use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use parc_proof::{
    ApplicationBinding, BindingStrength, Capability, CapabilityStatus, Continuity,
    ContinuityEdge, ContinuityEvent, EvidenceRecord, EvidenceStatus, Producer, ProofBuilder,
    ProofEnvelope, SigningMetadata, Subject, SubjectType, DRAFT_PROTOCOL_VERSION,
};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest as ShaDigest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const DEFAULT_SERVER: &str = "http://127.0.0.1:8787";
const DEFAULT_PROFILE: &str = "parc.basic.application";

#[derive(Debug, Parser)]
#[command(name = "parc-attester")]
#[command(about = "Runnable experimental PARC proof client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Request a challenge, construct a proof, sign it, and submit it.
    Attest {
        #[arg(long, env = "PARC_SERVER", default_value = DEFAULT_SERVER)]
        server: String,
        #[arg(long, default_value = "parc-demo-key.json")]
        key_file: PathBuf,
        #[arg(long, default_value = DEFAULT_PROFILE)]
        profile: String,
        #[arg(long)]
        save_submission: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Submit a previously saved signed request, useful for replay tests.
    Submit {
        #[arg(long, env = "PARC_SERVER", default_value = DEFAULT_SERVER)]
        server: String,
        #[arg(long)]
        submission: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate or validate a local demo signing key.
    Keygen {
        #[arg(long, default_value = "parc-demo-key.json")]
        key_file: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge_id: String,
    challenge: String,
    protocol_version: String,
    profile: String,
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedSubmission {
    challenge_id: String,
    payload: String,
    public_key: String,
    signature: String,
    algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredKey {
    version: u32,
    secret_key: String,
    public_key: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Attest {
            server,
            key_file,
            profile,
            save_submission,
            output,
        } => attest(&server, &key_file, &profile, save_submission.as_deref(), output.as_deref()),
        Command::Submit {
            server,
            submission,
            output,
        } => submit_saved(&server, &submission, output.as_deref()),
        Command::Keygen { key_file } => {
            let key = load_or_create_key(&key_file)?;
            let fingerprint = subject_from_key(&key);
            println!("keyFile={} subject={fingerprint}", key_file.display());
            Ok(())
        }
    }
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(StdDuration::from_secs(15))
        .build()
        .context("failed to create HTTP client")
}

fn attest(
    server: &str,
    key_file: &Path,
    profile: &str,
    save_submission: Option<&Path>,
    output: Option<&Path>,
) -> Result<()> {
    if profile.trim().is_empty() {
        bail!("profile must not be blank");
    }
    let server = server.trim_end_matches('/');
    let client = http_client()?;
    let challenge: ChallengeResponse = client
        .post(format!("{server}/v1/challenges"))
        .json(&json!({"profile": profile}))
        .send()
        .context("challenge request failed")?
        .error_for_status()
        .context("challenge endpoint returned an error")?
        .json()
        .context("challenge response was not valid JSON")?;

    let key = load_or_create_key(key_file)?;
    let submission = create_submission(&challenge, &key)?;
    if let Some(path) = save_submission {
        write_json(path, &submission)?;
    }

    let response: Value = client
        .post(format!("{server}/v1/verify"))
        .json(&submission)
        .send()
        .context("proof submission failed")?
        .error_for_status()
        .context("verifier endpoint returned an HTTP error")?
        .json()
        .context("verifier response was not valid JSON")?;
    emit_json(&response, output)?;

    if response.pointer("/result/status").and_then(Value::as_str) != Some("pass") {
        bail!("verifier did not return pass");
    }
    Ok(())
}

fn submit_saved(server: &str, submission_path: &Path, output: Option<&Path>) -> Result<()> {
    let server = server.trim_end_matches('/');
    let submission: SignedSubmission = serde_json::from_slice(
        &fs::read(submission_path)
            .with_context(|| format!("failed to read {}", submission_path.display()))?,
    )
    .context("saved submission is invalid")?;
    let response: Value = http_client()?
        .post(format!("{server}/v1/verify"))
        .json(&submission)
        .send()
        .context("saved proof submission failed")?
        .error_for_status()
        .context("verifier endpoint returned an HTTP error")?
        .json()
        .context("verifier response was not valid JSON")?;
    emit_json(&response, output)
}

fn create_submission(challenge: &ChallengeResponse, key: &SigningKey) -> Result<SignedSubmission> {
    if challenge.protocol_version != DRAFT_PROTOCOL_VERSION {
        bail!(
            "server protocol {} is unsupported; expected {}",
            challenge.protocol_version,
            DRAFT_PROTOCOL_VERSION
        );
    }
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge.challenge.as_bytes())
        .context("challenge is not unpadded base64url")?;
    let issued_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format issuedAt")?;

    let mut proof_id = [0_u8; 18];
    OsRng.fill_bytes(&mut proof_id);
    let proof_id = URL_SAFE_NO_PAD.encode(proof_id);

    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let executable_bytes = fs::read(&executable).unwrap_or_default();
    let executable_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(&executable_bytes));
    let executable_size = fs::metadata(&executable).map(|value| value.len()).unwrap_or(0);

    let mut claims = Map::new();
    claims.insert("os".into(), json!(std::env::consts::OS));
    claims.insert("architecture".into(), json!(std::env::consts::ARCH));
    claims.insert("processId".into(), json!(std::process::id()));
    claims.insert("executableSize".into(), json!(executable_size));
    claims.insert("executableSha256".into(), json!(executable_digest));

    let proof = ProofBuilder::new()
        .profile(challenge.profile.clone())
        .proof_id(proof_id)
        .challenge(challenge_bytes)
        .time_bounds(issued_at, challenge.expires_at.clone())
        .subject(Subject {
            subject_type: SubjectType::Pairwise,
            value: subject_from_key(key),
        })
        .application(ApplicationBinding {
            package_name: Some("org.nullweave.parc.demo.cli".into()),
            version_code: Some(1),
            signing_certificate_sha256: None,
            build_id: Some(env!("CARGO_PKG_VERSION").into()),
            binding_strength: BindingStrength::SelfAsserted,
        })
        .capability(Capability {
            name: "parc.demo.ed25519".into(),
            status: CapabilityStatus::Available,
            reason: None,
        })
        .evidence(EvidenceRecord {
            id: "demo-runtime-summary".into(),
            kind: "parc.demo.runtime.summary".into(),
            producer: Producer {
                id: "parc-attester".into(),
                boundary: "ordinary-host-process".into(),
                mediation: Some("standard-library-and-host-os".into()),
            },
            status: EvidenceStatus::Present,
            observed_at: Some(OffsetDateTime::now_utc().format(&Rfc3339)?),
            digest: None,
            claims,
            dependencies: vec![],
            limitations: vec![
                "self-reported-host-observation".into(),
                "not-android-hardware-attestation".into(),
                "not-a-device-integrity-verdict".into(),
            ],
        })
        .continuity(Continuity {
            events: vec![
                ContinuityEvent {
                    id: "challenge-received".into(),
                    kind: "challenge-received".into(),
                    asserted_by: "parc-attester".into(),
                    sequence: Some(1),
                },
                ContinuityEvent {
                    id: "evidence-collected".into(),
                    kind: "evidence-collected".into(),
                    asserted_by: "parc-attester".into(),
                    sequence: Some(2),
                },
                ContinuityEvent {
                    id: "proof-signed".into(),
                    kind: "proof-signed".into(),
                    asserted_by: "parc-attester".into(),
                    sequence: Some(3),
                },
            ],
            edges: vec![
                ContinuityEdge {
                    before: "challenge-received".into(),
                    after: "evidence-collected".into(),
                    maximum_interval_ms: None,
                },
                ContinuityEdge {
                    before: "evidence-collected".into(),
                    after: "proof-signed".into(),
                    maximum_interval_ms: None,
                },
            ],
        })
        .signing(SigningMetadata {
            format: "parc-demo-ed25519-v1".into(),
            algorithm: "Ed25519".into(),
            credential_refs: vec![],
        })
        .build()?;

    let payload = proof.to_json_bytes()?;
    let signature = key.sign(&payload);
    Ok(SignedSubmission {
        challenge_id: challenge.challenge_id.clone(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        algorithm: "Ed25519".into(),
    })
}

fn load_or_create_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let stored: StoredKey = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
        )
        .context("key file is invalid JSON")?;
        if stored.version != 1 {
            bail!("unsupported key file version {}", stored.version);
        }
        let secret = decode_fixed::<32>(&stored.secret_key, "secretKey")?;
        let key = SigningKey::from_bytes(&secret);
        let expected_public = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        if stored.public_key != expected_public {
            bail!("key file public key does not match the secret key");
        }
        return Ok(key);
    }

    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let key = SigningKey::generate(&mut OsRng);
    let stored = StoredKey {
        version: 1,
        secret_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
    };
    write_private_json(path, &stored)?;
    Ok(key)
}

fn subject_from_key(key: &SigningKey) -> String {
    let digest = Sha256::digest(key.verifying_key().as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .with_context(|| format!("{name} is not unpadded base64url"))?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to {N} bytes, got {actual}"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn emit_json(value: &Value, path: Option<&Path>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if let Some(path) = path {
        fs::write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", String::from_utf8(bytes).expect("JSON is UTF-8"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier as _};

    #[test]
    fn generated_submission_has_a_valid_signature_and_payload() {
        let key = SigningKey::generate(&mut OsRng);
        let challenge = ChallengeResponse {
            challenge_id: "challenge-1".into(),
            challenge: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            protocol_version: DRAFT_PROTOCOL_VERSION.into(),
            profile: DEFAULT_PROFILE.into(),
            expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(5))
                .format(&Rfc3339)
                .unwrap(),
        };
        let submission = create_submission(&challenge, &key).expect("submission");
        let payload = URL_SAFE_NO_PAD.decode(submission.payload).unwrap();
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(submission.signature)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_bytes(&signature_bytes);
        key.verifying_key().verify(&payload, &signature).unwrap();
        let envelope: ProofEnvelope = serde_json::from_slice(&payload).unwrap();
        assert_eq!(envelope.protocol_version, DRAFT_PROTOCOL_VERSION);
        assert_eq!(envelope.profile, DEFAULT_PROFILE);
        assert_eq!(envelope.evidence.len(), 1);
    }
}
