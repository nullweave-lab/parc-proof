//! Experimental proof construction primitives for PARC.
//!
//! This crate does not implement signing, key attestation, or relying-party
//! policy. Callers must provide reviewed cryptographic and platform adapters.

use std::collections::{HashMap, HashSet, VecDeque};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DRAFT_PROTOCOL_VERSION: &str = "0.1-draft";
pub const MIN_CHALLENGE_BYTES: usize = 16;
pub const MAX_CHALLENGE_BYTES: usize = 384;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofEnvelope {
    pub protocol_version: String,
    pub profile: String,
    pub proof_id: String,
    pub challenge: String,
    pub issued_at: String,
    pub expires_at: String,
    pub subject: Subject,
    pub application: ApplicationBinding,
    pub capabilities: Vec<Capability>,
    pub evidence: Vec<EvidenceRecord>,
    pub continuity: Continuity,
    pub signing: SigningMetadata,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    #[serde(rename = "type")]
    pub subject_type: SubjectType,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Ephemeral,
    Pairwise,
    Rotating,
    Stable,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationBinding {
    pub package_name: Option<String>,
    pub version_code: Option<u64>,
    pub signing_certificate_sha256: Option<String>,
    pub build_id: Option<String>,
    #[serde(default)]
    pub binding_strength: BindingStrength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BindingStrength {
    #[default]
    SelfAsserted,
    Measured,
    CredentialBound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub name: String,
    pub status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityStatus {
    Available,
    Unsupported,
    Failed,
    Withheld,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    pub id: String,
    pub kind: String,
    pub producer: Producer,
    pub status: EvidenceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Producer {
    pub id: String,
    pub boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceStatus {
    Present,
    Unsupported,
    Failed,
    Indeterminate,
    Withheld,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Continuity {
    #[serde(default)]
    pub events: Vec<ContinuityEvent>,
    #[serde(default)]
    pub edges: Vec<ContinuityEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityEvent {
    pub id: String,
    pub kind: String,
    pub asserted_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityEdge {
    pub before: String,
    pub after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_interval_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningMetadata {
    pub format: String,
    pub algorithm: String,
    #[serde(default)]
    pub credential_refs: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("profile must not be empty")]
    EmptyProfile,
    #[error("proof id must not be empty")]
    EmptyProofId,
    #[error("subject value must not be empty")]
    EmptySubject,
    #[error("challenge encoding is invalid")]
    InvalidChallengeEncoding,
    #[error("challenge length {actual} is outside {min}..={max} bytes")]
    InvalidChallengeLength { actual: usize, min: usize, max: usize },
    #[error("issuedAt and expiresAt must not be empty")]
    MissingTimeBounds,
    #[error("duplicate evidence id: {0}")]
    DuplicateEvidenceId(String),
    #[error("evidence {record} depends on missing evidence {dependency}")]
    MissingEvidenceDependency { record: String, dependency: String },
    #[error("evidence dependency graph contains a cycle")]
    CyclicEvidenceDependencies,
    #[error("duplicate continuity event id: {0}")]
    DuplicateContinuityEvent(String),
    #[error("continuity edge references missing event: {0}")]
    MissingContinuityEvent(String),
    #[error("continuity graph contains a cycle")]
    CyclicContinuity,
    #[error("signing format and algorithm must not be empty")]
    MissingSigningMetadata,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

impl ProofEnvelope {
    pub fn validate(&self) -> Result<(), BuildError> {
        if self.profile.trim().is_empty() {
            return Err(BuildError::EmptyProfile);
        }
        if self.proof_id.trim().is_empty() {
            return Err(BuildError::EmptyProofId);
        }
        if self.subject.value.trim().is_empty() {
            return Err(BuildError::EmptySubject);
        }
        let challenge = URL_SAFE_NO_PAD
            .decode(self.challenge.as_bytes())
            .map_err(|_| BuildError::InvalidChallengeEncoding)?;
        if !(MIN_CHALLENGE_BYTES..=MAX_CHALLENGE_BYTES).contains(&challenge.len()) {
            return Err(BuildError::InvalidChallengeLength {
                actual: challenge.len(),
                min: MIN_CHALLENGE_BYTES,
                max: MAX_CHALLENGE_BYTES,
            });
        }
        if self.issued_at.trim().is_empty() || self.expires_at.trim().is_empty() {
            return Err(BuildError::MissingTimeBounds);
        }
        if self.signing.format.trim().is_empty() || self.signing.algorithm.trim().is_empty() {
            return Err(BuildError::MissingSigningMetadata);
        }
        validate_evidence(&self.evidence)?;
        validate_continuity(&self.continuity)?;
        Ok(())
    }

    /// Serializes the logical draft model. The output is not a frozen canonical
    /// signature format and must not be signed directly in production.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, BuildError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| BuildError::Serialization(error.to_string()))
    }
}

fn validate_evidence(records: &[EvidenceRecord]) -> Result<(), BuildError> {
    let mut ids = HashSet::new();
    for record in records {
        if !ids.insert(record.id.as_str()) {
            return Err(BuildError::DuplicateEvidenceId(record.id.clone()));
        }
    }

    let mut indegree: HashMap<&str, usize> = ids.iter().map(|id| (*id, 0)).collect();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut unique_edges = HashSet::new();
    for record in records {
        for dependency in &record.dependencies {
            if !ids.contains(dependency.as_str()) {
                return Err(BuildError::MissingEvidenceDependency {
                    record: record.id.clone(),
                    dependency: dependency.clone(),
                });
            }
            let edge = (dependency.as_str(), record.id.as_str());
            if unique_edges.insert(edge) {
                *indegree.get_mut(record.id.as_str()).expect("known evidence id") += 1;
                dependents.entry(dependency.as_str()).or_default().push(record.id.as_str());
            }
        }
    }
    if !is_acyclic(&mut indegree, &dependents) {
        return Err(BuildError::CyclicEvidenceDependencies);
    }
    Ok(())
}

fn validate_continuity(continuity: &Continuity) -> Result<(), BuildError> {
    let mut ids = HashSet::new();
    for event in &continuity.events {
        if !ids.insert(event.id.as_str()) {
            return Err(BuildError::DuplicateContinuityEvent(event.id.clone()));
        }
    }

    let mut indegree: HashMap<&str, usize> = ids.iter().map(|id| (*id, 0)).collect();
    let mut successors: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut unique_edges = HashSet::new();
    for edge in &continuity.edges {
        if !ids.contains(edge.before.as_str()) {
            return Err(BuildError::MissingContinuityEvent(edge.before.clone()));
        }
        if !ids.contains(edge.after.as_str()) {
            return Err(BuildError::MissingContinuityEvent(edge.after.clone()));
        }
        let relation = (edge.before.as_str(), edge.after.as_str());
        if unique_edges.insert(relation) {
            *indegree.get_mut(edge.after.as_str()).expect("known continuity event") += 1;
            successors.entry(edge.before.as_str()).or_default().push(edge.after.as_str());
        }
    }
    if !is_acyclic(&mut indegree, &successors) {
        return Err(BuildError::CyclicContinuity);
    }
    Ok(())
}

fn is_acyclic<'a>(
    indegree: &mut HashMap<&'a str, usize>,
    successors: &HashMap<&'a str, Vec<&'a str>>,
) -> bool {
    let mut queue: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut visited = 0;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        if let Some(next) = successors.get(id) {
            for successor in next {
                let degree = indegree.get_mut(successor).expect("known graph node");
                *degree -= 1;
                if *degree == 0 {
                    queue.push_back(successor);
                }
            }
        }
    }
    visited == indegree.len()
}

#[derive(Debug, Default)]
pub struct ProofBuilder {
    profile: Option<String>,
    proof_id: Option<String>,
    challenge: Option<Vec<u8>>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    subject: Option<Subject>,
    application: ApplicationBinding,
    capabilities: Vec<Capability>,
    evidence: Vec<EvidenceRecord>,
    continuity: Continuity,
    signing: Option<SigningMetadata>,
}

impl ProofBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn profile(mut self, value: impl Into<String>) -> Self {
        self.profile = Some(value.into());
        self
    }

    pub fn proof_id(mut self, value: impl Into<String>) -> Self {
        self.proof_id = Some(value.into());
        self
    }

    pub fn challenge(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.challenge = Some(value.into());
        self
    }

    pub fn time_bounds(mut self, issued_at: impl Into<String>, expires_at: impl Into<String>) -> Self {
        self.issued_at = Some(issued_at.into());
        self.expires_at = Some(expires_at.into());
        self
    }

    pub fn subject(mut self, value: Subject) -> Self {
        self.subject = Some(value);
        self
    }

    pub fn application(mut self, value: ApplicationBinding) -> Self {
        self.application = value;
        self
    }

    pub fn capability(mut self, value: Capability) -> Self {
        self.capabilities.push(value);
        self
    }

    pub fn evidence(mut self, value: EvidenceRecord) -> Self {
        self.evidence.push(value);
        self
    }

    pub fn continuity(mut self, value: Continuity) -> Self {
        self.continuity = value;
        self
    }

    pub fn signing(mut self, value: SigningMetadata) -> Self {
        self.signing = Some(value);
        self
    }

    pub fn build(self) -> Result<ProofEnvelope, BuildError> {
        let challenge = self.challenge.unwrap_or_default();
        if !(MIN_CHALLENGE_BYTES..=MAX_CHALLENGE_BYTES).contains(&challenge.len()) {
            return Err(BuildError::InvalidChallengeLength {
                actual: challenge.len(),
                min: MIN_CHALLENGE_BYTES,
                max: MAX_CHALLENGE_BYTES,
            });
        }
        let envelope = ProofEnvelope {
            protocol_version: DRAFT_PROTOCOL_VERSION.to_owned(),
            profile: self.profile.ok_or(BuildError::EmptyProfile)?,
            proof_id: self.proof_id.ok_or(BuildError::EmptyProofId)?,
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            issued_at: self.issued_at.ok_or(BuildError::MissingTimeBounds)?,
            expires_at: self.expires_at.ok_or(BuildError::MissingTimeBounds)?,
            subject: self.subject.ok_or(BuildError::EmptySubject)?,
            application: self.application,
            capabilities: self.capabilities,
            evidence: self.evidence,
            continuity: self.continuity,
            signing: self.signing.ok_or(BuildError::MissingSigningMetadata)?,
            extensions: serde_json::Map::new(),
        };
        envelope.validate()?;
        Ok(envelope)
    }
}
