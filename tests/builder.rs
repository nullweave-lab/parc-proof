use parc_proof::{
    Continuity, ProofBuilder, SigningMetadata, Subject, SubjectType, MIN_CHALLENGE_BYTES,
};

fn minimal_builder() -> ProofBuilder {
    ProofBuilder::new()
        .profile("parc.basic.application")
        .proof_id("proof-0000000001")
        .challenge(vec![0xA5; MIN_CHALLENGE_BYTES])
        .time_bounds("2026-08-03T08:00:00Z", "2026-08-03T08:05:00Z")
        .subject(Subject {
            subject_type: SubjectType::Ephemeral,
            value: "subject-1".into(),
        })
        .continuity(Continuity::default())
        .signing(SigningMetadata {
            format: "detached-placeholder".into(),
            algorithm: "none-for-test".into(),
            credential_refs: vec![],
        })
}

#[test]
fn builds_minimal_draft_envelope() {
    let proof = minimal_builder().build().expect("valid proof");
    let json = proof.to_json_bytes().expect("serializable");
    assert!(json.starts_with(b"{"));
}

#[test]
fn rejects_short_challenge() {
    let error = ProofBuilder::new()
        .profile("parc.basic.application")
        .proof_id("proof-0000000002")
        .challenge(vec![0; MIN_CHALLENGE_BYTES - 1])
        .time_bounds("2026-08-03T08:00:00Z", "2026-08-03T08:05:00Z")
        .subject(Subject {
            subject_type: SubjectType::Ephemeral,
            value: "subject-2".into(),
        })
        .signing(SigningMetadata {
            format: "test".into(),
            algorithm: "test".into(),
            credential_refs: vec![],
        })
        .build()
        .expect_err("short challenge must fail");

    assert!(error.to_string().contains("challenge length"));
}
