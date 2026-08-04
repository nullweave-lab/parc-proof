use parc_proof::{
    BuildError, Continuity, ContinuityEdge, ContinuityEvent, EvidenceRecord, EvidenceStatus,
    Producer, ProofBuilder, SigningMetadata, Subject, SubjectType, MIN_CHALLENGE_BYTES,
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

fn evidence(id: &str, dependencies: &[&str]) -> EvidenceRecord {
    EvidenceRecord {
        id: id.into(),
        kind: "parc.test".into(),
        producer: Producer {
            id: "test".into(),
            boundary: "test".into(),
            mediation: None,
        },
        status: EvidenceStatus::Present,
        observed_at: None,
        digest: None,
        claims: serde_json::Map::new(),
        dependencies: dependencies.iter().map(|value| (*value).into()).collect(),
        limitations: vec![],
    }
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

#[test]
fn rejects_evidence_dependency_cycle() {
    let error = minimal_builder()
        .evidence(evidence("e1", &["e2"]))
        .evidence(evidence("e2", &["e1"]))
        .build()
        .expect_err("cycle must fail");
    assert_eq!(error, BuildError::CyclicEvidenceDependencies);
}

#[test]
fn rejects_continuity_cycle() {
    let continuity = Continuity {
        events: vec![
            ContinuityEvent {
                id: "a".into(),
                kind: "test".into(),
                asserted_by: "test".into(),
                sequence: Some(1),
            },
            ContinuityEvent {
                id: "b".into(),
                kind: "test".into(),
                asserted_by: "test".into(),
                sequence: Some(2),
            },
        ],
        edges: vec![
            ContinuityEdge {
                before: "a".into(),
                after: "b".into(),
                maximum_interval_ms: None,
            },
            ContinuityEdge {
                before: "b".into(),
                after: "a".into(),
                maximum_interval_ms: None,
            },
        ],
    };
    let error = minimal_builder()
        .continuity(continuity)
        .build()
        .expect_err("cycle must fail");
    assert_eq!(error, BuildError::CyclicContinuity);
}
