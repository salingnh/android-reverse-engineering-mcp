from __future__ import annotations

import unittest

import security_finding as finding


class SecurityFindingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = "a" * 64
        self.rule = finding.RuleIdentity("safe-reverser", "auth.token-in-query", "1")
        self.anchor = finding.SemanticAnchor("FLOW_NODE", "flow:v1:node:abc", "dex")
        self.finding_id = finding.security_finding_id(self.snapshot, self.rule, self.anchor)

    def candidate(self, **overrides) -> finding.SecurityFinding:
        values = {
            "snapshot_id": self.snapshot,
            "finding_id": self.finding_id,
            "rule": self.rule,
            "title": "Token material reaches a query parameter",
            "category": "authentication",
            "severity": "medium",
            "state": "candidate",
            "primary_anchor": self.anchor,
            "candidate_producers": ("security-investigator",),
            "knowledge_refs": (
                finding.KnowledgeRef("CWE", "CWE-598"),
                finding.KnowledgeRef("MASWE", "MASWE-0052"),
            ),
            "evidence_refs": ("evidence:z", "evidence:a", "evidence:a"),
            "flow_path_ids": ("flow:path:2", "flow:path:1"),
            "limitations": ("runtime behavior not observed",),
        }
        values.update(overrides)
        return finding.SecurityFinding(**values)

    def test_identity_is_stable_across_lifecycle_and_evidence_growth(self):
        first = self.candidate()
        probable = finding.transition_finding(first, "probable")
        self.assertEqual(first.finding_id, probable.finding_id)
        self.assertEqual(probable.evidence_refs, ("evidence:a", "evidence:z"))
        self.assertEqual(probable.flow_path_ids, ("flow:path:1", "flow:path:2"))

    def test_canonical_id_depends_on_snapshot_rule_and_semantic_anchor(self):
        same = finding.security_finding_id(self.snapshot, self.rule, self.anchor)
        changed_rule = finding.security_finding_id(
            self.snapshot,
            finding.RuleIdentity("safe-reverser", "auth.token-in-query", "2"),
            self.anchor,
        )
        changed_anchor = finding.security_finding_id(
            self.snapshot,
            self.rule,
            finding.SemanticAnchor("FLOW_NODE", "flow:v1:node:def", "dex"),
        )
        self.assertEqual(same, self.finding_id)
        self.assertNotEqual(changed_rule, self.finding_id)
        self.assertNotEqual(changed_anchor, self.finding_id)

    def test_candidate_producers_are_multi_source_deduplicated_and_sorted(self):
        item = self.candidate(
            candidate_producers=("project-native", "semgrep-adapter", "project-native")
        )
        self.assertEqual(
            item.candidate_producers,
            ("project-native", "semgrep-adapter"),
        )
        self.assertEqual(item.finding_id, self.finding_id)

    def test_candidate_requires_at_least_one_producer(self):
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(candidate_producers=())

    def test_terminal_state_requires_independent_verification(self):
        candidate = self.candidate()
        verification = finding.VerificationRecord(
            verifier="security-verifier",
            verdict="verified",
            method="STATIC_DATA_FLOW",
            evidence_refs=("evidence:verification",),
            flow_path_ids=("flow:path:1",),
        )
        verified = finding.transition_finding(
            candidate,
            "verified",
            verification=verification,
        )
        self.assertEqual(verified.state, "verified")
        self.assertEqual(verified.finding_id, candidate.finding_id)
        self.assertEqual(verified.verification.verdict, "verified")

    def test_terminal_state_without_verification_is_rejected(self):
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(state="verified")

    def test_verifier_must_be_independent_from_all_candidate_producers(self):
        verification = finding.VerificationRecord(
            verifier="semgrep-adapter",
            verdict="verified",
            method="STATIC_SEMANTIC",
        )
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(
                state="verified",
                candidate_producers=("project-native", "semgrep-adapter"),
                verification=verification,
            )

    def test_verification_verdict_must_match_terminal_state(self):
        verification = finding.VerificationRecord(
            verifier="security-verifier",
            verdict="refuted",
            method="STATIC_REACHABILITY",
        )
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(state="verified", verification=verification)

    def test_terminal_state_cannot_regress_to_probable(self):
        verification = finding.VerificationRecord(
            verifier="security-verifier",
            verdict="verified",
            method="STATIC_DATA_FLOW",
        )
        verified = finding.transition_finding(
            self.candidate(),
            "verified",
            verification=verification,
        )
        with self.assertRaises(finding.FindingTransitionError):
            finding.transition_finding(verified, "probable")

    def test_candidate_cannot_carry_terminal_verification(self):
        verification = finding.VerificationRecord(
            verifier="security-verifier",
            verdict="unknown",
            method="MANUAL_REVIEW",
        )
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(verification=verification)

    def test_unknown_knowledge_taxonomy_is_rejected(self):
        with self.assertRaises(finding.SecurityFindingError):
            finding.KnowledgeRef("backend-private-taxonomy", "X-1")

    def test_related_anchors_are_deduplicated_and_primary_is_not_repeated(self):
        related = finding.SemanticAnchor("PROGRAM_ENTITY", "pm:v1:function:x", "dex")
        item = self.candidate(related_anchors=(self.anchor, related, related))
        self.assertEqual(item.related_anchors, (related,))

    def test_serialized_contract_has_no_numeric_confidence(self):
        payload = self.candidate().to_dict()
        self.assertEqual(payload["schema_version"], 1)
        self.assertNotIn("confidence", payload)
        self.assertNotIn("score", payload)
        self.assertEqual(payload["state"], "candidate")
        self.assertEqual(payload["candidate_producers"], ["security-investigator"])
        self.assertIsNone(payload["verification"])

    def test_reference_count_is_bounded(self):
        refs = tuple(f"evidence:{index}" for index in range(finding.MAX_REFS + 1))
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(evidence_refs=refs)

    def test_producer_count_is_bounded(self):
        producers = tuple(f"producer:{index}" for index in range(finding.MAX_PRODUCERS + 1))
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(candidate_producers=producers)

    def test_invalid_finding_id_is_rejected(self):
        with self.assertRaises(finding.SecurityFindingError):
            self.candidate(finding_id="finding:v1:not-canonical")


if __name__ == "__main__":
    unittest.main()
