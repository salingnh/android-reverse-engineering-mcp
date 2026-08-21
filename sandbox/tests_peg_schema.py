#!/usr/bin/env python3
import unittest

import peg_schema


class ProgramEvidenceGraphSchemaTests(unittest.TestCase):
    def test_schema_contains_cross_runtime_nodes_and_core_edges(self):
        descriptor = peg_schema.schema_descriptor()
        self.assertEqual(descriptor["schema_version"], 2)
        self.assertIn("Method", descriptor["node_types"])
        self.assertIn("DartFunction", descriptor["node_types"])
        self.assertIn("NativeFunction", descriptor["node_types"])
        self.assertIn("Endpoint", descriptor["node_types"])
        self.assertIn("FLOWS_TO", descriptor["edge_types"])
        self.assertIn("JNI_BINDS", descriptor["edge_types"])
        self.assertIn("CONFIRMS", descriptor["edge_types"])
        self.assertEqual(
            descriptor["evidence_states"], ["observed", "derived", "hypothesized"]
        )
        self.assertEqual(
            descriptor["limits"]["properties_json_bytes"],
            peg_schema.MAX_PROPERTIES_JSON_BYTES,
        )

    def test_evidence_requires_explicit_provenance_and_state(self):
        record = peg_schema.evidence(
            analysis_id="job-123",
            artifact_sha256="a" * 64,
            analyzer_name="androguard",
            analyzer_version="4.1.4",
            state="observed",
            location={"dex": "classes.dex", "offset": 42},
            image_version="0.2.1",
            build_commit="abc123",
            limitations=["reflection not resolved"],
        )
        self.assertEqual(record["analysis_id"], "job-123")
        self.assertEqual(record["state"], "observed")
        self.assertEqual(record["location"]["offset"], 42)
        self.assertEqual(record["build_commit"], "abc123")
        self.assertNotIn("confidence", record)

    def test_evidence_rejects_invalid_state_sha_location_and_non_json(self):
        kwargs = dict(
            analysis_id="job-123",
            artifact_sha256="a" * 64,
            analyzer_name="test",
            analyzer_version="1",
            state="observed",
            location={"file": "x"},
        )
        with self.assertRaises(ValueError):
            peg_schema.evidence(**{**kwargs, "state": "verified"})
        with self.assertRaises(ValueError):
            peg_schema.evidence(**{**kwargs, "artifact_sha256": "not-a-sha"})
        with self.assertRaises(ValueError):
            peg_schema.evidence(**{**kwargs, "location": {}})
        with self.assertRaises(ValueError):
            peg_schema.evidence(**{**kwargs, "location": {"value": object()}})

    def test_node_and_edge_types_are_allow_listed(self):
        evidence = peg_schema.evidence(
            analysis_id="job-123",
            artifact_sha256="b" * 64,
            analyzer_name="test",
            analyzer_version="1",
            state="derived",
            location={"file": "source.java", "line": 10},
        )
        node = peg_schema.node(
            "Method",
            "LExample; foo ()V",
            properties={"name": "foo"},
            evidence_record=evidence,
        )
        edge = peg_schema.edge(
            "CALLS",
            "LExample; foo ()V",
            "LApi; call ()V",
            evidence_record=evidence,
        )
        self.assertEqual(node["kind"], "Method")
        self.assertEqual(edge["kind"], "CALLS")
        with self.assertRaises(ValueError):
            peg_schema.node("ArbitraryNode", "x")
        with self.assertRaises(ValueError):
            peg_schema.edge("MAYBE_FLOWS", "x", "y")

    def test_builders_reject_unbounded_or_malformed_payloads(self):
        with self.assertRaises(ValueError):
            peg_schema.node("String", "str:1", properties="not-an-object")
        with self.assertRaises(ValueError):
            peg_schema.node(
                "String",
                "str:1",
                properties={"payload": "x" * peg_schema.MAX_PROPERTIES_JSON_BYTES},
            )
        with self.assertRaises(ValueError):
            peg_schema.edge(
                "CALLS",
                "a",
                "b",
                evidence_record={
                    "schema_version": 1,
                    "state": "observed",
                    "analysis_id": "x",
                    "artifact_sha256": "a" * 64,
                    "analyzer": {"name": "x", "version": "1"},
                    "location": {"file": "x"},
                },
            )

    def test_builders_copy_mutable_input(self):
        properties = {"nested": {"value": 1}}
        node = peg_schema.node("String", "str:1", properties=properties)
        properties["nested"]["value"] = 2
        self.assertEqual(node["properties"]["nested"]["value"], 1)


if __name__ == "__main__":
    unittest.main()
