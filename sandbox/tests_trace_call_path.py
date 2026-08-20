#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import pu_call_path
import pu_index


class TraceCallPathTests(unittest.TestCase):
    def make_graph(self, *, analysis_kind="dex-xref", truncated=None):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        workspace = root / "workspace"
        job = root / "job"
        workspace.mkdir()
        job.mkdir()
        (workspace / "app.apk").write_bytes(b"fixture")
        (job / "job.json").write_text(json.dumps({"artifact": "app.apk"}), encoding="utf-8")
        conn = pu_index.connect(job)
        conn.executescript(
            """
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE methods(
              id TEXT PRIMARY KEY,class TEXT NOT NULL,name TEXT NOT NULL,
              descriptor TEXT NOT NULL,parameter_count INTEGER,
              external INTEGER NOT NULL,source_json TEXT NOT NULL
            );
            CREATE TABLE call_edges(
              caller TEXT NOT NULL,callee TEXT NOT NULL,offset INTEGER NOT NULL,
              confidence REAL NOT NULL,kind TEXT NOT NULL
            );
            CREATE INDEX idx_edges_caller ON call_edges(caller);
            CREATE INDEX idx_edges_callee ON call_edges(callee);
            """
        )
        for key, value in {
            "analysis_kind": analysis_kind,
            "truncated": truncated or {"methods": False, "edges": False},
        }.items():
            conn.execute("INSERT INTO metadata VALUES (?,?)", (key, json.dumps(value)))
        conn.commit()
        return tmp, workspace, job, conn

    @staticmethod
    def method(conn, symbol_id, clazz, name, descriptor="()V", external=0):
        conn.execute(
            "INSERT INTO methods VALUES (?,?,?,?,?,?,?)",
            (symbol_id, clazz, name, descriptor, 0, external, "{}"),
        )

    @staticmethod
    def edge(conn, caller, callee, offset=0):
        conn.execute(
            "INSERT INTO call_edges VALUES (?,?,?,?,?)",
            (caller, callee, offset, 0.98, "dex-xref"),
        )

    def trace(self, job, workspace, source, target, **kwargs):
        return pu_call_path.trace_call_path(job, workspace, {}, source, target, **kwargs)

    def test_returns_all_shortest_paths_deterministically(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            for symbol_id, clazz, name in [
                ("A", "p.A", "start"), ("B", "p.B", "b"),
                ("C", "p.C", "c"), ("D", "p.D", "target"),
            ]:
                self.method(conn, symbol_id, clazz, name)
            self.edge(conn, "A", "C", 20)
            self.edge(conn, "A", "B", 10)
            self.edge(conn, "B", "D", 30)
            self.edge(conn, "C", "D", 40)
            conn.commit(); conn.close()
            first = self.trace(job, workspace, "p.A start", "p.D target")
            second = self.trace(job, workspace, "p.A start", "p.D target")
            expected = [["A", "B", "D"], ["A", "C", "D"]]
            self.assertEqual([[n["id"] for n in p["nodes"]] for p in first["paths"]], expected)
            self.assertEqual(first["paths"], second["paths"])
            self.assertEqual(first["shortest_depth"], 2)
            self.assertFalse(first["truncated"])
            self.assertTrue(first["search_complete"])
        finally:
            tmp.cleanup()

    def test_cycle_does_not_loop(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            for symbol_id in "ABC": self.method(conn, symbol_id, f"p.{symbol_id}", symbol_id.lower())
            self.edge(conn, "A", "B"); self.edge(conn, "B", "A"); self.edge(conn, "B", "C")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "C")
            self.assertTrue(result["found"])
            self.assertEqual(result["shortest_depth"], 2)
            self.assertEqual(result["stats"]["visited_nodes"], 3)
        finally: tmp.cleanup()

    def test_reverse_traversal_preserves_original_call_edge(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            for symbol_id in "ABC": self.method(conn, symbol_id, f"p.{symbol_id}", symbol_id.lower())
            self.edge(conn, "A", "B", 1); self.edge(conn, "B", "C", 2)
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "C", "A", direction="reverse")
            self.assertEqual([n["id"] for n in result["paths"][0]["nodes"]], ["C", "B", "A"])
            edge = result["paths"][0]["edges"][0]
            self.assertEqual((edge["caller"], edge["callee"]), ("B", "C"))
            self.assertEqual((edge["traversal_from"], edge["traversal_to"]), ("C", "B"))
        finally: tmp.cleanup()

    def test_candidate_sets_do_not_merge_same_named_methods(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            for row in [
                ("E", "p.Entry", "start"),
                ("L1", "p.Api", "login"),
                ("L2", "p.AdminApi", "login"),
                ("L3", "p.Api", "login", "(Ljava/lang/String;)V"),
            ]:
                self.method(conn, *row)
            self.edge(conn, "E", "L1")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "Entry start", "login")
            self.assertEqual(result["target_resolution"]["status"], "candidate-set")
            self.assertEqual(result["target_resolution"]["candidate_count"], 3)
            self.assertEqual([n["id"] for n in result["paths"][0]["nodes"]], ["E", "L1"])
        finally: tmp.cleanup()

    def test_zero_length_path(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            self.method(conn, "A", "p.A", "a"); conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "A")
            self.assertEqual(result["shortest_depth"], 0)
            self.assertEqual([n["id"] for n in result["paths"][0]["nodes"]], ["A"])
            self.assertEqual(result["paths"][0]["edges"], [])
        finally: tmp.cleanup()

    def test_depth_budget_is_reported(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            for symbol_id in "ABCD": self.method(conn, symbol_id, f"p.{symbol_id}", symbol_id.lower())
            self.edge(conn, "A", "B"); self.edge(conn, "B", "C"); self.edge(conn, "C", "D")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "D", max_depth=2)
            self.assertFalse(result["found"])
            self.assertIn("depth_limit", result["truncation_reasons"])
        finally: tmp.cleanup()

    def test_node_budget_is_reported(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            self.method(conn, "A", "p.A", "a"); self.method(conn, "T", "p.T", "t")
            for index in range(250):
                self.method(conn, f"N{index}", f"p.N{index}", "n")
                self.edge(conn, "A", f"N{index}")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "T", max_visited_nodes=200)
            self.assertFalse(result["found"])
            self.assertIn("node_budget", result["truncation_reasons"])
        finally: tmp.cleanup()

    def test_edge_budget_is_reported(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            self.method(conn, "A", "p.A", "a"); self.method(conn, "T", "p.T", "t")
            for index in range(150):
                self.method(conn, f"N{index}", f"p.N{index}", "n")
                self.edge(conn, "A", f"N{index}")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "T", max_scanned_edges=100)
            self.assertIn("edge_budget", result["truncation_reasons"])
            self.assertEqual(result["stats"]["scanned_edges"], 100)
        finally: tmp.cleanup()

    def test_path_limit_only_when_more_paths_exist(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            self.method(conn, "A", "p.A", "a"); self.method(conn, "T", "p.T", "t")
            for index in range(5):
                mid = f"M{index}"; self.method(conn, mid, f"p.{mid}", "m")
                self.edge(conn, "A", mid, index); self.edge(conn, mid, "T", index)
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "T", max_paths=3)
            self.assertEqual(len(result["paths"]), 3)
            self.assertIn("path_limit", result["truncation_reasons"])
        finally: tmp.cleanup()

    def test_unresolved_endpoint_does_not_traverse(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            self.method(conn, "A", "p.A", "a"); conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "missing")
            self.assertFalse(result["found"])
            self.assertEqual(result["target_resolution"]["status"], "unresolved")
            self.assertIn("target_unresolved", result["resolution_reasons"])
            self.assertEqual(result["stats"]["scanned_edges"], 0)
        finally: tmp.cleanup()

    def test_source_fallback_is_explicitly_unavailable(self):
        tmp, workspace, job, conn = self.make_graph(analysis_kind="source-fallback")
        try:
            self.method(conn, "A", "p.A", "a"); self.method(conn, "B", "p.B", "b")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "B")
            self.assertFalse(result["available"])
            self.assertEqual(result["unavailable_reason"], "program_index_has_no_dex_xref_graph")
            self.assertEqual(result["truncation_reasons"], [])
        finally: tmp.cleanup()

    def test_index_truncation_prevents_conclusive_negative(self):
        tmp, workspace, job, conn = self.make_graph(truncated={"methods": False, "edges": True})
        try:
            self.method(conn, "A", "p.A", "a"); self.method(conn, "B", "p.B", "b")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "B")
            self.assertFalse(result["found"])
            self.assertTrue(result["truncated"])
            self.assertIn("index_edges_truncated", result["truncation_reasons"])
        finally: tmp.cleanup()

    def test_intermediate_symbol_may_be_missing_from_method_table(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            self.method(conn, "A", "p.A", "a"); self.method(conn, "B", "p.B", "b")
            self.edge(conn, "A", "external-X"); self.edge(conn, "external-X", "B")
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "A", "B")
            nodes = result["paths"][0]["nodes"]
            self.assertEqual([node["id"] for node in nodes], ["A", "external-X", "B"])
            self.assertIsNone(nodes[1]["external"])
        finally: tmp.cleanup()

    def test_large_graph_100k_methods_250k_edges(self):
        tmp, workspace, job, conn = self.make_graph()
        try:
            conn.executemany(
                "INSERT INTO methods VALUES (?,?,?,?,?,?,?)",
                ((f"M{i}", f"stress.C{i}", f"m{i}", "()V", 0, 0, "{}") for i in range(100_000)),
            )
            conn.executemany(
                "INSERT INTO call_edges VALUES (?,?,?,?,?)",
                (
                    (f"M{i % 100_000}", f"M{(i % 100_000 + 1 + i // 100_000) % 100_000}", i, 0.98, "dex-xref")
                    for i in range(250_000)
                ),
            )
            conn.commit(); conn.close()
            result = self.trace(job, workspace, "M0", "M5", max_depth=8)
            self.assertTrue(result["found"])
            self.assertLessEqual(result["shortest_depth"], 5)
            self.assertLess(result["stats"]["scanned_edges"], 1000)
        finally: tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
