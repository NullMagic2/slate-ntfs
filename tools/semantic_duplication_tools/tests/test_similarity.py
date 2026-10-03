"""Module: semantic_duplication_tools.tests
Purpose: Verify symbol extraction, ranking and bounded similarity groups.
Created: 2026-10-03
Architecture: Separate tests exercise the public engine and real CodeGraph exporter.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("similarity", ROOT / "semantic_search.py")
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)


class SimilarityTests(unittest.TestCase):
    def test_groups_require_every_pair_and_keep_types_separate(self):
        symbols = [{"category": "function"}] * 3 + [{"category": "type"}]
        scores = np.array([
            [1, .95, .30, 1], [.95, 1, .90, 1], [.30, .90, 1, 1], [1, 1, 1, 1],
        ])
        self.assertEqual(ENGINE.group_symbols(symbols, scores, .8), [[0, 1]])

    def test_zero_terms_and_empty_source_have_finite_results(self):
        vectors, _ = ENGINE.lexical_vectors(["", "fn pub self"])
        self.assertTrue(np.isfinite(vectors).all())
        args = argparse.Namespace()
        self.assertEqual(ENGINE.analyze([], args)["groups"], [])
        with self.assertRaises(ValueError):
            ENGINE.normalized(np.array([[float("nan")]]))

    def test_words_split_code_identifiers_without_losing_acronyms(self):
        self.assertEqual(ENGINE.terms("readMFTRecord disk_offset"), ["read", "mft", "record", "disk", "offset"])

    def test_model_chunks_retain_and_weight_the_final_partial_window(self):
        class Tokenizer:
            def num_special_tokens_to_add(self, pair):
                return 2

            def encode(self, text, add_special_tokens, verbose):
                return list(range(len(text)))

            def decode(self, tokens):
                return ",".join(map(str, tokens))

        class Model:
            max_seq_length = 16
            tokenizer = Tokenizer()

            def __init__(self, name, **options):
                assert options["local_files_only"] and not options["trust_remote_code"]
                self.device = options["device"] or "cuda:0"

            def encode(self, chunks, **options):
                assert chunks == ["0,1,2,3,4,5", "6,7,8,9,10,11", "12"]
                assert options["batch_size"] == ENGINE.DEFAULT_BATCH_SIZE
                return np.array([[1., 0.], [0., 1.], [1., 0.]])

        args = argparse.Namespace(
            model="fixture", download_model=False, revision=None,
            device="auto", batch_size=ENGINE.DEFAULT_BATCH_SIZE, max_tokens=ENGINE.DEFAULT_MAX_TOKENS,
        )
        for requested, actual in (("auto", "cuda:0"), ("cpu", "cpu")):
            with self.subTest(device=requested):
                args.device = requested
                with patch.dict("sys.modules", {"sentence_transformers": types.SimpleNamespace(SentenceTransformer=Model)}):
                    vectors, metadata = ENGINE.semantic_vectors(["a" * 13], args)
                np.testing.assert_allclose(vectors, ENGINE.normalized(np.array([[7., 6.]])))
                self.assertEqual(metadata["chunks"], 3)
                self.assertEqual(metadata["device"], actual)


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.extractor = Path(os.environ.get(
            "CODEGRAPH_EXTRACTOR", ROOT / "target/cargo-target/debug/extract"
        ))
        if not cls.extractor.is_file():
            raise unittest.SkipTest("Build the CodeGraph exporter first")

    def test_codegraph_spans_and_neighbors_preserve_unicode_and_identity(self):
        source = '''// UTF-8 prefix: ação
mod first {
    struct Range { offset: u64, length: u64 }
    fn read_record(bytes: &[u8], at: usize) -> u8 { bytes[at] }
}
mod second {
    struct Range { offset: u64, length: u64 }
    fn read_record(bytes: &[u8], at: usize) -> u8 { bytes[at] }
    fn write_record(bytes: &mut [u8], at: usize, value: u8) { bytes[at] = value; }
    fn invoke(bytes: &[u8]) -> u8 { read_record(bytes, 0) }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.rs"
            path.write_text(source)
            symbols, _, _ = ENGINE.extract([path], self.extractor)
        self.assertEqual(len(symbols), 6)
        self.assertEqual(len({symbol["id"] for symbol in symbols}), 6)
        for symbol in symbols:
            span = symbol["span"]
            selected = source.encode()[span["start_byte"]:span["end_byte"]].decode()
            self.assertEqual(symbol["source"], selected)
        args = argparse.Namespace(top_k=5, threshold=.8)
        vectors, _ = ENGINE.lexical_vectors([symbol["source"] for symbol in symbols])
        with patch.object(ENGINE, "semantic_vectors", return_value=(vectors, {})):
            result = ENGINE.analyze(symbols, args)
        for symbol in result["symbols"]:
            self.assertNotIn(symbol["id"], [item["id"] for item in symbol["neighbors"]])
            if symbol["name"] == "read_record":
                self.assertTrue(symbol["neighbors"][0]["identical_source"])
        caller = next(symbol for symbol in symbols if symbol["name"] == "invoke")
        self.assertIn("read_record", [call["name"] for call in caller["calls"]])
        self.assertTrue(result["groups"])

    def test_project_discovery_and_cross_file_calls_and_query_neighbors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "query.rs"
            shared = root / "shared.rs"
            query.write_text("use crate::shared::read; pub struct Range { start: u64, len: u64 }\n"
                             "pub fn read(bytes: &[u8], at: usize) -> u8 { bytes[at] }\n"
                             "pub fn invoke(bytes: &[u8]) -> u8 { shared::read(bytes, 0) }\n")
            shared.write_text("pub struct Range { start: u64, len: u64 }\n"
                              "pub fn read(bytes: &[u8], at: usize) -> u8 { bytes[at] }\n")
            for name in ("tests", "target", "vendor"):
                folder = root / name
                folder.mkdir()
                (folder / "fixture.rs").write_text("fn ignored() {}")
            unsupported = root / "unsupported.sh"
            unsupported.write_text("#!/bin/sh\ntrue\n")
            partial = root / "partial.rs"
            partial.write_text("fn broken( {")
            files, excluded = ENGINE.discover(root)
            self.assertEqual(len(excluded), 3)
            self.assertEqual(set(files), {query, shared, unsupported, partial})
            self.assertIn(root / "tests/fixture.rs", ENGINE.discover(root, include_tests=True)[0])
            symbols, hashes, graph = ENGINE.extract(files, self.extractor)
            self.assertIn(str(unsupported), graph["unsupported_files"])
            self.assertIn(str(partial), graph["partial_files"])
            self.assertEqual(set(hashes), {str(query), str(shared), str(partial)})
            by_id = {symbol["id"]: symbol for symbol in symbols}
            shared_read = next(s for s in symbols if s["file"] == str(shared) and s["name"] == "read")
            caller = next(s for s in symbols if s["name"] == "invoke")
            self.assertTrue(any(c["target_id"] == shared_read["id"] and c["scope"] == "project"
                                for c in caller["calls"]))
            self.assertTrue(any(c["id"] == caller["id"] and c["scope"] == "project"
                                for c in shared_read["callers"]))
            vectors, _ = ENGINE.lexical_vectors([s["source"] for s in symbols])
            args = argparse.Namespace(top_k=5, threshold=.8)
            with patch.object(ENGINE, "semantic_vectors", return_value=(vectors, {})):
                report = ENGINE.analyze(symbols, args, {str(query)})
            self.assertEqual(len(report["query_symbols"]), 3)
            for symbol in symbols:
                if symbol["id"] in report["query_symbols"] and symbol["name"] != "invoke":
                    match = by_id[symbol["external_neighbors"][0]["id"]]
                    self.assertEqual(match["file"], str(shared))
                    self.assertEqual(match["category"], symbol["category"])
                    self.assertEqual(match["name"], symbol["name"])
            self.assertTrue(any(len({by_id[m]["file"] for m in group["members"]}) > 1
                                for group in report["groups"]))

    @unittest.skipUnless(os.environ.get("SEMANTIC_MODEL_TESTS") == "1", "Select the cached pretrained model test")
    def test_pretrained_cli_ranks_renamed_reads_above_deletion(self):
        source = "fn load_byte(bytes: &[u8], at: usize) -> u8 { bytes[at] }\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.rs"
            output = Path(directory) / "report.json"
            path.write_text(source)
            shared = Path(directory) / "shared.rs"
            shared.write_text("fn fetch_item(input: &[u8], position: usize) -> u8 { input[position] }\n"
                              "fn remove_folder(path: &std::path::Path) { std::fs::remove_dir_all(path).unwrap(); }\n")
            subprocess.run(
                [sys.executable, str(ROOT / "semantic_search.py"), str(path),
                 "--project", directory, "--extractor", str(self.extractor.resolve()), "--output", str(output)],
                capture_output=True, text=True, check=True,
            )
            report = json.loads(output.read_text())
        embedding = report["embedding"]
        self.assertEqual(len(report["files"]), 2)
        self.assertEqual(len(report["query_symbols"]), 1)
        self.assertEqual(embedding["backend"], "sentence-transformers")
        self.assertEqual(embedding["model"], ENGINE.DEFAULT_MODEL)
        self.assertEqual(embedding["revision"], ENGINE.DEFAULT_MODEL_REVISION)
        import torch

        expected_device = "cuda:0" if torch.cuda.is_available() else "cpu"
        self.assertEqual(embedding["device"], expected_device)
        symbols = {symbol["id"]: symbol for symbol in report["symbols"]}
        read = next(symbol for symbol in symbols.values() if symbol["name"] == "load_byte")
        neighbors = {symbols[item["id"]]["name"]: item for item in read["neighbors"]}
        self.assertGreater(
            neighbors["fetch_item"]["semantic_cosine"],
            neighbors["remove_folder"]["semantic_cosine"],
        )
        self.assertEqual(symbols[read["neighbors"][0]["id"]]["name"], "fetch_item")
        self.assertEqual(symbols[read["external_neighbors"][0]["id"]]["name"], "fetch_item")


if __name__ == "__main__":
    unittest.main()
