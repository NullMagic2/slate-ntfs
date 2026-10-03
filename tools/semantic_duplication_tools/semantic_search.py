#!/usr/bin/env python3
"""Module: semantic_duplication_tools.semantic_search
Purpose: Rank and group CodeGraph symbols for evidence-based reuse review.
Created: 2026-10-03
Architecture: CodeGraph extracts symbols; SentenceTransformers ranks candidates.
Reports preserve source, call-resolution evidence and pairwise group bounds.
"""

import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import numpy as np

CALLABLE_KINDS = {"function", "method", "procedure", "constructor", "destructor"}
TYPE_KINDS = {"class", "struct", "enum", "trait", "interface", "type_alias"}
CALL_KINDS = {"call", "method_call", "construction"}
STOP_WORDS = set((
    "fn pub self mut let const return if else for while in impl use mod struct enum type "
    "class def import from true false none some ok err as and or not the a an to of with is it this that"
).split())
MAX_FEATURES = 4096
DEFAULT_THRESHOLD = 0.80
DEFAULT_NEIGHBORS = 5
DEFAULT_MODEL = "Qwen/Qwen3-Embedding-0.6B"
DEFAULT_MODEL_REVISION = "97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
DEFAULT_BATCH_SIZE = 8
DEFAULT_MAX_TOKENS = 1024
SEMANTIC_WEIGHT = 0.70
LEXICAL_WEIGHT = 0.20
CALL_WEIGHT = 0.10
TOKEN_MARGIN = 8
EXCLUDED_DIRECTORIES = {".git", "target", "__pycache__", ".venv", "venv", "node_modules", "vendor", "dist", "build", "results"}
GENERATED_FILES = {"ntfs_rs.mod.c", "core_fingerprint.h"}


def terms(text):
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z])([A-Z][a-z])", r"\1 \2", text)
    return [word for word in re.findall(r"[^\W\d_]+", text.lower()) if word not in STOP_WORDS]


def leading_comment(source, start):
    lines = source[:start].decode("utf-8").splitlines()
    result = []
    for line in reversed(lines):
        line = line.strip()
        if line.startswith(("//", "#", "*")):
            result.append(line)
        elif not line and not result:
            continue
        else:
            break
    return "\n".join(reversed(result))


def discover(root, include_tests=False):
    files, excluded = [], []
    for directory, folders, names in os.walk(root):
        for name in folders[:]:
            path = Path(directory) / name
            if name in EXCLUDED_DIRECTORIES or path.is_symlink() or (name in {"tests", "test"} and not include_tests):
                folders.remove(name)
                excluded.append(str(path))
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or name in GENERATED_FILES or (name.startswith("test_") and not include_tests):
                excluded.append(str(path))
            else:
                files.append(path.resolve())
    return sorted(files), sorted(excluded)


def project_root(files):
    start = Path(os.path.commonpath([str(path.parent) for path in files]))
    ancestors = (start, *start.parents)
    for path in ancestors:
        if (path / ".git").exists() or (path / "STYLE_GUIDE.md").is_file():
            return path
    crates = [path for path in ancestors if (path / "Cargo.toml").is_file()]
    return crates[-1] if crates else start


def extract(paths, exporter):
    result = subprocess.run(
        [str(exporter), "--project"], input=json.dumps([str(path) for path in paths]),
        capture_output=True, text=True, check=True,
    )
    project = json.loads(result.stdout)
    symbols, hashes, names = [], {}, {}

    def walk(nodes, path, source, parents=()):
        for node in nodes:
            identity = f"{path}::{node['id']}"
            names[identity] = node["name"]
            qualified = (*parents, node["name"])
            if node["kind"] in CALLABLE_KINDS | TYPE_KINDS:
                span = node["span"]
                code = source[span["start_byte"]:span["end_byte"]].decode("utf-8")
                symbols.append({
                    "id": identity, "local_id": node["id"],
                    "file": str(path), "name": node["name"],
                    "qualified_name": "::".join(qualified), "kind": node["kind"],
                    "category": "function" if node["kind"] in CALLABLE_KINDS else "type",
                    "signature": node["signature"], "span": span,
                    "source": code, "documentation": leading_comment(source, span["start_byte"]),
                    "source_sha256": hashlib.sha256(code.encode()).hexdigest(),
                    "calls": [], "callers": [],
                })
            walk(node["children"], path, source, qualified)

    for document in project["documents"]:
        path = Path(document["path"])
        source = document["source"].encode("utf-8")
        hashes[str(path)] = hashlib.sha256(source).hexdigest()
        walk(document["outline"]["symbols"], path, source)
    by_id = {symbol["id"]: symbol for symbol in symbols}

    def link(caller_id, target_id, name, edge, scope):
        if edge["kind"] not in CALL_KINDS or caller_id not in by_id:
            return
        caller = by_id[caller_id]
        call = {"name": name, "target_id": target_id, "resolution": edge["resolution"],
                "kind": edge["kind"], "scope": scope}
        if call not in caller["calls"]:
            caller["calls"].append(call)
        if target_id in by_id:
            incoming = {"id": caller_id, "resolution": edge["resolution"], "scope": scope}
            if incoming not in by_id[target_id]["callers"]:
                by_id[target_id]["callers"].append(incoming)

    for document in project["documents"]:
        path = document["path"]
        for edge in document["outline"]["dependencies"]["edges"]:
            target = edge["target"]
            target_id = f"{path}::{target['value']}" if target["type"] == "symbol" else None
            caller_id = f"{path}::{edge['from']}"
            link(caller_id, target_id, names.get(target_id, target["value"]), edge, "local")
            for candidate in edge.get("candidates", []):
                identity = f"{path}::{candidate}"
                link(caller_id, identity, names.get(identity, candidate), edge, "local-candidate")
    for edge in project["cross_edges"]:
        caller_id = f"{edge['from_module']}::{edge['from_symbol']}"
        target_id = f"{edge['to_module']}::{edge['to_symbol']}"
        link(caller_id, target_id, names.get(target_id, edge["to_symbol"]), edge, "project")
    graph = {
        "module_edges": project["module_edges"], "cross_edges": project["cross_edges"],
        "unsupported_files": project["unsupported"],
        "partial_files": [doc["path"] for doc in project["documents"] if doc["outline"]["has_syntax_errors"]],
    }
    return symbols, hashes, graph


def normalized(matrix):
    if not np.isfinite(matrix).all():
        raise ValueError("Embedding contains non-finite values")
    return matrix / np.maximum(np.linalg.norm(matrix, axis=1, keepdims=True), np.finfo(float).eps)


def lexical_vectors(documents):
    counts = [Counter(terms(document)) for document in documents]
    frequency = Counter(word for count in counts for word in count)
    vocabulary = sorted(frequency, key=lambda word: (-frequency[word], word))[:MAX_FEATURES]
    positions = {word: index for index, word in enumerate(vocabulary)}
    vectors = np.zeros((len(documents), len(vocabulary)), dtype=float)
    for row, count in enumerate(counts):
        for word, occurrences in count.items():
            if word in positions:
                inverse_frequency = np.log((1 + len(documents)) / (1 + frequency[word])) + 1
                vectors[row, positions[word]] = (1 + np.log(occurrences)) * inverse_frequency
    return normalized(vectors), counts


def semantic_vectors(documents, args):
    from sentence_transformers import SentenceTransformer

    revision = args.revision or (DEFAULT_MODEL_REVISION if args.model == DEFAULT_MODEL else None)
    model = SentenceTransformer(
        args.model, device=None if args.device == "auto" else args.device,
        local_files_only=not args.download_model, trust_remote_code=False,
        revision=revision, model_kwargs={"dtype": "auto"},
    )
    # Bound each batch while retaining all long-symbol chunks in the pooled vector.

    model.max_seq_length = min(model.max_seq_length, args.max_tokens)
    width = model.max_seq_length - model.tokenizer.num_special_tokens_to_add(pair=False) - TOKEN_MARGIN
    if width <= 0:
        raise ValueError("Model token window is too small")
    chunks, owners, weights = [], [], []
    for owner, document in enumerate(documents):
        tokens = model.tokenizer.encode(document, add_special_tokens=False, verbose=False)
        for start in range(0, max(1, len(tokens)), width):
            part = tokens[start:start + width]
            chunks.append(model.tokenizer.decode(part))
            owners.append(owner)
            weights.append(max(1, len(part)))
    vectors = model.encode(
        chunks, batch_size=args.batch_size, convert_to_numpy=True,
        normalize_embeddings=True, show_progress_bar=False,
    )
    pooled = np.zeros((len(documents), vectors.shape[1]))
    for owner, vector, weight in zip(owners, vectors, weights):
        pooled[owner] += vector * weight
    return normalized(pooled), {
        "backend": "sentence-transformers", "model": args.model, "revision": revision,
        "device": str(model.device), "dimensions": vectors.shape[1],
        "sentence_transformers": version("sentence-transformers"), "torch": version("torch"),
        "chunks": len(chunks), "chunk_token_limit": width, "batch_size": args.batch_size,
        "pooling": "Token-weighted mean of normalized chunk embeddings; normalized per symbol.",
    }


def call_similarity(left, right):
    return len(left & right) / len(left | right) if left | right else 0.0


def pair_scores(lexical, semantic, calls, left, right):
    lexical_scores = np.clip(lexical[left] @ lexical[right].T, 0, 1)
    semantic_scores = np.clip(semantic[left] @ semantic[right].T, 0, 1)
    call_scores = np.array([[call_similarity(calls[a], calls[b]) for b in right] for a in left])
    scores = SEMANTIC_WEIGHT * semantic_scores + LEXICAL_WEIGHT * lexical_scores + CALL_WEIGHT * call_scores
    return scores, semantic_scores, lexical_scores, call_scores


def group_symbols(symbols, scores, threshold):
    groups = [[index] for index in range(len(symbols))]
    pairs = sorted((-scores[a, b], a, b) for a in range(len(symbols)) for b in range(a + 1, len(symbols))
                   if symbols[a]["category"] == symbols[b]["category"] and scores[a, b] >= threshold)
    membership = list(range(len(symbols)))
    for _, left, right in pairs:
        first, second = membership[left], membership[right]
        if first == second:
            continue
        if all(scores[a, b] >= threshold for a in groups[first] for b in groups[second]):
            for index in groups[second]:
                membership[index] = first
            groups[first].extend(groups[second])
            groups[second] = []
    return [group for group in groups if len(group) > 1]


def analyze(symbols, args, query_files=None):
    if not symbols:
        return {"symbols": [], "query_symbols": [], "groups": [],
                "embedding": {"backend": "sentence-transformers", "empty": True}}
    queries = [index for index, symbol in enumerate(symbols) if query_files is None or symbol["file"] in query_files]
    if not queries:
        return {"symbols": symbols, "query_symbols": [], "groups": [],
                "embedding": {"backend": "sentence-transformers", "empty_query": True}}
    documents = ["\n".join((symbol["name"], symbol["signature"], symbol["documentation"], symbol["source"]))
                 for symbol in symbols]
    lexical, counts = lexical_vectors(documents)
    semantic, embedding = semantic_vectors(documents, args)
    calls = [{call.get("target_id") or f"unresolved:{call['name']}" for call in symbol["calls"]}
             for symbol in symbols]
    scores, semantic_scores, lexical_scores, call_scores = pair_scores(
        lexical, semantic, calls, queries, list(range(len(symbols))),
    )
    grouped = set(queries)
    for row, index in enumerate(queries):
        symbol = symbols[index]
        candidates = [other for other in range(len(symbols)) if other != index
                      and symbols[other]["category"] == symbol["category"]]
        candidates.sort(key=lambda other: (-scores[row, other], symbols[other]["id"]))

        def neighbor(other):
            return {
                "id": symbols[other]["id"], "score": float(scores[row, other]),
                "semantic_cosine": float(semantic_scores[row, other]),
                "lexical_cosine": float(lexical_scores[row, other]), "call_overlap": float(call_scores[row, other]),
                "identical_source": symbol["source_sha256"] == symbols[other]["source_sha256"],
                "shared_terms": sorted(counts[index].keys() & counts[other].keys()),
            }

        symbol["neighbors"] = [neighbor(other) for other in candidates[:args.top_k]]
        external = [other for other in candidates if symbols[other]["file"] != symbol["file"]]
        symbol["external_neighbors"] = [neighbor(other) for other in external[:args.top_k]]
        grouped.update(other for other in candidates if scores[row, other] >= args.threshold)
    selected = sorted(grouped)
    group_scores, _, _, _ = pair_scores(lexical, semantic, calls, selected, selected)
    selected_symbols = [symbols[index] for index in selected]
    groups = group_symbols(selected_symbols, group_scores, args.threshold)
    query_ids = {symbols[index]["id"] for index in queries}
    groups = [{"members": [selected_symbols[index]["id"] for index in group],
               "category": selected_symbols[group[0]]["category"],
               "minimum_pair_score": float(min(group_scores[a, b] for a in group for b in group if a != b))}
              for group in groups if any(selected_symbols[index]["id"] in query_ids for index in group)]
    return {"symbols": symbols, "query_symbols": sorted(query_ids), "groups": groups, "embedding": embedding}


def main():
    parser = argparse.ArgumentParser(description="Find related CodeGraph functions and types; never edits source.")
    parser.add_argument("files", type=Path, nargs="*", help="Query files; compared against the whole project")
    parser.add_argument("--project", type=Path, help="Project root; inferred from query files when omitted")
    parser.add_argument("--include-tests", action="store_true", help="Include test folders and test_* files")
    parser.add_argument("--extractor", type=Path, required=True, help="Binary produced by build.py")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Local/cached model (default: %(default)s)")
    parser.add_argument("--revision", help="Pinned model revision for reproducibility")
    parser.add_argument("--device", default="auto", help="auto selects an available GPU; cpu or cuda:0 overrides")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS, help="Maximum tokens per model chunk")
    parser.add_argument("--download-model", action="store_true", help="Permit downloading model weights")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--top-k", type=int, default=DEFAULT_NEIGHBORS)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("This tool targets Linux only")
    if min(args.top_k, args.batch_size, args.max_tokens) < 1 or not 0 < args.threshold <= 1:
        parser.error("top-k/batch-size/max-tokens must be positive; threshold must be in (0, 1]")
    queries = sorted({path.resolve(strict=True) for path in args.files})
    if not queries and not args.project:
        parser.error("Supply query files or --project ROOT to compare all project symbols")
    root = args.project.resolve(strict=True) if args.project else project_root(queries)
    if not root.is_dir() or any(not path.is_relative_to(root) for path in queries):
        parser.error("--project must be a directory containing every query file")
    files, excluded = discover(root, args.include_tests)
    print(f"Indexing project {root} ...", file=sys.stderr)
    symbols, hashes, graph = extract(files, args.extractor.resolve(strict=True))
    if str(args.output.resolve()) in hashes:
        parser.error("Report output must not overwrite an indexed source file")
    if any(str(path) not in hashes for path in queries):
        parser.error("A query file was excluded or unsupported; use --include-tests for test files")
    print(f"Embedding {len(symbols)} symbols across {len(hashes)} files ...", file=sys.stderr)
    report = analyze(symbols, args, {str(path) for path in queries} if queries else None)
    report.update({"schema_version": 2, "files": hashes, "threshold": args.threshold, "top_k": args.top_k,
                   "project": {"root": str(root), "query_files": [str(path) for path in queries],
                               "include_tests": args.include_tests, "excluded_paths": excluded},
                   "graph": graph,
                   "runtime": {"python": sys.version, "numpy": np.__version__},
                   "weights": {"semantic": SEMANTIC_WEIGHT, "lexical": LEXICAL_WEIGHT, "calls": CALL_WEIGHT},
                   "limitations": ["Scores rank review candidates, not behavioral equivalence or deletion safety.",
                                   "CodeGraph call resolution is heuristic; missing callers do not prove unused code.",
                                   "CodeGraph cannot compile Rust macros, reexports, traits or FFI to prove call targets.",
                                   "Partial parses and unsupported files are listed in graph coverage.",
                                   "Groups compare functions with functions and types with types; only selected queries are ranked.",
                                   "Every group pair meets the threshold; groups are a greedy partition."]})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(hashes)} files, {len(symbols)} corpus symbols, {len(report.get('query_symbols', []))} query symbols, "
          f"{len(report['groups'])} groups, {len(graph['partial_files'])} partial parses -> {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, ImportError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
