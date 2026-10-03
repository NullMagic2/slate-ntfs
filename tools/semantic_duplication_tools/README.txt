Module: semantic_duplication_tools.documentation
Purpose: Explain symbol similarity search and reviewable grouping.
Created: 2026-10-03
Architecture: The CodeGraph exporter supplies source spans and call evidence;
the Python engine ranks functions/types and emits JSON for refactoring review.

Linux CLI: semantic duplication candidates

Run commands from this directory. Requirements: Rust/Cargo, Python 3.10+,
SentenceTransformers, NumPy, and extracted CodeGraph v0.6.11 source.
CodeGraph is used as a direct dependency, not copied into Slate's source.

    python3 -m pip install -r requirements.txt
    python3 build.py --codegraph /path/to/CodeGraph-v0.6.11
    python3 semantic_search.py ../../src/tools/recovery.rs \
        --extractor target/cargo-target/debug/extract \
        --output target/recovery-similarity.json --download-model

Pass --offline to build.py when the Cargo dependencies are already cached.
The normal Cargo dependency cache is respected. Build artifacts stay in target/.
Input files select the queries; the comparison corpus is the whole project.
The root is inferred from Git/style-guide markers or the outer Cargo manifest.
--project ROOT overrides discovery. With no query files, it ranks all symbols:

    python3 semantic_search.py --project ../.. \
        --extractor target/cargo-target/debug/extract \
        --output target/project-similarity.json

What is searched

CodeGraph extracts every function/method and declared type, including aliases,
traits and nested declarations. Its parser registry selects supported Rust,
Python, C/C++, and Pascal files, including Python scripts without extensions.
ProjectIndex joins per-file graphs and supplies cross-file calls and callers;
the tool reuses that implementation rather than inventing another resolver.
Source hashes and exact UTF-8 byte/line spans identify the source version.

Source is scanned recursively. Separate tests are included with --include-tests.
Generated kernel metadata, vendored code, build/cache directories and symlinks
are excluded. project.excluded_paths lists these exclusions; graph lists
unsupported files, partial parses, module dependencies and cross-file edges.
Shell and PowerShell have no CodeGraph parser and are listed as unsupported.
Partial parses retain available symbols but cannot establish complete coverage.

Pretrained semantic embeddings

The engine uses SentenceTransformers with Qwen/Qwen3-Embedding-0.6B, a model
that supports code retrieval. Its default revision is pinned in semantic_search.py
and recorded in every report. There is no LSA backend or automatic substitute.
Names, signatures, adjacent documentation and complete source form each input.

    python3 semantic_search.py ../../src/tools/recovery.rs \
        --extractor target/cargo-target/debug/extract \
        --output target/recovery-semantic.json

The first command above permits downloading the pinned weights. Subsequent
runs use the cache without --download-model. Source code stays on this machine;
the download retrieves model files, not an external inference service.

SentenceTransformers selects an available GPU by default, including AMD ROCm.
Install the appropriate PyTorch build before requirements.txt when using a GPU.
--device cpu or --device cuda:0 overrides automatic selection. Reports include
the actual device, model revision, embedding dimensions and package versions.
--batch-size defaults to 8; --max-tokens defaults to 1024. Long symbols are
split into bounded chunks and pooled with token-count weights, retaining their
final partial chunk. These pooled vectors are normalized per symbol.

To select another cached model or local directory:

    python3 semantic_search.py ../../src/tools/recovery.rs \
        --extractor target/cargo-target/debug/extract \
        --model /path/to/local/sentence-transformer \
        --output target/recovery-semantic.json

--revision pins an alternate model. Model inference stays local and remote model
code is disabled. Missing dependencies or weights fail instead of changing the
comparison method. Retrieval training does not establish code equivalence;
chunk pooling and the score threshold require review for this Rust corpus.
Model reference: https://huggingface.co/Qwen/Qwen3-Embedding-0.6B
API reference: https://sbert.net/docs/package_reference/sentence_transformer/model.html

Scores and proposed groups

The score is 70% semantic cosine + 20% lexical cosine + 10% shared-call Jaccard.
Calls compare project-qualified symbol identities when CodeGraph resolves them;
unresolved names remain syntax evidence with explicit resolution labels.
These fixed heuristic weights are reported, not calibrated probabilities.
Each query symbol gets --top-k nearest neighbors (default 5) across the corpus,
plus external_neighbors from other files even when local matches rank higher.
The full corpus inventory retains source and call evidence. Component scores,
shared terms and exact-source comparisons remain visible below the grouping
threshold. Function/type categories stay separate.

Groups use a deterministic greedy partition with a complete-link constraint:
EVERY pair in a group must meet --threshold (default 0.80). An A~B~C chain
cannot group A with C unless their direct score also qualifies. Groups contain
at least one query symbol and may span files; singletons remain in the inventory.

Review the source and contracts before merging: errors, mutation order,
ownership, side effects and platform assumptions can differ despite high scores.
Graph resolution is heuristic; Rust macro expansion, reexports, traits and FFI
need compiler/source confirmation. Ambiguous targets retain candidate edges.
Conditional code inside indexed files is parsed without evaluating cfg flags.
Missing incoming edges do not establish dead code.
The tool never rewrites code or executes code from the analyzed source.

Selective tests (no tests run during build)

    python3 -m unittest discover -s tests -v

CODEGRAPH_EXTRACTOR can select another built exporter for the integration test.
Without an exporter, that integration test is explicitly skipped.
The project fixture checks discovery, partial/unsupported coverage, cross-file
callers/callees and external function/type matches with query-only ranking.
The cached pretrained model test is selective and performs actual inference:

    SEMANTIC_MODEL_TESTS=1 python3 -m unittest discover -s tests -v
