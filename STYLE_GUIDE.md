<!--
Module: documentation.style_guide
Purpose: Define source readability, comments and documentation creation rules.
Created: 2026-10-01
Architecture: Contributors apply these rules across source, tests and packaging;
ARCHITECTURE.md describes module boundaries and runtime responsibilities.
-->

# Slate NTFS style guide

## Human-readable files and module headers

Handwritten source, scripts, configuration, tests and documentation must be easy
for a person to read. Use clear names, consistent indentation, spaces around
operators and after commas, and blank lines between functions and logical
steps. Split long statements and lists across lines. Avoid minified code,
one-line functions and methods, and multiple unrelated actions on one line. Write
function and method bodies across multiple lines, including short accessors, so
their behavior remains easy to read and extend. Use four
spaces per indentation level in Rust, Python and new C code. Keep required
syntax such as Makefile recipe tabs intact. Generated files and vendored code
retain their upstream format; identify them as generated rather than editing
their formatting by hand.

Every handwritten file must begin with a module-level comment that
states its module name, purpose, creation day and relationship to the rest of
the code. Keep a required shebang or encoding declaration first. Use the
language's normal comment syntax: Rust `//!` documentation, a Python module
docstring, a C block comment or shell/configuration `#` comments. For documents,
use a short introductory note or HTML comment as appropriate.

The creation day is the day the file was first created, written as `YYYY-MM-DD`;
it is not the last-edit date. Preserve it when editing the file. If the creation
day was not recorded, consult the filesystem creation (birth) timestamp, for
example `stat -c '%w' path`, and use that date to fill in the header. Prefer
the original file's timestamp and also consult reliable history where
available. Modification time (`mtime`) and metadata-change time (`ctime`) are
not creation timestamps. For copied or extracted source with no recorded date,
the available file's birth date may be used as the timestamp fallback; record
that provenance in the validation notes so it is not presented as verified
original authorship. If neither a recorded date nor a creation timestamp is
available, write `Created: unknown`.

Use a single module-name line at the opening of the header; do not repeat the
name in a closing comment. Add comments to important, non-obvious functions and
commands too. Explain the reason, invariant or consequence: credential changes,
authorization boundaries, fallback behavior, subprocess flags, on-disk ordering
and notification requirements. Avoid comments that merely restate the syntax.
Indent standalone comments with the code they describe, using the same spaces
as the surrounding block. Leave one space between code and an inline comment,
and one space after a line-comment marker (`//`, `#`, or `//!`). Preserve `/* ... */`
block delimiters and the language's required syntax. Never run a comment into
the preceding statement. Keep comments next to the decisions they explain and
update them with the code.

Keep comments compact. Each ordinary comment block, including API documentation
and docstrings, must use no more than four lines. An opening module comment may
use up to ten lines. Count blank lines and block delimiters within the comment.
Do not split one explanation into adjacent blocks to bypass these limits;
shorten it and keep only the reason or invariant the reader needs.

Short Python explanations use `#` comments, with one space after `#`, rather
than triple-quoted strings. Indent them inside the function and leave a blank
line between the explanation and the statements it describes. Use docstrings
for actual module or API documentation, rather than incidental implementation
comments. For example:

```python
def gio_access(path, writable, deletable=None, uid=UID, gid=GID, groups=()):
    # Check the same GIO capabilities that determine Files menu actions.

    text = run(
        "gio", "info", "-a",
        "access::can-write,access::can-delete,access::can-rename", path,
        capture_output=True,
        text=True,
        preexec_fn=credentials(uid, gid, groups),
    ).stdout
```

For example, the mount-state module begins with:

```rust
//! Module: ntfs_permissions::mount
//! Purpose: inspect live mount state and apply saved permissions safely.
//! Created: 2026-10-01
//! Architecture: the privileged policy backend calls this module to remount
//! drives; the GTK model reads it to show actual read-only state. The kernel
//! writer remains responsible for deciding whether NTFS can accept writes.
```

Keep one opening module header per source file. After merging source files,
remove their old embedded module headers instead of carrying separate file
provenance blocks into the merged file. Inline namespaces do not need repeated
module headers; use ordinary comments only where they explain an invariant.

The architecture comment must explain the module's boundary, not just repeat
its filename. Name its important callers, the lower-level services or modules
it uses, and which decisions it owns. State where it passes responsibility to
another layer. Update this description and the directory map when moving or
splitting a module. The header explains the file locally; ARCHITECTURE.md explains how those files
work together.

## Linux-only target

The project targets Linux only. Do not add product builds, platform adapters,
compatibility stubs or fallback implementations for other operating systems.
Express Linux requirements at the relevant crate or module boundary instead of
repeating unsupported-platform branches in individual functions.

## Reusable modules and data types

Before writing or changing code, inspect the existing modules, data types and
call graph for an implementation that already owns the required behavior. Make
an explicit effort to reuse that implementation by calling it; copying its code
or introducing another equivalent helper does not count as reuse. Check that its
invariants, validation, error handling and ordering match the caller's needs.

Design code for reuse from the start. Modules and data types must be reusable
across callers and APIs within the Linux target.
Give each module a clear responsibility and each type a coherent meaning with
explicit invariants. Keep shared logic independent of a particular command,
user interface or platform; put those dependencies behind adapters at the
appropriate boundary. Reuse existing types and operations where they express
the same concept, and avoid duplicating models or behavior for individual
callers. Keep interfaces small and explicit, and introduce abstractions only
when they support a concrete shared responsibility.

## Tests and selective execution

Production modules CANNOT contain embedded tests, test fixtures or test-only
helper implementations. All tests MUST stay in separate test folders, grouped
by the functionality they verify; do not place test implementations alongside
production modules. Production modules may reference those
external test files without containing their implementations.

Provide explicit selectors or test-name filters so each module or suite can be
run independently. Document the command for each suite. Builds must not run
tests automatically, and the test entry point must list available suites when
no selector is given rather than implicitly running every test.

## Named constants

Never use magic numbers. Give numeric values with domain meaning a descriptive
constant, including format offsets, sizes, record identities, flags, permission
masks, timeouts and retry limits. Use the constant at each relevant call site.

Constants are expected to be shared across modules throughout the project.
Define each domain concept once in its owning module and import that constant
wherever the same concept is used. Parsers, encoders, recovery, checking and
formatting must agree through the shared definition; do not duplicate its value
in local constants.

Reuse existing constants from the owning module or Linux API before adding
another definition. Derive related values from those constants rather than
repeating their numeric values. Do not reuse a constant for a different concept
merely because its value happens to match. Keep constants at the narrowest shared
scope that expresses their ownership; avoid creating a separate constants module
for one caller. Configuration fields and named test-fixture declarations should
state their values explicitly rather than hiding them inside executable logic.

## Formatting and platform

Format Rust with the root rustfmt.toml (120 columns, maximal small heuristics).
The project targets 64-bit Linux only. Do not add platform guards, 32-bit
overflow conversions or portable fallbacks for other systems; the tools crate
asserts the 64-bit assumption once. Linux ioctl numbers and file-descriptor
helpers live in src/tools/linux.rs.

## Plain comment text

Do not use backticks in code comments or docstrings, including module headers.
Write identifiers, paths and commands as plain text. Markdown prose outside
code comments may use its normal formatting.

## Creating documentation files

Ask the user before creating any additional Markdown (.md) file. An explicit
request from the user to create a named Markdown file supplies that approval.
Prefer updating existing documentation when the user has not requested a new
file. Do not create extra Markdown reports or notes without asking first.
