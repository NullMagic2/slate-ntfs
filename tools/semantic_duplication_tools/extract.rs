//! Module: semantic_duplication_tools::extract
//! Purpose: Export source outlines and a project-wide CodeGraph dependency index.
//! Created: 2026-10-03
//! Architecture: The Python similarity CLI consumes this adapter; CodeGraph
//! owns language parsing, source spans and dependency analysis.

use codegraph::{LanguageId, ParserRegistry, ProjectIndex};
use std::error::Error;
use std::io::{self, Write};
use std::path::PathBuf;

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments
        .next()
        .ok_or("usage: extract SOURCE_FILE | --project < PATHS_JSON")?;
    if arguments.next().is_some() {
        return Err("usage: extract SOURCE_FILE".into());
    }
    let paths = if first == "--project" {
        serde_json::from_reader::<_, Vec<PathBuf>>(io::stdin().lock())?
    } else {
        vec![PathBuf::from(first)]
    };
    let registry = ParserRegistry::new();
    let mut project = ProjectIndex::new();
    let mut documents = Vec::new();
    let mut unsupported = Vec::new();
    for path in paths {
        let path = path.canonicalize()?;
        let language = registry.language_for_path(&path);
        if language.is_none() && path.extension().is_some() {
            unsupported.push(path);
            continue;
        }
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(_) if language.is_none() => {
                unsupported.push(path);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let language = language.or_else(|| {
            source
                .lines()
                .next()
                .filter(|line| line.starts_with("#!") && line.contains("python"))
                .map(|_| LanguageId::Python)
        });
        let Some(language) = language else {
            unsupported.push(path);
            continue;
        };
        let document = registry.parse_as(&language, source)?;
        eprintln!("Indexed {}", path.display());
        project.upsert_path(&path, &document);
        documents.push(serde_json::json!({
            "path": path, "language": document.language().as_str(),
            "source": document.source(), "outline": document.outline(),
        }));
    }
    let output = serde_json::json!({
        "documents": documents, "unsupported": unsupported,
        "module_edges": project.module_edges(), "cross_edges": project.cross_symbol_edges(),
    });
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output)?;
    writeln!(stdout)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("extract: {error}");
        std::process::exit(1);
    }
}
