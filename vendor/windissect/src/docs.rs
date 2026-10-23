//! Categorized documentation generator for Windissect IR databases.

use crate::model::Database;
use anyhow::Result;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Generate codebase documentation and API reference pages.
pub fn generate_all(db: Option<&Database>, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    generate_codebase_md(&out_dir.join("codebase.md"))?;
    if let Some(db) = db {
        let api_dir = out_dir.join("api");
        fs::create_dir_all(&api_dir)?;
        generate_api_md(db, &api_dir)?;
    }
    Ok(())
}

fn generate_codebase_md(path: &Path) -> Result<()> {
    let content = r"# Codebase Architecture

Overview of the Windissect PE/PDB extraction pipeline and module structure.

## Modules

| Module | Description | Entrypoints |
|---|---|---|
| [`main.rs`](../src/main.rs) | CLI entrypoint (`extract`, `emit-cpp`, `emit-headers`, `emit-rust`, `classes`, `verify`, `doc`). | `main()` |
| [`extract.rs`](../src/extract.rs) | PE export reader (`goblin`) and PDB GUID extractor. | `from_pe()` |
| [`pdbsym.rs`](../src/pdbsym.rs) | PDB symbol iterator (`pdb` crate) for internal functions. | `read()` |
| [`demangle.rs`](../src/demangle.rs) | MSVC demangler (`msvc-demangler`) and function classifier. | `demangle()`, `parse_decl()`, `classify()` |
| [`typeparse.rs`](../src/typeparse.rs) | C++ type parser (builtins, pointers, templates, function pointers). | `parse()`, `type_text()` |
| [`model.rs`](../src/model.rs) | IR data models (`Symbol`, `Signature`, `Database`). | `Database`, `Symbol` |
| [`emit.rs`](../src/emit.rs) | C++ header generator. | `cpp_class()`, `emit_all_headers()` |
| [`emit_rust.rs`](../src/emit_rust.rs) | Rust FFI bindings crate generator. | `generate_crate()` |
| [`verify.rs`](../src/verify.rs) | IR validation suite. | `run()` |
| [`docs.rs`](../src/docs.rs) | Documentation generator. | `generate_all()` |

---

## Detailed Module Overview

### 1. `main.rs`
Handles CLI arguments using `clap` and dispatches subcommands (`extract`, `verify`, `emit-headers`, `emit-rust`, etc.).

### 2. `extract.rs` & `pdbsym.rs`
Parses PE exports using `goblin` and merges identity-matched public and private functions from Microsoft PDBs.

### 3. `demangle.rs` & `typeparse.rs`
Demangles MSVC symbols and parses C++ function declarations into structured types (return type, class, method name, parameters, calling convention).

### 4. `model.rs`
Defines the serialized IR (`ir/symbols.json`).

### 5. `emit.rs` & `emit_rust.rs`
Generates C++ headers and a target-specific buildable Rust FFI crate.

### 6. `verify.rs`
Validates that generated IR matches schema rules and ground-truth method signatures.
";
    fs::write(path, content)?;
    Ok(())
}

fn classify_category(class: &str) -> &'static str {
    if class.contains("Layout") {
        "Layout Managers"
    } else if class.contains("Provider")
        || class.contains("Accessible")
        || class.contains("Proxy")
        || class.contains("Uia")
    {
        "Accessibility & UIA Providers"
    } else if class.contains("Parser")
        || class.contains("Xml")
        || class.contains("Sheet")
        || class.contains("ByteCode")
    {
        "XML & Parsing Engine"
    } else if class.contains("Animation") || class.contains("PVL") {
        "Animation & PVL"
    } else if class.contains("Button")
        || class.contains("Edit")
        || class.contains("Text")
        || class.contains("Progress")
        || class.contains("Bar")
        || class.contains("Select")
        || class.contains("List")
        || class.contains("View")
        || class.contains("Combobox")
    {
        "Controls & Widgets"
    } else if class.contains("Behavior") {
        "Behaviors & Policies"
    } else if class.contains("Value")
        || class.contains("Font")
        || class.contains("Color")
        || class.contains("Expression")
        || class.contains("UID")
    {
        "Values & Data Types"
    } else if class.contains("Element") || class.contains("HWND") || class.contains("ClassInfo") {
        "Core & Base Elements"
    } else if class.contains("Macro")
        || class.contains("Page")
        || class.contains("Repeater")
        || class.contains("Viewer")
        || class.contains("Dialog")
        || class.contains("Expand")
        || class.contains("XBaby")
    {
        "Containers & Composites"
    } else {
        "Utilities & Helpers"
    }
}

fn generate_api_md(db: &Database, api_dir: &Path) -> Result<()> {
    let classes = crate::emit::classes(db);
    let mut categorized: BTreeMap<&'static str, Vec<(&String, &String, usize)>> = BTreeMap::new();

    for item @ (_, class, _) in &classes {
        let cat = classify_category(class);
        categorized
            .entry(cat)
            .or_default()
            .push((&item.0, &item.1, item.2));
    }

    let mut index = String::new();
    let _ = write!(index, "# {} API Reference\n\n", db.binary.file);
    let _ = write!(
        index,
        "Total symbols: **{}** | Total classes: **{}**\n\n",
        db.symbols.len(),
        classes.len()
    );

    // Category Table of Contents
    index.push_str("## Category Index\n\n");
    for cat in categorized.keys() {
        let anchor = cat
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == ' ' || c == '-' {
                    c
                } else {
                    ' '
                }
            })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-");
        let _ = writeln!(index, "- [{cat}](#{anchor})");
    }
    index.push_str("\n---\n\n");

    // Check for duplicate class names across namespaces
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, class, _) in &classes {
        let clean = crate::emit::sanitize_filename(class);
        *name_counts.entry(clean).or_default() += 1;
    }

    // Render each category
    for (cat, class_list) in &categorized {
        let _ = write!(index, "## {cat}\n\n");
        index.push_str("| Namespace | Class | Members | Link |\n|---|---|---|---|\n");

        for (ns, class, count) in class_list {
            let clean = crate::emit::sanitize_filename(class);
            let file_name = if name_counts.get(&clean).copied().unwrap_or(0) <= 1 {
                format!("{clean}.md")
            } else {
                format!(
                    "{}_{clean}.md",
                    if ns.is_empty() {
                        "global".into()
                    } else {
                        crate::emit::sanitize_filename(ns)
                    }
                )
            };
            let _ = writeln!(
                index,
                "| `{ns}` | `{class}` | {count} | [{class}](./{file_name}) |"
            );

            let class_page = render_class_page(db, ns, class, *count, cat);
            fs::write(api_dir.join(&file_name), class_page)?;
        }
        index.push('\n');
    }

    fs::write(api_dir.join("README.md"), index)?;
    Ok(())
}

fn render_class_page(db: &Database, ns: &str, class: &str, count: usize, category: &str) -> String {
    let mut page = String::new();
    let display_namespace = if ns.is_empty() { "global" } else { ns };
    let _ = write!(page, "# `{display_namespace}` :: `{class}`\n\n");
    let _ = write!(page, "**Category:** [{category}](./README.md)\n\n");
    let _ = write!(
        page,
        "Reconstructed from `{}`. Total members: **{count}**.\n\n",
        db.binary.file
    );
    page.push_str("```cpp\n");
    page.push_str(&crate::emit::cpp_class(db, ns, class));
    page.push_str("\n```\n\n## Member List\n\n");
    page.push_str("| Method | Return | Shape | Provenance | Exported |\n|---|---|---|---|---|\n");
    for symbol in db.symbols.iter().filter(|symbol| {
        !symbol.library
            && symbol.sig.parse_ok
            && symbol.sig.namespace.as_deref().unwrap_or("") == ns
            && symbol.sig.class.as_deref() == Some(class)
    }) {
        let method = symbol.sig.method.as_deref().unwrap_or("?");
        let ret = symbol
            .sig
            .ret
            .as_ref()
            .map_or("void", |ty| ty.text.as_str());
        let kind = format!("{:?}", symbol.kind);
        let provenance = format!("{:?}", symbol.provenance);
        let exported = if symbol.exported { "Yes" } else { "No (PDB)" };
        let _ = writeln!(
            page,
            "| `{method}` | `{ret}` | `{kind}` | `{provenance}` | {exported} |"
        );
    }
    page
}
