//! Emitters over the IR. First target: a reconstructed C++ class header.

use crate::model::{ClaimSubject, Database, Kind, Symbol, Type, TypeText};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

type ClassList = Vec<(String, String, usize)>;

struct HeaderContext<'a> {
    class_list: ClassList,
    class_set: BTreeSet<String>,
    members: BTreeMap<(String, String), Vec<&'a Symbol>>,
    nested_classes: BTreeMap<String, BTreeSet<String>>,
    class_records: BTreeMap<String, &'a serde_json::Value>,
    forward_declarations: String,
}

impl<'a> HeaderContext<'a> {
    fn new(db: &'a Database) -> Self {
        let class_list = classes(db);
        let mut class_set: BTreeSet<String> = class_list
            .iter()
            .map(|(namespace, class, _)| {
                if namespace.is_empty() || namespace == "global" {
                    class.clone()
                } else {
                    format!("{namespace}::{class}")
                }
            })
            .collect();
        let forward_types = collect_forward_types(db, &class_list);
        class_set.extend(namespace_class_collisions(&forward_types));
        let mut members: BTreeMap<(String, String), Vec<&Symbol>> = BTreeMap::new();
        for symbol in &db.symbols {
            if symbol.library || !symbol.sig.parse_ok {
                continue;
            }
            let Some(class) = symbol.sig.class.as_ref() else {
                continue;
            };
            members
                .entry((
                    symbol.sig.namespace.clone().unwrap_or_default(),
                    class.clone(),
                ))
                .or_default()
                .push(symbol);
        }
        for class_members in members.values_mut() {
            sort_class_members(class_members);
        }
        let mut nested_classes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for symbol in &db.symbols {
            let Some(namespace) = symbol.sig.namespace.as_deref() else {
                continue;
            };
            let Some(class) = symbol.sig.class.as_ref() else {
                continue;
            };
            if class_set.contains(namespace) && is_cpp_identifier(class) {
                nested_classes
                    .entry(namespace.to_string())
                    .or_default()
                    .insert(class.clone());
            }
        }
        let class_records = db
            .classes
            .iter()
            .filter_map(|record| {
                record
                    .get("qualified_name")
                    .and_then(serde_json::Value::as_str)
                    .map(|name| (name.to_string(), record))
            })
            .collect();
        let forward_declarations = build_forward_declarations_from(db, &class_list);
        Self {
            class_list,
            class_set,
            members,
            nested_classes,
            class_records,
            forward_declarations,
        }
    }
}

fn build_forward_declarations_from(db: &Database, all_classes: &ClassList) -> String {
    let ns_classes = collect_forward_types(db, all_classes);
    let mut out = forward_preamble();
    emit_generic_forwards(&ns_classes, &mut out);
    out
}

fn collect_forward_types(
    db: &Database,
    all_classes: &ClassList,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut ns_classes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let concrete_classes: BTreeSet<String> = all_classes
        .iter()
        .map(|(namespace, class, _)| {
            if namespace.is_empty() || namespace == "global" {
                class.clone()
            } else {
                format!("{namespace}::{class}")
            }
        })
        .collect();
    for (ns, class, _) in all_classes {
        let clean_ns = if ns == "global" {
            String::new()
        } else {
            ns.clone()
        };
        ns_classes
            .entry(clean_ns)
            .or_default()
            .insert(class.clone());
    }

    // Add every non-template named type referenced by a signature. Template
    // specializations are emitted as opaque placeholders by `clean_cpp_type`.
    for s in &db.symbols {
        if let Some(ret) = &s.sig.ret
            && !ret.text.contains("enum ")
        {
            collect_named_types(&ret.ast, &concrete_classes, &mut ns_classes);
            collect_bare_named_types(&ret.text, &concrete_classes, &mut ns_classes);
        }
        for p in &s.sig.params {
            if !p.text.contains("enum ") {
                collect_named_types(&p.ast, &concrete_classes, &mut ns_classes);
                collect_bare_named_types(&p.text, &concrete_classes, &mut ns_classes);
            }
        }
    }

    ns_classes
}

fn collect_bare_named_types(
    text: &str,
    concrete_classes: &BTreeSet<String>,
    types: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for token in text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || character == '_' || character == ':')
    }) {
        let parts: Vec<&str> = token.split("::").filter(|part| !part.is_empty()).collect();
        let Some((name, namespace)) = parts.split_last() else {
            continue;
        };
        if parts.iter().all(|part| is_cpp_identifier(part))
            && !is_builtin_type_name(name)
            && !(1..parts.len()).any(|end| concrete_classes.contains(&parts[..end].join("::")))
            && !matches!(
                *name,
                "class"
                    | "struct"
                    | "union"
                    | "enum"
                    | "const"
                    | "volatile"
                    | "virtual"
                    | "static"
                    | "public"
                    | "protected"
                    | "private"
                    | "__cdecl"
            )
        {
            types
                .entry(namespace.join("::"))
                .or_default()
                .insert((*name).to_string());
        }
    }
}

fn collect_named_types(
    ty: &Type,
    concrete_classes: &BTreeSet<String>,
    types: &mut BTreeMap<String, BTreeSet<String>>,
) {
    match ty {
        Type::Named { path, args }
            if args.is_empty() && path.iter().all(|part| is_cpp_identifier(part)) =>
        {
            if let Some((name, namespace)) = path.split_last()
                && !is_builtin_type_name(name)
                && !(1..path.len()).any(|end| concrete_classes.contains(&path[..end].join("::")))
            {
                types
                    .entry(namespace.join("::"))
                    .or_default()
                    .insert(name.clone());
            }
        }
        Type::Ptr { to } | Type::Ref { to } | Type::Const { of: to } => {
            collect_named_types(to, concrete_classes, types);
        }
        Type::FnPtr { ret, params, .. } => {
            collect_named_types(ret, concrete_classes, types);
            for parameter in params {
                collect_named_types(parameter, concrete_classes, types);
            }
        }
        Type::Builtin { .. } | Type::Named { .. } | Type::Raw { .. } => {}
    }
}

fn is_builtin_type_name(name: &str) -> bool {
    matches!(
        name,
        "void"
            | "bool"
            | "char"
            | "signed"
            | "unsigned"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "wchar_t"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "intptr_t"
            | "uintptr_t"
            | "size_t"
            | "ptrdiff_t"
            | "DWRITE_FONT_WEIGHT"
            | "DWRITE_FONT_STYLE"
            | "DWRITE_FONT_STRETCH"
            | "TouchKeyboardNotificationsDesired"
            | "XmlNodeType"
            | "StructureChangeType"
            | "TOUCHTOOLTIP_INPUT"
            | "TOUCHTOOLTIP_TYPE"
            | "TOUCHTOOLTIP_OPTION_FLAGS"
            | "TOUCHTOOLTIP_LAYOUT_DIRECTION"
            | "TOUCHTOOLTIP_PLACEMENT"
            | "TOUCHTOOLTIP_CREATE_FLAGS"
    )
}

fn forward_preamble() -> String {
    let mut out = String::new();
    out.push_str("#pragma once\n\n");
    out.push_str("#include <cstdint>\n\n");
    out.push_str("// Forward declarations (automatically generated)\n");
    out.push_str("class WindissectOpaque;\n");
    out
}

fn emit_generic_forwards(ns_classes: &BTreeMap<String, BTreeSet<String>>, out: &mut String) {
    let collision_owners = namespace_class_collisions(ns_classes);
    for owner in &collision_owners {
        let (namespace, name) = owner.rsplit_once("::").unwrap_or(("", owner));
        let parts: Vec<&str> = namespace
            .split("::")
            .filter(|part| !part.is_empty())
            .collect();
        for part in &parts {
            let _ = write!(out, "namespace {part} {{ ");
        }
        let _ = write!(out, "class {name}; ");
        for _ in &parts {
            out.push_str("} ");
        }
        out.push('\n');
    }
    let namespace_paths: BTreeSet<&str> = ns_classes
        .keys()
        .filter(|namespace| !namespace.is_empty())
        .flat_map(|namespace| {
            namespace
                .match_indices("::")
                .map(|(index, _)| &namespace[..index])
                .chain(std::iter::once(namespace.as_str()))
        })
        .collect();
    for (ns, names) in ns_classes {
        if let Some(first) = ns.split("::").next()
            && ns_classes
                .get("")
                .is_some_and(|global| global.contains(first))
        {
            continue;
        }
        if (1..=ns.split("::").count())
            .map(|end| ns.split("::").take(end).collect::<Vec<_>>().join("::"))
            .any(|prefix| collision_owners.contains(&prefix))
        {
            continue;
        }
        let parts: Vec<&str> = ns.split("::").filter(|p| !p.is_empty()).collect();
        for part in &parts {
            let _ = write!(out, "namespace {part} {{ ");
        }
        for name in names {
            let qualified = if ns.is_empty() {
                name.clone()
            } else {
                format!("{ns}::{name}")
            };
            if !name.contains(['<', ' ', '`'])
                && (!namespace_paths.contains(qualified.as_str())
                    || collision_owners.contains(&qualified))
            {
                let _ = write!(out, "class {name}; ");
            }
        }
        for _ in &parts {
            out.push_str("} ");
        }
        out.push('\n');
    }
    out.push('\n');
}

fn namespace_class_collisions(ns_classes: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<String> {
    let mut collisions: BTreeSet<String> = ns_classes
        .keys()
        .filter_map(|namespace| {
            let (parent, name) = namespace.rsplit_once("::").unwrap_or(("", namespace));
            ns_classes
                .get(parent)
                .is_some_and(|names| names.contains(name))
                .then(|| namespace.clone())
        })
        .collect();
    for namespace in ns_classes.keys() {
        let mut prefix = String::new();
        for part in namespace.split("::") {
            if !prefix.is_empty() {
                prefix.push_str("::");
            }
            prefix.push_str(part);
            if part.contains('_')
                && part
                    .chars()
                    .all(|character| character == '_' || !character.is_ascii_lowercase())
            {
                collisions.insert(prefix.clone());
                break;
            }
        }
    }
    let all_collisions = collisions.clone();
    collisions.retain(|candidate| {
        !candidate
            .match_indices("::")
            .any(|(index, _)| all_collisions.contains(&candidate[..index]))
    });
    collisions
}

/// Reconstruct a single C++ class declaration from the IR.
pub fn cpp_class(db: &Database, ns: &str, class: &str) -> String {
    let context = HeaderContext::new(db);
    cpp_class_from_context(db, &context, ns, class)
}

fn cpp_class_from_context(
    db: &Database,
    context: &HeaderContext<'_>,
    ns: &str,
    class: &str,
) -> String {
    render_cpp_class(db, context, ns, class, &context.forward_declarations)
}

fn render_cpp_class(
    db: &Database,
    context: &HeaderContext<'_>,
    ns: &str,
    class: &str,
    preamble: &str,
) -> String {
    let key = (ns.to_string(), class.to_string());
    let members = context.members.get(&key).map_or(&[][..], Vec::as_slice);
    let clean_ns = ns.to_string();
    let has_ns = !clean_ns.is_empty() && clean_ns != "global";
    let mut out = preamble.to_string();
    let _ = writeln!(
        out,
        "// Reconstructed from {} by Windissect. {} member(s).",
        db.binary.file,
        members.len()
    );
    emit_base_evidence(&context.class_records, &clean_ns, class, &mut out);
    if has_ns {
        let _ = writeln!(out, "namespace {clean_ns} {{");
    }
    let _ = writeln!(out, "class {class} {{");
    let qualified_class = if clean_ns.is_empty() || clean_ns == "global" {
        class.to_string()
    } else {
        format!("{clean_ns}::{class}")
    };
    if let Some(nested) = context.nested_classes.get(&qualified_class) {
        out.push_str("public:\n");
        for nested_class in nested {
            let _ = writeln!(out, "    class {nested_class};");
        }
    }
    emit_class_members(members, class, &context.class_set, &mut out);
    out.push_str("};\n");
    if has_ns {
        let _ = writeln!(out, "}} // namespace {clean_ns}");
    }
    out
}

fn access_rank(access: Option<&str>) -> usize {
    match access {
        Some("public") => 0,
        Some("protected") => 1,
        Some("private") => 2,
        _ => 3,
    }
}

fn sort_class_members(members: &mut [&Symbol]) {
    // Group by access (public, protected, private, then unspecified), method
    // name within, so the header reads like a real declaration.
    members.sort_by(|a, b| {
        access_rank(a.sig.access.as_deref())
            .cmp(&access_rank(b.sig.access.as_deref()))
            .then(a.sig.method.cmp(&b.sig.method))
    });
}

fn emit_base_evidence(
    class_records: &BTreeMap<String, &serde_json::Value>,
    clean_ns: &str,
    class: &str,
    out: &mut String,
) {
    let qualified_class = if clean_ns.is_empty() || clean_ns == "global" {
        class.to_string()
    } else {
        format!("{clean_ns}::{class}")
    };
    if let Some(record) = class_records.get(&qualified_class) {
        for base in record
            .get("bases")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = base
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let evidence = base
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let confidence = base
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let _ = writeln!(out, "// Base evidence: {name} ({confidence}; {evidence}).");
        }
    }
}

fn emit_class_members(
    members: &[&Symbol],
    class: &str,
    class_set: &BTreeSet<String>,
    out: &mut String,
) {
    let mut cur = 4usize; // force a label before the first member
    let mut has_dtor = false;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for m in members {
        let method = m.sig.method.as_deref().unwrap_or("?");
        if method.contains('`') || method.contains('<') || method.contains("operator") {
            continue; // closures, template methods, operator overloads
        }
        // Multiple-inheritance adjustor thunks demangle as "[thunk]:...", skip.
        if m.demangled
            .as_deref()
            .is_some_and(|d| d.starts_with("[thunk]"))
        {
            continue;
        }
        // Dedup overloads that collapse to one signature after cleaning (e.g.
        // params that both placeholder to void*, or differ only by return type),
        // which C++ rejects.
        let key = format!(
            "{method}|{}",
            m.sig
                .params
                .iter()
                .map(|p| { canonical_parameter_type(&clean_cpp_type(&p.text, class, class_set,)) })
                .collect::<Vec<_>>()
                .join(",")
        );
        if !seen.insert(key) {
            continue;
        }
        if method.contains("deleting destructor") || method.starts_with('~') {
            if has_dtor {
                continue; // Skip duplicate destructor declarations
            }
            has_dtor = true;
        }

        let acc = access_rank(m.sig.access.as_deref());
        if acc != cur {
            cur = acc;
            let label = ["public", "protected", "private", "public /*unspecified*/"][acc];
            let _ = writeln!(out, "{label}:");
        }
        out.push_str(&decl_line(m, class, class_set));
        out.push('\n');
    }
}

/// One member declaration line with relatable kind and exact raw mangled symbol in comments.
fn decl_line(s: &Symbol, class_name: &str, class_set: &BTreeSet<String>) -> String {
    let sig = &s.sig;
    let method = sig.method.as_deref().unwrap_or("?");
    let mangled = &s.mangled;
    let kind_str = format!("{:?}", s.kind);
    let prov_str = if s.exported {
        "PE Export"
    } else {
        "PDB Internal"
    };

    let mut doc_comment =
        format!("    // Category: {kind_str} | Source: {prov_str}\n    // Symbol: {mangled}\n    ");

    // Handle deleting destructors and normal destructors
    if method.contains("deleting destructor") || method.starts_with('~') {
        let storage = if sig.storage.as_deref() == Some("virtual") {
            "virtual "
        } else {
            ""
        };
        let _ = write!(doc_comment, "{storage}~{class_name}();");
        return doc_comment;
    }

    let mut line = String::new();
    match sig.storage.as_deref() {
        Some("virtual") => line.push_str("virtual "),
        Some("static") => line.push_str("static "),
        _ => {}
    }
    let params: Vec<String> = sig
        .params
        .iter()
        .map(|p| clean_cpp_type(&p.text, class_name, class_set))
        .collect();
    if !matches!(s.kind, Kind::Ctor | Kind::Dtor)
        && let Some(ret) = &sig.ret
        && matches!(ret.ast, Type::FnPtr { .. })
    {
        let cleaned = clean_cpp_type(&ret.text, class_name, class_set);
        let declarator = format!(
            "*{method}({}){}",
            params.join(", "),
            if sig.is_const { " const" } else { "" }
        );
        let rendered = cleaned.find("(*)").map_or_else(
            || {
                cleaned.find("( *)").map_or_else(
                    || format!("WindissectOpaque *{method}({})", params.join(", ")),
                    |index| {
                        format!(
                            "{}({declarator}){}",
                            &cleaned[..index],
                            &cleaned[index + 4..]
                        )
                    },
                )
            },
            |index| {
                format!(
                    "{}({declarator}){}",
                    &cleaned[..index],
                    &cleaned[index + 3..]
                )
            },
        );
        line.push_str(rendered.trim());
        line.push(';');
        doc_comment.push_str(&line);
        return doc_comment;
    }
    // ctors/dtors have no return type.
    if !matches!(s.kind, Kind::Ctor | Kind::Dtor)
        && let Some(ret) = &sig.ret
    {
        line.push_str(&clean_cpp_return_type(&ret.text, class_name, class_set));
        line.push(' ');
    }
    line.push_str(method);
    line.push('(');
    line.push_str(&params.join(", "));
    line.push(')');
    if sig.is_const {
        line.push_str(" const");
    }
    line.push(';');

    doc_comment.push_str(&line);
    doc_comment
}

/// A `class/struct/union/enum X` (or `X<...>`) reference in a type string.
struct TypeRef {
    start: usize,
    end: usize,
    kw: &'static str,
    qual: String,
    template: bool,
}

/// Every elaborated type reference in `text`, left to right.
fn scan_type_refs(text: &str) -> Vec<TypeRef> {
    let b = text.as_bytes();
    let mut refs = Vec::new();
    for kw in ["class", "struct", "union", "enum"] {
        let mut from = 0;
        while let Some(rel) = text[from..].find(kw) {
            let start = from + rel;
            from = start + kw.len();
            if start > 0 && (b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_') {
                continue;
            }
            let ak = start + kw.len();
            if ak >= text.len() || b[ak] != b' ' {
                continue;
            }
            let qs = ak + 1;
            let mut i = qs;
            while i < text.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b':') {
                i += 1;
            }
            if i == qs {
                continue;
            }
            let qual = text[qs..i].trim_end_matches(':').to_string();
            let mut j = i;
            while j < text.len() && b[j] == b' ' {
                j += 1;
            }
            let template = j < text.len() && b[j] == b'<';
            let mut end = if template { match_angle(text, j) } else { i };
            while text[end..].starts_with("::") {
                let name_start = end + 2;
                let name_len = text[name_start..]
                    .chars()
                    .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                    .map(char::len_utf8)
                    .sum::<usize>();
                if name_len == 0 {
                    break;
                }
                end = name_start + name_len;
            }
            refs.push(TypeRef {
                start,
                end,
                kw,
                qual,
                template,
            });
        }
    }
    refs.sort_by_key(|r| r.start);
    refs
}

/// Index just past the `>` closing the `<` at `open`.
fn match_angle(text: &str, open: usize) -> usize {
    let b = text.as_bytes();
    let mut depth = 0;
    for (i, byte) in b.iter().enumerate().skip(open) {
        match byte {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// True when a type is nested inside a class, so not forward-declarable.
fn is_nested(qual: &str, current_class: &str, class_set: &BTreeSet<String>) -> bool {
    let parts: Vec<&str> = qual.split("::").filter(|s| !s.is_empty()).collect();
    (1..parts.len())
        .any(|end| parts[end - 1] == current_class || class_set.contains(&parts[..end].join("::")))
}

fn clean_cpp_type(s: &str, current_class: &str, class_set: &BTreeSet<String>) -> String {
    let mut cleaned = s.replace("__cdecl", "");

    // General pass: placeholder types C++ cannot forward-declare.
    // enum -> int (ABI-safe); nested or templated class/struct/union -> void*.
    let mut spans: Vec<(usize, usize, &str)> = Vec::new();
    for r in scan_type_refs(&cleaned) {
        let repl = if r.kw == "enum" {
            "int"
        } else if r.template || is_nested(&r.qual, current_class, class_set) {
            // Replace the referred base type, not its declarator. A source
            // pointer such as `Nested *` must become `void *`, not `void **`.
            "WindissectOpaque"
        } else {
            continue;
        };
        spans.push((r.start, r.end, repl));
    }
    // Keep only outermost spans (a template ref contains inner refs), then splice
    // right to left so earlier byte indices stay valid.
    spans.sort_by_key(|s| s.0);
    let mut max_end = 0;
    let mut kept: Vec<(usize, usize, &str)> = Vec::new();
    for sp in spans {
        if sp.0 >= max_end {
            kept.push(sp);
        }
        max_end = max_end.max(sp.1);
    }
    for (start, end, repl) in kept.iter().rev() {
        cleaned.replace_range(*start..*end, repl);
    }
    while cleaned.contains("  ") {
        cleaned = cleaned.replace("  ", " ");
    }
    cleaned = cleaned.trim().to_string();
    cleaned = cleaned
        .replace("class ", "")
        .replace("struct ", "")
        .replace("union ", "");

    // Self-referential class type simplification inside class body
    if !current_class.is_empty() {
        let full_directui = format!("DirectUI::{current_class}");
        if cleaned.contains(&full_directui) {
            cleaned = cleaned.replace(&full_directui, current_class);
        }
    }

    qualify_cpp_paths(apply_compat_type_rewrites(cleaned))
}

fn qualify_cpp_paths(mut value: String) -> String {
    let bytes = value.as_bytes();
    let mut insertions = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
            && (index == 0 || bytes[index - 1] != b':')
        {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b':')
            {
                index += 1;
            }
            if value[start..index].contains("::") {
                insertions.push(start);
            }
        } else {
            index += 1;
        }
    }
    for insertion in insertions.into_iter().rev() {
        value.insert_str(insertion, "::");
    }
    value
}

fn canonical_parameter_type(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" *", "*")
        .replace("* ", "*")
        .replace(" &", "&")
        .replace("& ", "&")
}

fn clean_cpp_return_type(value: &str, class: &str, class_set: &BTreeSet<String>) -> String {
    let mut cleaned = clean_cpp_type(value, class, class_set);
    if let Some(without_volatile) = cleaned.strip_suffix(" volatile") {
        cleaned = without_volatile.to_string();
    }
    if !cleaned.contains(['*', '&']) {
        cleaned = cleaned
            .strip_prefix("const ")
            .or_else(|| cleaned.strip_suffix(" const"))
            .unwrap_or(&cleaned)
            .to_string();
    }
    cleaned
}

fn apply_compat_type_rewrites(mut cleaned: String) -> String {
    if cleaned.contains("STACK_SYMBOL_INFO") {
        cleaned = cleaned.replace("CallstackTracker::STACK_SYMBOL_INFO", "void*");
    }
    if cleaned.contains("SWF::Bits") {
        cleaned = cleaned
            .replace("class SWF::Bits", "void*")
            .replace("SWF::Bits", "void*");
    }
    if cleaned.contains("LineSegment") {
        cleaned = cleaned
            .replace("struct SWF::Shape::LineSegment", "void*")
            .replace("Shape::LineSegment", "void*");
    }
    if cleaned.contains("SWF::Types::BrushType") {
        cleaned = cleaned.replace("enum SWF::Types::BrushType", "int");
    }
    if cleaned.contains("TILING_DATA") {
        cleaned = cleaned
            .replace("ContentTiler::TILING_DATA", "void*")
            .replace("DirectUI::ContentTiler::TILING_DATA", "void*");
    }
    if cleaned.contains("CCacheThread::Invoke") {
        cleaned = cleaned
            .replace(
                "class DirectUI::StyleSheetCache::CCacheThread::Invoke",
                "void",
            )
            .replace("CCacheThread::Invoke", "void");
    }
    if cleaned.contains("::AccessibleButton::ACCESSIBLEROLE") {
        cleaned = cleaned.replace(
            "struct DirectUI::AccessibleButton::ACCESSIBLEROLE",
            "uintptr_t",
        );
    }
    if cleaned.contains("::TouchTooltipTimings::TIMINGS") {
        cleaned = cleaned.replace("struct DirectUI::TouchTooltipTimings::TIMINGS", "uintptr_t");
    }
    if cleaned.contains("::Internal::ListenerData") {
        cleaned = cleaned.replace("struct DirectUI::Internal::ListenerData", "uintptr_t");
    }
    if cleaned.contains("::SmoothDot::DRAW_PARAMS") {
        cleaned = cleaned.replace("struct DirectUI::SmoothDot::DRAW_PARAMS", "uintptr_t");
    }
    if cleaned.contains("::CActivityOverlay::FUNCMODE") {
        cleaned = cleaned.replace("enum DirectUI::CActivityOverlay::FUNCMODE", "int");
    }
    if cleaned.contains("SWF::Tag::TagID") {
        cleaned = cleaned.replace("enum SWF::Tag::TagID", "int");
    }
    if cleaned.contains("::GraphicsPath") {
        cleaned = cleaned.replace("class Gdiplus::GraphicsPath", "void");
    }
    if cleaned.contains("::SmoothingMode") {
        cleaned = cleaned.replace("enum Gdiplus::SmoothingMode", "int");
    }
    if cleaned.contains("::DUIXmlParser::ParsedArg") {
        cleaned = cleaned.replace("union DirectUI::DUIXmlParser::ParsedArg", "void*");
    }
    if cleaned.contains("CheckedStateFlags") {
        cleaned = cleaned
            .replace("enum DirectUI::CheckedStateFlags", "int")
            .replace("enum CheckedStateFlags", "int");
    }
    if cleaned.contains("::_DUI_PARSE_STATE") {
        cleaned = cleaned.replace("enum DirectUI::_DUI_PARSE_STATE", "int");
    }
    if cleaned.contains("Schema::Event") {
        cleaned = cleaned
            .replace("enum DirectUI::Schema::Event", "int")
            .replace("Schema::Event", "int");
    }
    if cleaned.contains("::Impl::ParserCacheEntry") {
        cleaned = cleaned.replace("struct DirectUI::Impl::ParserCacheEntry", "void*");
    }
    if cleaned.contains("InvokeHelper::InvokeArgs") {
        cleaned = cleaned.replace("InvokeHelper::InvokeArgs", "void");
    }
    if cleaned.contains("class SWF::Tag") {
        cleaned = cleaned.replace("class SWF::Tag", "void*");
    }
    if cleaned.contains("SWF::SWF") {
        cleaned = cleaned
            .replace("class SWF::SWF", "class SWF")
            .replace("SWF::SWF", "SWF");
    }
    if cleaned.contains("class SWF::Movie") || cleaned.contains("SWF::Movie") {
        cleaned = cleaned
            .replace("class SWF::Movie", "void*")
            .replace("SWF::Movie", "void*");
    }
    if cleaned.contains("class SWF::Fluster") || cleaned.contains("SWF::Fluster") {
        cleaned = cleaned
            .replace("class SWF::Fluster", "void*")
            .replace("SWF::Fluster", "void*");
    }
    cleaned
}

/// List the (namespace, class) pairs present, with member counts.
pub fn classes(db: &Database) -> Vec<(String, String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for s in &db.symbols {
        if s.library || !s.sig.parse_ok {
            continue;
        }
        if let Some(class) = &s.sig.class {
            // Names that are namespaces (or namespace/class collisions) cannot
            // be emitted as standalone classes without a redeclaration clash.
            const NS_NAMES: &[&str] = &[
                "DirectUI",
                "SWF",
                "Library",
                "Windows",
                "Microsoft",
                "Gdiplus",
                "D2D1",
                "Immersive",
                "UI",
                "WRL",
                "Wrappers",
                "Tag",
                "BinaryFile",
                "Impl",
                "Internal",
                "ParserTools",
                "StyleSheetCache",
                "type_info",
                "exception",
            ];
            if class.contains('<')
                || !is_cpp_identifier(class)
                || is_builtin_type_name(class)
                || NS_NAMES.contains(&class.as_str())
            {
                continue;
            }
            let ns = s.sig.namespace.clone().unwrap_or_default();
            if !valid_cpp_namespace(&ns) {
                continue;
            }
            *counts.entry((ns, class.clone())).or_default() += 1;
        }
    }
    let mut v: Vec<_> = counts
        .into_iter()
        .map(|((namespace, class), count)| (namespace, class, count))
        .collect();
    v.sort_by_key(|item| std::cmp::Reverse(item.2));
    v
}

fn valid_cpp_namespace(namespace: &str) -> bool {
    namespace.is_empty() || namespace == "global" || namespace.split("::").all(is_cpp_identifier)
}

fn is_cpp_identifier(value: &str) -> bool {
    if matches!(
        value,
        "alignas"
            | "alignof"
            | "and"
            | "asm"
            | "auto"
            | "bitand"
            | "bitor"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "compl"
            | "concept"
            | "const"
            | "consteval"
            | "constexpr"
            | "constinit"
            | "const_cast"
            | "continue"
            | "co_await"
            | "co_return"
            | "co_yield"
            | "decltype"
            | "default"
            | "delete"
            | "do"
            | "dynamic_cast"
            | "else"
            | "enum"
            | "explicit"
            | "export"
            | "extern"
            | "false"
            | "for"
            | "friend"
            | "goto"
            | "if"
            | "inline"
            | "mutable"
            | "namespace"
            | "new"
            | "noexcept"
            | "not"
            | "nullptr"
            | "operator"
            | "or"
            | "private"
            | "protected"
            | "public"
            | "register"
            | "reinterpret_cast"
            | "requires"
            | "return"
            | "sizeof"
            | "static"
            | "static_assert"
            | "static_cast"
            | "struct"
            | "switch"
            | "template"
            | "this"
            | "thread_local"
            | "throw"
            | "true"
            | "try"
            | "typedef"
            | "typeid"
            | "typename"
            | "union"
            | "using"
            | "virtual"
            | "volatile"
            | "while"
            | "xor"
    ) {
        return false;
    }
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

pub fn sanitize_filename(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean_str = clean.trim_matches('_');
    let mut filename = if clean_str.is_empty() {
        "AnonClass".to_string()
    } else {
        clean_str.to_string()
    };
    if filename.len() > 96 {
        let hash = stable_filename_hash(&filename);
        filename.truncate(79);
        filename.push('_');
        let _ = write!(filename, "{hash:016x}");
    }
    if is_windows_device_name(&filename) {
        filename.insert(0, '_');
    }
    filename
}

fn stable_filename_hash(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn is_windows_device_name(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub fn category_dir(class: &str) -> &'static str {
    if class.contains("Layout") {
        "layouts"
    } else if class.contains("Provider")
        || class.contains("Accessible")
        || class.contains("Proxy")
        || class.contains("Uia")
    {
        "accessibility"
    } else if class.contains("Parser")
        || class.contains("Xml")
        || class.contains("Sheet")
        || class.contains("ByteCode")
    {
        "parsing"
    } else if class.contains("Animation") || class.contains("PVL") {
        "animation"
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
        "controls"
    } else if class.contains("Behavior") {
        "behaviors"
    } else if class.contains("Value")
        || class.contains("Font")
        || class.contains("Color")
        || class.contains("Expression")
        || class.contains("UID")
    {
        "values"
    } else if class.contains("Element") || class.contains("HWND") || class.contains("ClassInfo") {
        "core"
    } else if class.contains("Macro")
        || class.contains("Page")
        || class.contains("Repeater")
        || class.contains("Viewer")
        || class.contains("Dialog")
        || class.contains("Expand")
        || class.contains("XBaby")
    {
        "containers"
    } else {
        "utilities"
    }
}

/// Emit all C++ class headers into `headers/<category>/` subdirectories.
pub fn emit_all_headers(db: &Database, out_dir: &std::path::Path) -> anyhow::Result<usize> {
    validate_output_directory(out_dir)?;
    prepare_output_directory(out_dir)?;
    let (count, verified_includes, candidate_includes) = emit_class_header_files(db, out_dir)?;
    emit_master_header(db, out_dir, &verified_includes)?;
    emit_candidate_master_header(db, out_dir, &verified_includes, &candidate_includes)?;
    emit_flat_c_header(db, out_dir)?;
    Ok(count)
}

fn validate_output_directory(out_dir: &std::path::Path) -> anyhow::Result<()> {
    use std::fs;
    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    let resolved_out = if out_dir.exists() {
        fs::canonicalize(out_dir)?
    } else {
        let name = out_dir
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("output directory must have a final component"))?;
        let parent = out_dir
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        fs::canonicalize(parent)?.join(name)
    };
    anyhow::ensure!(
        resolved_out != cwd,
        "refusing to replace the current directory"
    );
    anyhow::ensure!(
        resolved_out.parent().is_some(),
        "refusing to replace a filesystem root"
    );
    Ok(())
}

fn prepare_output_directory(out_dir: &std::path::Path) -> anyhow::Result<()> {
    use std::fs;
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir)?;

    for category in [
        "core",
        "controls",
        "layouts",
        "parsing",
        "animation",
        "accessibility",
        "containers",
        "values",
        "behaviors",
        "utilities",
    ] {
        fs::create_dir_all(out_dir.join(category))?;
    }
    Ok(())
}

fn emit_class_header_files(
    db: &Database,
    out_dir: &std::path::Path,
) -> anyhow::Result<(usize, Vec<String>, Vec<String>)> {
    use std::fs;
    let context = HeaderContext::new(db);
    let mut count = 0;
    let mut includes_list = Vec::new();
    let mut candidate_includes = Vec::new();

    fs::write(out_dir.join("windissect_abi.h"), abi_metadata_header(db))?;
    includes_list.push("windissect_abi.h".to_string());
    fs::write(
        out_dir.join("windissect_forwards.h"),
        &context.forward_declarations,
    )?;
    includes_list.push("windissect_forwards.h".to_string());
    fs::write(out_dir.join("windissect_vcalls.h"), vcall_header(db))?;
    includes_list.push("windissect_vcalls.h".to_string());
    fs::write(out_dir.join("windissect_calls.h"), direct_call_header(db))?;
    includes_list.push("windissect_calls.h".to_string());

    // Check for duplicate class names across namespaces
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, class, _) in &context.class_list {
        let clean = sanitize_filename(class).to_ascii_lowercase();
        *name_counts.entry(clean).or_default() += 1;
    }

    for (ns, class, _) in &context.class_list {
        let cat = category_dir(class);
        let clean = sanitize_filename(class);
        let file_name = if name_counts
            .get(&clean.to_ascii_lowercase())
            .copied()
            .unwrap_or(0)
            <= 1
        {
            format!("{clean}.h")
        } else {
            let hash = stable_filename_hash(&format!("{ns}::{class}"));
            format!("{clean}_{hash:016x}.h")
        };
        let code = render_cpp_class(
            db,
            &context,
            ns,
            class,
            "#pragma once\n#include \"../windissect_forwards.h\"\n\n",
        );
        let rel_path = format!("{cat}/{file_name}");
        fs::write(out_dir.join(&rel_path), code)?;
        candidate_includes.push(rel_path);
        count += 1;
    }

    Ok((count, includes_list, candidate_includes))
}

fn target_filename(db: &Database) -> String {
    let target = std::path::Path::new(&db.binary.file)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(&db.binary.file);
    sanitize_filename(target)
}

fn emit_master_header(
    db: &Database,
    out_dir: &std::path::Path,
    includes: &[String],
) -> anyhow::Result<()> {
    use std::fs;
    let target_file = target_filename(db);
    let mut master_hdr = String::new();
    let _ = write!(
        master_hdr,
        "// Windissect verified C++ surface for {}.\n// Candidate class declarations are isolated in the _candidates header.\n// Validated dialects: C++17, C++20, C++23, and C++26 draft.\n#pragma once\n\n#if defined(_MSVC_LANG)\n#  define WINDISSECT_CPLUSPLUS _MSVC_LANG\n#else\n#  define WINDISSECT_CPLUSPLUS __cplusplus\n#endif\n#if WINDISSECT_CPLUSPLUS < 201703L\n#  error \"Windissect C++ output requires C++17 or newer\"\n#endif\n\n",
        db.binary.file
    );
    for inc in includes {
        let _ = writeln!(master_hdr, "#include \"{inc}\"");
    }
    fs::write(out_dir.join(format!("{target_file}.h")), master_hdr)?;
    Ok(())
}

fn emit_candidate_master_header(
    db: &Database,
    out_dir: &std::path::Path,
    verified_includes: &[String],
    candidate_includes: &[String],
) -> anyhow::Result<()> {
    use std::fs;
    let target_file = target_filename(db);
    let mut header = format!(
        "// Windissect exhaustive candidate class surface for {}.\n// Experimental: declarations may contain unresolved PDB language ambiguities.\n#pragma once\n\n",
        db.binary.file
    );
    for include in verified_includes.iter().chain(candidate_includes) {
        let _ = writeln!(header, "#include \"{include}\"");
    }
    fs::write(out_dir.join(format!("{target_file}_candidates.h")), header)?;
    Ok(())
}

fn emit_flat_c_header(db: &Database, out_dir: &std::path::Path) -> anyhow::Result<()> {
    use std::fs;
    let target_file = target_filename(db);
    let mut c_hdr = String::new();
    let guard = format!("{}_C_H", target_file.to_ascii_uppercase());
    let _ = write!(
        c_hdr,
        "// Flat C exports observed in {}. Unknown ABIs are intentionally not declared.\n// Validated dialects: ISO C17/C23/C26 draft and Windissect C20 (C ABI under C++20).\n#pragma once\n#ifndef {guard}\n#define {guard}\n#if defined(__cplusplus)\n#  if __cplusplus < 202002L\n#    define WINDISSECT_C20_PROFILE 0\n#  else\n#    define WINDISSECT_C20_PROFILE 1\n#  endif\nextern \"C\" {{\n#else\n#  if defined(__STDC_VERSION__) && __STDC_VERSION__ < 201710L\n#    error \"Windissect C output requires C17 or newer\"\n#  endif\n#  define WINDISSECT_C20_PROFILE 0\n#  define WINDISSECT_C_STANDARD __STDC_VERSION__\n#endif\n\n",
        db.binary.file
    );
    for s in &db.symbols {
        if s.library || !s.exported || s.mangled.starts_with('?') {
            continue;
        }
        let _ = writeln!(c_hdr, "// Export: {} (ABI unverified)", s.mangled);
    }
    let _ = write!(
        c_hdr,
        "\n#ifdef __cplusplus\n}} // extern \"C\"\n#endif\n#endif // {guard}\n"
    );
    fs::write(out_dir.join(format!("{target_file}_c.h")), c_hdr)?;
    Ok(())
}

/// Emit machine-consumable ABI evidence without pretending incomplete RTTI is
/// a compilable class definition. Exact PDB field offsets and tentative
/// PE-vftable bounds remain explicitly labelled by their evidence strings.
fn abi_metadata_header(db: &Database) -> String {
    let mut out = String::from(
        "// Windissect recovered ABI metadata. DO NOT EDIT.\n// Portable across C++17, C++20, C++23, and C++26 draft modes.\n#pragma once\n#include <cstddef>\n#include <cstdint>\n\nnamespace windissect_abi {\nstruct TypeLayout { const char* name; std::uint64_t size; const char* kind; };\nstruct FieldLayout { const char* owner; const char* name; std::uint32_t type_index; std::uint64_t offset; bool is_static; };\nstruct FieldObservation { const char* owner; const char* suggested_name; std::uint64_t offset; std::uint32_t width; const char* access; std::uint32_t evidence_rva; const char* evidence_symbol; const char* confidence; };\nstruct BaseLayout { const char* derived; const char* base; std::int64_t offset; bool is_virtual; const char* evidence; const char* confidence; };\nstruct VTableLayout { const char* name; std::uint32_t rva; std::uint32_t slots; const char* evidence; const char* confidence; };\nstruct VTableSlotLayout { std::uint32_t table_rva; std::uint32_t slot; std::uint32_t target_rva; const char* target_id; const char* target_name; bool ambiguous; std::int32_t this_adjustment; };\n\n",
    );
    emit_abi_types(db, &mut out);
    emit_abi_fields(db, &mut out);
    emit_abi_observations(db, &mut out);
    emit_abi_bases(db, &mut out);
    emit_abi_vtables(db, &mut out);
    emit_abi_vtable_slots(db, &mut out);
    out.push_str("    {0, 0, 0, nullptr, nullptr, true, 0},\n};\ninline constexpr std::size_t vtable_slot_count = (sizeof(vtable_slots) / sizeof(vtable_slots[0])) - 1;\n}\n");
    out
}

fn emit_abi_types(db: &Database, out: &mut String) {
    out.push_str("inline constexpr TypeLayout types[] = {\n");
    for ty in &db.types {
        let name = cpp_string(
            ty.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        let kind = cpp_string(
            ty.get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
        );
        let size = ty
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let _ = writeln!(out, "    {{\"{name}\", {size}ULL, \"{kind}\"}},");
    }
    out.push_str("    {nullptr, 0, nullptr},\n};\ninline constexpr std::size_t type_count = (sizeof(types) / sizeof(types[0])) - 1;\n");
}

fn emit_abi_fields(db: &Database, out: &mut String) {
    out.push_str("inline constexpr FieldLayout fields[] = {\n");
    for ty in &db.types {
        let owner = cpp_string(
            ty.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        for field in ty
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = cpp_string(
                field
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            );
            let type_index = field
                .get("type_index")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let offset = field
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let is_static = field
                .get("is_static")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let _ = writeln!(
                out,
                "    {{\"{owner}\", \"{name}\", {type_index}U, {offset}ULL, {is_static}}},"
            );
        }
    }
    out.push_str("    {nullptr, nullptr, 0, 0, false},\n};\ninline constexpr std::size_t field_count = (sizeof(fields) / sizeof(fields[0])) - 1;\n");
}

fn emit_abi_observations(db: &Database, out: &mut String) {
    out.push_str("inline constexpr FieldObservation field_observations[] = {\n");
    for ty in &db.types {
        let owner = cpp_string(
            ty.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        for observation in ty
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let suggested_name = observation
                .get("suggested_name")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || "nullptr".to_string(),
                    |s| format!("\"{}\"", cpp_string(s)),
                );
            let offset = observation
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let width = observation
                .get("width")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let access = cpp_string(
                observation
                    .get("access")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
            );
            let evidence_rva = observation
                .get("evidence_rva")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let evidence_symbol = cpp_string(
                observation
                    .get("evidence_symbol")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            );
            let confidence = cpp_string(
                observation
                    .get("confidence")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("tentative"),
            );
            let _ = writeln!(
                out,
                "    {{\"{owner}\", {suggested_name}, {offset}ULL, {width}U, \"{access}\", 0x{evidence_rva:X}U, \"{evidence_symbol}\", \"{confidence}\"}},"
            );
        }
    }
    out.push_str("    {nullptr, nullptr, 0, 0, nullptr, 0, nullptr, nullptr},\n};\ninline constexpr std::size_t field_observation_count = (sizeof(field_observations) / sizeof(field_observations[0])) - 1;\n");
}

fn emit_abi_bases(db: &Database, out: &mut String) {
    out.push_str("inline constexpr BaseLayout bases[] = {\n");
    let mut seen_bases = BTreeSet::new();
    for owner in db.types.iter().chain(db.classes.iter()) {
        let derived = owner
            .get("qualified_name")
            .or_else(|| owner.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        for base in owner
            .get("bases")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = base
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let evidence = base
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("pdb-tpi");
            let confidence = base
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("certain");
            let offset = base
                .get("offset")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let is_virtual = base
                .get("is_virtual")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if seen_bases.insert((derived.to_string(), name.to_string())) {
                let _ = writeln!(
                    out,
                    "    {{\"{}\", \"{}\", {offset}LL, {is_virtual}, \"{}\", \"{}\"}},",
                    cpp_string(derived),
                    cpp_string(name),
                    cpp_string(evidence),
                    cpp_string(confidence)
                );
            }
        }
    }
    out.push_str("    {nullptr, nullptr, -1, false, nullptr, nullptr},\n};\ninline constexpr std::size_t base_count = (sizeof(bases) / sizeof(bases[0])) - 1;\n");
}

fn emit_abi_vtables(db: &Database, out: &mut String) {
    out.push_str("inline constexpr VTableLayout vtables[] = {\n");
    for vtable in &db.vtables {
        let name = cpp_string(
            vtable
                .get("demangled")
                .or_else(|| vtable.get("class_name"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        let rva = vtable
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let slots = vtable
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        let evidence = cpp_string(
            vtable
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
        );
        let confidence = cpp_string(
            vtable
                .get("confidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("pdb-derived"),
        );
        let _ = writeln!(
            out,
            "    {{\"{name}\", 0x{rva:X}U, {slots}U, \"{evidence}\", \"{confidence}\"}},"
        );
    }
    out.push_str("    {nullptr, 0, 0, nullptr, nullptr},\n};\ninline constexpr std::size_t vtable_count = (sizeof(vtables) / sizeof(vtables[0])) - 1;\n");
}

fn emit_abi_vtable_slots(db: &Database, out: &mut String) {
    out.push_str("inline constexpr VTableSlotLayout vtable_slots[] = {\n");
    for vtable in &db.vtables {
        let table_rva = vtable
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        for entry in vtable
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let slot = entry
                .get("slot")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let target_rva = entry
                .get("target_rva")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let id = entry
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || "nullptr".to_string(),
                    |s| format!("\"{}\"", cpp_string(s)),
                );
            let name = entry
                .get("target_name")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || "nullptr".to_string(),
                    |s| format!("\"{}\"", cpp_string(s)),
                );
            let ambiguous = entry
                .get("target_ambiguous")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let adjustment = entry
                .get("this_adjustment")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let _ = writeln!(
                out,
                "    {{0x{table_rva:X}U, {slot}U, 0x{target_rva:X}U, {id}, {name}, {ambiguous}, {adjustment}}},"
            );
        }
    }
}

fn cpp_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn vcall_header(db: &Database) -> String {
    let mut out = String::from(
        "// Windissect signature-verified virtual-slot helpers. DO NOT EDIT.\n\
         #pragma once\n#include <cstdint>\n\n\
         #if defined(_M_IX86) || defined(__i386__)\n\
         #error \"Windissect typed vcalls currently require the Windows x64 ABI\"\n\
         #endif\n\nnamespace windissect_vcalls {\n",
    );
    let symbols: BTreeMap<&str, &Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let verified_callable = db.verified_callable_symbol_ids();
    let proven_claims = db.proven_claim_ids();
    let verified_slots: BTreeSet<VerifiedVtableSlot<'_>> = db
        .claims
        .iter()
        .filter(|claim| proven_claims.contains(claim.id.as_str()))
        .filter_map(|claim| match &claim.subject {
            ClaimSubject::VtableSlot {
                owner,
                table_rva,
                table_object_offset,
                slot,
                target_rva,
            } => Some((
                owner.as_str(),
                *table_rva,
                *table_object_offset,
                *slot,
                *target_rva,
            )),
            _ => None,
        })
        .collect();
    let mut used = BTreeSet::new();
    for table in &db.vtables {
        emit_vtable_helpers(
            table,
            &symbols,
            &verified_callable,
            &verified_slots,
            &mut used,
            &mut out,
        );
    }
    out.push_str("\n} // namespace windissect_vcalls\n");
    out
}

fn emit_vtable_helpers(
    table: &serde_json::Value,
    symbols: &BTreeMap<&str, &Symbol>,
    verified_callable: &BTreeSet<&str>,
    verified_slots: &BTreeSet<VerifiedVtableSlot<'_>>,
    used: &mut BTreeSet<String>,
    out: &mut String,
) {
    let table_rva = table
        .get("rva")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let claim_owner = table
        .get("demangled")
        .and_then(serde_json::Value::as_str)
        .and_then(vftable_owner)
        .or_else(|| table.get("class_name").and_then(serde_json::Value::as_str))
        .unwrap_or("unknown");
    let owner = sanitize_filename(claim_owner);
    let context = CppVcallContext {
        symbols,
        verified_callable,
        verified_slots,
        table_rva,
        claim_owner,
        owner: &owner,
    };
    for entry in table
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        emit_one_vcall(entry, &context, used, out);
    }
}

fn emit_one_vcall(
    entry: &serde_json::Value,
    context: &CppVcallContext<'_>,
    used: &mut BTreeSet<String>,
    out: &mut String,
) {
    let symbols = context.symbols;
    let table_rva = context.table_rva;
    let claim_owner = context.claim_owner;
    let owner = context.owner;
    let ambiguous = entry
        .get("target_ambiguous")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let compatible = entry
        .get("signature_compatible")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if ambiguous && !compatible {
        return;
    }
    let Some(id) = entry
        .get("target_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            entry
                .get("signature_source_id")
                .and_then(serde_json::Value::as_str)
        })
    else {
        return;
    };
    let Some(symbol) = symbols.get(id).copied().filter(|s| s.sig.parse_ok) else {
        return;
    };
    let Some(ret) = cpp_abi_type(symbol.sig.ret.as_ref()) else {
        return;
    };
    let Some(params) = symbol
        .sig
        .params
        .iter()
        .map(|ty| cpp_abi_type(Some(ty)))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let slot = entry
        .get("slot")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let target_rva = entry
        .get("target_rva")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    if !context
        .verified_slots
        .contains(&(claim_owner, table_rva, None, slot, target_rva))
        || !context.verified_callable.contains(symbol.id.as_str())
    {
        return;
    }
    let method = if ambiguous {
        "abi_equivalent".to_string()
    } else {
        sanitize_filename(symbol.sig.method.as_deref().unwrap_or("virtual"))
    };
    let function = unique_cpp_name(used, &format!("{owner}_vslot_{slot}_{method}"));
    let this_ty = if symbol.sig.is_const {
        "const void*"
    } else {
        "void*"
    };
    let declarations = params
        .iter()
        .enumerate()
        .map(|(index, ty)| format!("{ty} p{index}"))
        .collect::<Vec<_>>();
    let arguments = (0..params.len())
        .map(|index| format!("p{index}"))
        .collect::<Vec<_>>();
    let fn_types = std::iter::once(this_ty.to_string())
        .chain(params.iter().cloned())
        .collect::<Vec<_>>()
        .join(", ");
    let fn_args = std::iter::once("self".to_string())
        .chain(arguments)
        .collect::<Vec<_>>()
        .join(", ");
    let declaration_tail = if declarations.is_empty() {
        String::new()
    } else {
        format!(", {}", declarations.join(", "))
    };
    let nodiscard = if ret == "void" { "" } else { "[[nodiscard]] " };
    let _ = write!(
        out,
        "\n// Slot {slot}; identity_ambiguous={ambiguous}; ABI-equivalent={compatible}.\n{nodiscard}inline {ret} {function}({this_ty} self{declaration_tail}) {{\n    using Fn = {ret} (*)({fn_types});\n    auto table = *reinterpret_cast<const void* const* const*>(self);\n    auto function_ptr = reinterpret_cast<Fn>(const_cast<void*>(table[{slot}]));\n"
    );
    if ret == "void" {
        let _ = write!(out, "    function_ptr({fn_args});\n}}\n");
    } else {
        let _ = write!(out, "    return function_ptr({fn_args});\n}}\n");
    }
}

fn unique_cpp_name(used: &mut BTreeSet<String>, base: &str) -> String {
    let mut name = base.to_string();
    let mut suffix = 2;
    while !used.insert(name.clone()) {
        name = format!("{base}_{suffix}");
        suffix += 1;
    }
    name
}

type VerifiedVtableSlot<'a> = (&'a str, u32, Option<i64>, u32, u32);

struct CppVcallContext<'a> {
    symbols: &'a BTreeMap<&'a str, &'a Symbol>,
    verified_callable: &'a BTreeSet<&'a str>,
    verified_slots: &'a BTreeSet<VerifiedVtableSlot<'a>>,
    table_rva: u32,
    claim_owner: &'a str,
    owner: &'a str,
}

fn vftable_owner(name: &str) -> Option<&str> {
    crate::rtti::vftable_owner_name(name)
}

fn cpp_abi_type(ty: Option<&TypeText>) -> Option<String> {
    let Some(ty) = ty else {
        return Some("void".to_string());
    };
    let text = ty.text.trim();
    if text.contains('*') || text.contains('&') {
        return Some(if text.contains("const") {
            "const void*".to_string()
        } else {
            "void*".to_string()
        });
    }
    Some(
        match text {
            "void" => "void",
            "bool" => "bool",
            "char" | "signed char" => "std::int8_t",
            "unsigned char" => "std::uint8_t",
            "short" | "__int16" => "std::int16_t",
            "unsigned short" | "wchar_t" | "__wchar_t" => "std::uint16_t",
            "int" | "long" | "__int32" | "signed long" | "signed int" => "std::int32_t",
            "unsigned" | "unsigned int" | "unsigned long" => "std::uint32_t",
            "__int64" | "long long" | "signed long long" => "std::int64_t",
            "unsigned __int64" | "unsigned long long" => "std::uint64_t",
            "float" => "float",
            "double" => "double",
            _ => return None,
        }
        .to_string(),
    )
}

fn direct_call_header(db: &Database) -> String {
    let mut out = direct_call_preamble(db);
    let mut used = BTreeSet::new();
    let verified_callable = db.verified_callable_symbol_ids();
    for symbol in &db.symbols {
        emit_direct_call(symbol, &verified_callable, &mut used, &mut out);
    }
    out.push_str("\n} // namespace windissect_calls\n");
    out
}

fn direct_call_preamble(db: &Database) -> String {
    let dll_wide = db
        .binary
        .file
        .encode_utf16()
        .chain(std::iter::once(0))
        .map(|value| format!("0x{value:04X}"))
        .collect::<Vec<_>>()
        .join(", ");
    let dll_wide_len = db.binary.file.encode_utf16().count() + 1;
    let timestamp = db
        .binary
        .timestamp
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let mut out = String::from(
        "// Windissect exact-build RVA call helpers. DO NOT EDIT.\n\
         // Configure set_resolver() with a loader that validates the expected build.\n\
         #pragma once\n#include <cstddef>\n#include <cstdint>\n#include <cstdlib>\n\n\
         #if defined(_M_IX86) || defined(__i386__)\n\
         #error \"Windissect typed direct calls currently require the Windows x64 ABI\"\n\
         #endif\n\nnamespace windissect_calls {\n\
         using ResolveRva = const void* (*)(std::uint32_t);\n\
         __DEFAULT_RESOLVER__\n\
         inline void set_resolver(ResolveRva value) noexcept { resolver = value; }\n\
         [[nodiscard]] inline const void* require(std::uint32_t rva) {\n\
             if (resolver == nullptr) std::abort();\n\
             const void* address = resolver(rva);\n\
             if (address == nullptr) std::abort();\n\
             return address;\n\
         }\n",
    );
    let windows_resolver = format!(
        "#if defined(_WIN32)\n\
         extern \"C\" __declspec(dllimport) void* __stdcall GetModuleHandleW(const wchar_t*);\n\
         [[nodiscard]] inline const void* default_resolver(std::uint32_t rva) {{\n\
             static constexpr wchar_t module_name[{dll_wide_len}] = {{{dll_wide}}};\n\
             const auto base = static_cast<const std::uint8_t*>(GetModuleHandleW(module_name));\n\
             if (base == nullptr) return nullptr;\n\
             const auto pe = *reinterpret_cast<const std::uint32_t*>(base + 0x3c);\n\
             const auto live_timestamp = *reinterpret_cast<const std::uint32_t*>(base + pe + 8);\n\
             const auto image_size = *reinterpret_cast<const std::uint32_t*>(base + pe + 80);\n\
             if (live_timestamp != {timestamp}U || rva >= image_size) return nullptr;\n\
             return base + rva;\n\
         }}\n\
         inline ResolveRva resolver = default_resolver;\n\
         #else\n\
         inline ResolveRva resolver = nullptr;\n\
         #endif"
    );
    out = out.replace("__DEFAULT_RESOLVER__", &windows_resolver);
    out
}

fn emit_direct_call(
    symbol: &Symbol,
    verified_callable: &BTreeSet<&str>,
    used: &mut BTreeSet<String>,
    out: &mut String,
) {
    if !verified_callable.contains(symbol.id.as_str())
        || symbol.library
        || !symbol.is_code
        || !symbol.sig.parse_ok
        || matches!(
            symbol.kind,
            Kind::Ctor | Kind::Dtor | Kind::Thunk | Kind::Data
        )
    {
        return;
    }
    let Some(ret) = cpp_abi_type(symbol.sig.ret.as_ref()) else {
        return;
    };
    let Some(params) = symbol
        .sig
        .params
        .iter()
        .map(|ty| cpp_abi_type(Some(ty)))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let has_this = symbol.sig.class.is_some() && symbol.sig.storage.as_deref() != Some("static");
    let this_ty = if symbol.sig.is_const {
        "const void*"
    } else {
        "void*"
    };
    let base = sanitize_filename(&format!(
        "{}_{}",
        symbol.sig.class.as_deref().unwrap_or("global"),
        symbol.sig.method.as_deref().unwrap_or("call")
    ));
    let mut function = base.clone();
    let mut suffix = 2;
    while !used.insert(function.clone()) {
        function = format!("{base}_{suffix}");
        suffix += 1;
    }
    let mut declarations = Vec::new();
    let mut types = Vec::new();
    let mut arguments = Vec::new();
    if has_this {
        declarations.push(format!("{this_ty} self"));
        types.push(this_ty.to_string());
        arguments.push("self".to_string());
    }
    for (index, ty) in params.iter().enumerate() {
        declarations.push(format!("{ty} p{index}"));
        types.push(ty.clone());
        arguments.push(format!("p{index}"));
    }
    let nodiscard = if ret == "void" { "" } else { "[[nodiscard]] " };
    let _ = write!(
        out,
        "\n// RVA 0x{:X}; {}; {}.\n{nodiscard}inline {ret} {function}({}) {{\n    using Fn = {ret} (*)({});\n    auto target = reinterpret_cast<Fn>(const_cast<void*>(require(0x{:X}U)));\n",
        symbol.rva,
        cpp_string(&symbol.mangled),
        if symbol.exported {
            "PE export"
        } else {
            "PDB internal"
        },
        declarations.join(", "),
        types.join(", "),
        symbol.rva,
    );
    if ret == "void" {
        let _ = write!(out, "    target({});\n}}\n", arguments.join(", "));
    } else {
        let _ = write!(out, "    return target({});\n}}\n", arguments.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_qualified_class_pointer_keeps_one_pointer_level() {
        let classes = std::iter::once("DirectUI::Element".to_string()).collect();
        assert_eq!(
            clean_cpp_type("class DirectUI::Element *", "Element", &classes),
            "Element *"
        );
    }

    #[test]
    fn class_name_suffix_is_not_rewritten_as_a_different_class() {
        let classes = std::iter::once("DirectUI::HWNDElementProvider".to_string()).collect();
        assert_eq!(
            clean_cpp_type(
                "class DirectUI::HWNDElementProvider * *",
                "HWNDElementProvider",
                &classes,
            ),
            "HWNDElementProvider * *"
        );
    }

    #[test]
    fn unavailable_nested_structure_preserves_pointer_depth() {
        let classes = ["DirectUI::CBinaryFile", "DirectUI::BinaryFile"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(
            clean_cpp_type(
                "struct DirectUI::BinaryFile::BDXEntry const *",
                "CBinaryFile",
                &classes,
            ),
            "WindissectOpaque const *"
        );
    }
}
