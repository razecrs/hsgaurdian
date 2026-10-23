//! Demangles MSVC C++ mangled symbols and classifies signatures. See `docs/architecture.md` or `cargo doc`.

use crate::model::{Kind, Signature, Symbol};
use crate::typeparse::{self, split_sep_top, split_top, type_text};
use msvc_demangler::DemangleFlags;

const CALLCONVS: &[&str] = &[
    "__cdecl",
    "__thiscall",
    "__stdcall",
    "__fastcall",
    "__vectorcall",
    "__clrcall",
];

/// Demangle one MSVC name to a full declaration; None if not a valid mangling.
pub fn demangle(mangled: &str) -> Option<String> {
    let flags = DemangleFlags::COMPLETE | DemangleFlags::SPACE_AFTER_COMMA;
    msvc_demangler::demangle(mangled, flags).ok()
}

/// Structure a demangled declaration; `parse_ok=false` if not fully split.
pub fn parse_decl(decl: &str) -> Signature {
    let mut sig = Signature::default();
    let mut s = decl.trim();
    if s.is_empty() {
        return sig;
    }

    // Access specifier.
    for a in ["public", "protected", "private"] {
        let pfx = format!("{a}: ");
        if let Some(rest) = s.strip_prefix(&pfx) {
            sig.access = Some(a.to_string());
            s = rest;
            break;
        }
    }
    // Storage class.
    if let Some(rest) = s.strip_prefix("virtual ") {
        sig.storage = Some("virtual".into());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("static ") {
        sig.storage = Some("static".into());
        s = rest;
    }

    // MSVC renders a method returning a function pointer as
    // `R (ret_cc * method_cc C::f(args))(callback_args)`. The method's
    // parameter list is nested inside the return declarator, so selecting the
    // final top-level parentheses would mistake callback_args for f's args.
    if parse_function_pointer_return(s, &mut sig) {
        return sig;
    }

    // Parameter list = the last top-level (...); optional trailing " const".
    let Some((open, close)) = typeparse::last_top_parens(s) else {
        return sig; // not a function decl (data/vftable/RTTI)
    };
    let head = s[..open].trim();
    let params = &s[open + 1..close];
    match s[close + 1..].trim() {
        "" => {}
        "const" => sig.is_const = true,
        _ => return sig, // unexpected trailing text, don't guess
    }

    // Split head into "<ret> <callconv> <qualified-name>".
    let Some((cc_idx, cc)) = typeparse::top_token(head, CALLCONVS) else {
        return sig; // no calling convention, flat C export / data
    };
    sig.callconv = Some(cc.to_string());
    let ret = head[..cc_idx].trim();
    if !ret.is_empty() {
        sig.ret = Some(type_text(ret));
    }
    let qual = head[cc_idx + cc.len()..].trim();

    // Qualified name -> namespace / class / method (top-level "::" split).
    if !assign_qualified_name(&mut sig, qual) {
        return sig;
    }

    // Parameters (top-level comma split; "void" = none).
    let p = params.trim();
    if !p.is_empty() && p != "void" {
        sig.params = split_top(params, ',').into_iter().map(type_text).collect();
    }

    sig.parse_ok = true;
    sig
}

fn parse_function_pointer_return(decl: &str, sig: &mut Signature) -> bool {
    let mut selected = None;
    for cc in CALLCONVS {
        let needle = format!(" {cc} ");
        for (index, _) in decl.match_indices(&needle) {
            let tail = decl[index + needle.len()..].trim_start();
            let Some(open) = tail.find('(') else { continue };
            let qual = tail[..open].trim();
            if qual.contains("::") {
                selected = Some((index, *cc, tail, open));
            }
        }
    }
    let Some((cc_index, cc, tail, open)) = selected else {
        return false;
    };
    let Some(close_rel) = tail[open..].find(')') else {
        return false;
    };
    let close = open + close_rel;
    let after = tail[close + 1..].trim_start();
    if !after.starts_with(")(") {
        return false;
    }
    let qual = tail[..open].trim();
    if !assign_qualified_name(sig, qual) {
        return false;
    }
    sig.callconv = Some(cc.to_string());
    let params = tail[open + 1..close].trim();
    if !params.is_empty() && params != "void" {
        sig.params = split_top(params, ',').into_iter().map(type_text).collect();
    }
    let return_prefix = decl[..cc_index].trim();
    let callback_suffix = after.strip_prefix(')').unwrap_or(after);
    sig.ret = Some(type_text(&format!("{return_prefix}){callback_suffix}")));
    sig.parse_ok = true;
    true
}

fn assign_qualified_name(sig: &mut Signature, qual: &str) -> bool {
    let parts = split_sep_top(qual, "::");
    match parts.len() {
        0 => false,
        1 => {
            sig.method = Some(parts[0].to_string());
            true
        }
        n => {
            sig.method = Some(parts[n - 1].to_string());
            sig.class = Some(parts[n - 2].to_string());
            if n > 2 {
                sig.namespace = Some(parts[..n - 2].join("::"));
            }
            true
        }
    }
}

/// Assign a shape by name and structure.
pub fn classify(s: &Symbol) -> Kind {
    // Non-function special names appear in the export table too.
    let m = &s.mangled;
    if m.starts_with("??_7") || m.starts_with("??_R") || m.starts_with("??_C") {
        return Kind::Operator; // vftable / RTTI / string literal (not a function)
    }
    // Flat C export: never mangled, so no signature, but the name is known.
    if !m.starts_with('?') {
        return Kind::CFunc;
    }
    if !s.sig.parse_ok {
        // Demangled but no param list => static data member (Schema::*Property).
        return if s.demangled.is_some() {
            Kind::Data
        } else {
            Kind::Unknown
        };
    }

    let name = s.sig.method.as_deref().unwrap_or("");
    let class = s.sig.class.as_deref().unwrap_or("");
    if name.starts_with('~')
        || m.starts_with("??1")
        || m.starts_with("??_G")
        || m.starts_with("??_E")
    {
        Kind::Dtor
    } else if (!class.is_empty() && name == class) || m.starts_with("??0") {
        Kind::Ctor
    } else if matches!(name, "AddRef" | "Release" | "QueryInterface") {
        Kind::Refcount
    } else if name.contains("operator") {
        Kind::Operator
    } else if is_accessor(name) {
        Kind::Accessor
    } else if class.is_empty() {
        Kind::CFunc
    } else {
        Kind::Method
    }
}

fn is_accessor(name: &str) -> bool {
    if name.ends_with("Prop") {
        return true;
    }
    for p in ["Get", "Set", "Is", "Has"] {
        if let Some(rest) = name.strip_prefix(p)
            && rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::parse_decl;

    #[test]
    fn parses_method_returning_function_pointer() {
        let sig = parse_decl(
            "public: class DirectUI::Value * (__cdecl * __cdecl DirectUI::DUIXmlParser::GetGetSheetCallback(void))(unsigned short const *, void *)",
        );
        assert!(sig.parse_ok);
        assert_eq!(sig.namespace.as_deref(), Some("DirectUI"));
        assert_eq!(sig.class.as_deref(), Some("DUIXmlParser"));
        assert_eq!(sig.method.as_deref(), Some("GetGetSheetCallback"));
        assert_eq!(sig.params, Vec::new());
        assert_eq!(sig.callconv.as_deref(), Some("__cdecl"));
    }
}
