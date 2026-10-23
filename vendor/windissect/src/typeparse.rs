//! Parse demangled type text into the structured [`Type`] AST; unknown shapes
//! fall back to [`Type::Raw`].

use crate::model::{Type, TypeArg, TypeText};

pub fn type_text(s: &str) -> TypeText {
    let t = s.trim().to_string();
    TypeText {
        ast: parse(&t),
        text: t,
    }
}

const BUILTINS: &[&str] = &[
    "void",
    "bool",
    "char",
    "wchar_t",
    "short",
    "int",
    "long",
    "float",
    "double",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
    "unsigned",
    "signed",
    "__wchar_t",
];

pub fn parse(s: &str) -> Type {
    let s = s.trim();
    if s.is_empty() {
        return Type::Raw {
            text: String::new(),
        };
    }

    // Function pointer: "RET (__cc *)(PARAMS)": two top-level paren groups, the
    // first containing a '*'. Handle before decorator stripping.
    if let Some(t) = parse_fnptr(s) {
        return t;
    }

    // Outermost decorator binds rightmost first: `T *`, `T &`, `T const`.
    if let Some(inner) = s.strip_suffix('*') {
        return Type::Ptr {
            to: Box::new(parse(inner)),
        };
    }
    if let Some(inner) = s.strip_suffix('&') {
        return Type::Ref {
            to: Box::new(parse(inner)),
        };
    }
    if let Some(inner) = strip_word_suffix(s, "const") {
        return Type::Const {
            of: Box::new(parse(inner)),
        };
    }
    if let Some(inner) = s.strip_prefix("const ") {
        return Type::Const {
            of: Box::new(parse(inner)),
        };
    }

    // Strip an elaborated-type keyword: `class X`, `struct X`, `enum X`, `union X`.
    let core = ["class ", "struct ", "enum ", "union "]
        .iter()
        .find_map(|k| s.strip_prefix(k))
        .unwrap_or(s)
        .trim();

    // Templated named type: `A::B<args>`.
    if let Some(lt) = top_level_index(core, '<')
        && core.ends_with('>')
    {
        let path = split_sep_top(&core[..lt], "::");
        let args = split_top(&core[lt + 1..core.len() - 1], ',')
            .into_iter()
            .map(parse_arg)
            .collect();
        return Type::Named {
            path: path.into_iter().map(str::to_string).collect(),
            args,
        };
    }

    // Builtin vs named.
    if !core.contains("::") && !core.contains('<') {
        let first = core.split_whitespace().next().unwrap_or("");
        if BUILTINS.contains(&first) {
            return Type::Builtin {
                name: core.to_string(),
            };
        }
    }
    if core
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
    {
        return Type::Named {
            path: split_sep_top(core, "::")
                .into_iter()
                .map(str::to_string)
                .collect(),
            args: vec![],
        };
    }
    Type::Raw {
        text: s.to_string(),
    }
}

fn parse_arg(s: &str) -> TypeArg {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return TypeArg::Const(n);
    }
    match parse(s) {
        Type::Raw { text } => TypeArg::Raw(text),
        t => TypeArg::Type(t),
    }
}

/// `RET (__cc *)(P1, P2)` -> `FnPtr`. Returns None if `s` isn't that shape.
fn parse_fnptr(s: &str) -> Option<Type> {
    let open1 = top_level_index(s, '(')?;
    let close1 = matching_paren(s, open1)?;
    let inner = &s[open1 + 1..close1];
    if !inner.contains('*') {
        return None; // not a pointer-ish paren group
    }
    // params are the next top-level paren group.
    let rest = &s[close1 + 1..];
    let open2 = top_level_index(rest, '(')?;
    let close2 = matching_paren(rest, open2)?;
    let params_str = &rest[open2 + 1..close2];

    let result_type = Box::new(parse(s[..open1].trim()));
    let callconv = inner
        .split_whitespace()
        .find(|w| w.starts_with("__"))
        .map(str::to_string);
    let params = if params_str.trim().is_empty() || params_str.trim() == "void" {
        vec![]
    } else {
        split_top(params_str, ',')
            .into_iter()
            .map(|p| parse(p.trim()))
            .collect()
    };
    Some(Type::FnPtr {
        ret: result_type,
        params,
        callconv,
    })
}

// ---- nesting-aware scanners (depth over <>, (), []) -----------------------

const fn delta(c: char) -> i32 {
    match c {
        '<' | '(' | '[' => 1,
        '>' | ')' | ']' => -1,
        _ => 0,
    }
}

/// Index of the first `c` at nesting depth 0.
fn top_level_index(s: &str, c: char) -> Option<usize> {
    let mut depth = 0;
    for (i, ch) in s.char_indices() {
        if depth == 0 && ch == c {
            return Some(i);
        }
        depth += delta(ch);
    }
    None
}

fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, ch) in s.char_indices().skip(open) {
        depth += delta(ch);
        if depth == 0 {
            return Some(i);
        }
    }
    None
}

/// Strip a trailing whole word (e.g. `const`) plus surrounding space, at top
/// level. Returns the remainder without the word.
fn strip_word_suffix<'a>(s: &'a str, word: &str) -> Option<&'a str> {
    let s = s.trim_end();
    let rest = s.strip_suffix(word)?;
    // must be a word boundary and at top level (depth 0 across the whole string)
    if rest.chars().last().is_none_or(|c| c == ' ') {
        // ensure the suffix isn't nested inside <> or ()
        let mut depth = 0;
        for ch in rest.chars() {
            depth += delta(ch);
        }
        if depth == 0 {
            return Some(rest.trim_end());
        }
    }
    None
}

/// Split on a single byte separator at depth 0.
pub fn split_top(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0, 0);
    for (i, ch) in s.char_indices() {
        if depth == 0 && ch == sep {
            out.push(&s[start..i]);
            start = i + ch.len_utf8();
            continue;
        }
        depth += delta(ch);
    }
    out.push(&s[start..]);
    out
}

/// Last balanced `(...)` at nesting depth 0: the method parameter list.
pub fn last_top_parens(s: &str) -> Option<(usize, usize)> {
    let (mut depth, mut cur, mut found) = (0i32, None, None);
    for (i, ch) in s.char_indices() {
        match ch {
            '<' | '[' => depth += 1,
            '>' | ']' => depth -= 1,
            '(' => {
                if depth == 0 {
                    cur = Some(i);
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0
                    && let Some(o) = cur
                {
                    found = Some((o, i));
                }
            }
            _ => {}
        }
    }
    found
}

/// First whole-word token from `toks` at depth 0 (e.g. a calling convention).
pub fn top_token<'a>(s: &str, toks: &[&'a str]) -> Option<(usize, &'a str)> {
    let (mut depth, bytes) = (0i32, s.as_bytes());
    let mut i = 0;
    while i < s.len() {
        if depth == 0 {
            for t in toks {
                if s[i..].starts_with(t) && word_boundary(s, i, i + t.len()) {
                    return Some((i, t));
                }
            }
        }
        depth += delta(bytes[i] as char);
        i += 1;
    }
    None
}

fn word_boundary(s: &str, lo: usize, hi: usize) -> bool {
    let isw = |c: u8| c == b'_' || c.is_ascii_alphanumeric();
    let b = s.as_bytes();
    if lo > 0 && isw(b[lo - 1]) {
        return false;
    }
    if hi < s.len() && isw(b[hi]) {
        return false;
    }
    true
}

/// Split on a multi-char separator ("::") at depth 0.
pub fn split_sep_top<'a>(s: &'a str, sep: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let (mut depth, mut start, mut i) = (0i32, 0usize, 0usize);
    let bytes = s.as_bytes();
    while i < s.len() {
        if depth == 0 && s[i..].starts_with(sep) {
            out.push(&s[start..i]);
            i += sep.len();
            start = i;
            continue;
        }
        depth += delta(bytes[i] as char);
        i += 1;
    }
    out.push(&s[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Type;

    #[test]
    fn builtin() {
        assert_eq!(parse("int"), Type::Builtin { name: "int".into() });
        assert_eq!(
            parse("unsigned long"),
            Type::Builtin {
                name: "unsigned long".into()
            }
        );
    }

    #[test]
    fn named_and_pointer() {
        assert_eq!(
            parse("class DirectUI::Element *"),
            Type::Ptr {
                to: Box::new(Type::Named {
                    path: vec!["DirectUI".into(), "Element".into()],
                    args: vec![]
                })
            }
        );
    }

    #[test]
    fn const_void_pointer() {
        // `void const *` is a pointer to const void.
        assert_eq!(
            parse("void const *"),
            Type::Ptr {
                to: Box::new(Type::Const {
                    of: Box::new(Type::Builtin {
                        name: "void".into()
                    })
                })
            }
        );
    }

    #[test]
    fn function_pointer() {
        let t = parse("int (__cdecl *)(void const *, void const *)");
        match t {
            Type::FnPtr {
                ret,
                params,
                callconv,
            } => {
                assert_eq!(*ret, Type::Builtin { name: "int".into() });
                assert_eq!(params.len(), 2);
                assert_eq!(callconv.as_deref(), Some("__cdecl"));
            }
            other => panic!("expected FnPtr, got {other:?}"),
        }
    }

    #[test]
    fn template_with_nontype_arg() {
        // DynamicArray<Element*, 0>: a type arg and a non-type constant arg.
        let t = parse("class DirectUI::DynamicArray<class DirectUI::Element *, 0>");
        match t {
            Type::Named { path, args } => {
                assert_eq!(
                    path,
                    vec!["DirectUI".to_string(), "DynamicArray".to_string()]
                );
                assert_eq!(args.len(), 2);
                assert!(matches!(args[1], TypeArg::Const(0)));
            }
            other => panic!("expected Named template, got {other:?}"),
        }
    }
}
