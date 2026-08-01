// src/names.rs - low-risk symbol display helpers.
//
// IDA's Python API has the canonical demangler for C++/Rust. In the Rust CLI,
// only render Rust names when `rustc-demangle` can unambiguously identify them;
// otherwise keep the exact IDA/idalib symbol unchanged.

/// Prefer a readable Rust demangled name while preserving the exact symbol.
pub fn render_symbol_name(name: &str) -> String {
    if let Some(demangled) = try_demangle_rust(name) {
        if demangled != name {
            return format!("{} ({})", demangled, name);
        }
    }
    name.to_string()
}

fn try_demangle_rust(name: &str) -> Option<String> {
    for candidate in rust_candidates(name) {
        if let Ok(demangled) = rustc_demangle::try_demangle(candidate) {
            let rendered = format!("{:#}", demangled);
            if rendered != candidate {
                return Some(rendered);
            }
        }
    }
    None
}

fn rust_candidates(name: &str) -> Vec<&str> {
    let trimmed = name.strip_prefix('.').unwrap_or(name);
    let mut out = Vec::new();

    if trimmed.starts_with("_R") {
        out.push(trimmed);
    }
    if let Some(stripped) = trimmed.strip_prefix('_') {
        if stripped.starts_with("_R") {
            out.push(stripped);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::render_symbol_name;

    #[test]
    fn keeps_plain_names() {
        assert_eq!(render_symbol_name("sub_1000"), "sub_1000");
    }
}
