//! Hard invariant: `of_with_ordinal` NEVER appears in this crate.
//! Using it silently converts a load-balanced replica pool into N
//! independently unreachable identities.

#[test]
fn of_with_ordinal_is_never_used() {
    let mut violations = Vec::new();
    for entry in walkdir::WalkDir::new("src")
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().map_or(false, |ext| ext == "rs") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            let code_only: String = content
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            if code_only.contains("of_with_ordinal") {
                violations.push(entry.path().to_path_buf());
            }
        }
    }
    assert!(
        violations.is_empty(),
        "of_with_ordinal found in code (not comments) in: {:?}",
        violations
    );
}
