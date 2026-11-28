//! Tables of what the Go implementation makes of a case, for the tests.

/// Runs `outcome` over every row and fails with each row where it is not what Go gives.
/// `table` is `(case, Go, Rust before)`; the last column is a record only, it shows where
/// Rust used to differ. A Go column of `-` is a case the Go check does not answer (the
/// test says why); `outcome` still runs, but nothing is compared.
pub(crate) fn assert_rows_as_in_go(
    table: &[(&str, &str, &str)],
    mut outcome: impl FnMut(&str) -> String,
) {
    let mut wrong = Vec::new();
    for (i, (name, go, _before)) in table.iter().enumerate() {
        if table[..i].iter().any(|row| row.0 == *name) {
            wrong.push(format!("{name}: two rows"));
        }
        let got = outcome(name);
        if *go != "-" && got != *go {
            wrong.push(format!("{name}: Go {go}, Rust {got}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
