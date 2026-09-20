//! Full-file golden tests for generated goss output.
//!
//! Unlike the fragment `contains()` checks in `golden_tests.rs`, these compare
//! the *entire* generated `goss.yml`/`goss_wait.yml` against a stored expected
//! file under `tests/fixtures/expected/<case>/`. They pin the provenance-comment
//! feature (issue #15) so it cannot silently regress again, and they guard the
//! exact rendered shape (section order, indentation, quoting).
//!
//! Regenerate the golden files after an intentional output change with:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test --test golden_output_tests
//! ```

use std::path::PathBuf;

use dgossgen::config::PolicyConfig;
use dgossgen::{extractor, generator, parser, Profile};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// A golden case: a fixture Dockerfile rendered under a given profile, stored
/// under `tests/fixtures/expected/<case_name>/`.
struct Case {
    /// Directory name under `expected/` holding this case's golden files.
    name: &'static str,
    /// Fixture Dockerfile file name under `tests/fixtures/`.
    fixture: &'static str,
    profile: Profile,
}

const CASES: &[Case] = &[
    Case {
        name: "nginx",
        fixture: "nginx.Dockerfile",
        profile: Profile::Standard,
    },
    Case {
        name: "node_multistage",
        fixture: "node_multistage.Dockerfile",
        profile: Profile::Standard,
    },
    Case {
        name: "python_simple",
        fixture: "python_simple.Dockerfile",
        profile: Profile::Standard,
    },
    Case {
        name: "go_minimal",
        fixture: "go_minimal.Dockerfile",
        profile: Profile::Standard,
    },
    Case {
        name: "complex_healthcheck",
        fixture: "complex_healthcheck.Dockerfile",
        profile: Profile::Standard,
    },
    // php_composer under `strict` exercises package-install assertions (which
    // are Low confidence and filtered out under `standard`), pinning the
    // provenance comments on `command:` package checks.
    Case {
        name: "php_composer_strict",
        fixture: "php_composer.Dockerfile",
        profile: Profile::Strict,
    },
    // cmd_before_entrypoint has a CMD/ENTRYPOINT but no EXPOSE or HEALTHCHECK,
    // so it generates a goss.yml with no goss_wait.yml. This exercises
    // check_golden's `None` (no-wait) branch, which every other case skips.
    Case {
        name: "cmd_before_entrypoint",
        fixture: "cmd_before_entrypoint.Dockerfile",
        profile: Profile::Standard,
    },
];

fn generate_case(case: &Case) -> generator::GeneratorOutput {
    let df = parser::parse_dockerfile(&fixtures_dir().join(case.fixture))
        .unwrap_or_else(|e| panic!("parsing fixture {}: {e}", case.fixture));
    let contract = extractor::extract_contract(&df, None, &[]);
    generator::generate(&contract, case.profile, &PolicyConfig::default(), None)
}

/// Compare `actual` against the golden file at `expected/<case>/<file>`, or, when
/// `UPDATE_GOLDEN=1`, (re)write the golden. `expected` of `None` means the file
/// should not exist (e.g. no wait file was generated).
fn check_golden(case: &str, file: &str, actual: Option<&str>) {
    let path = fixtures_dir().join("expected").join(case).join(file);
    let updating = std::env::var_os("UPDATE_GOLDEN").is_some();

    if updating {
        match actual {
            Some(content) => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, content).unwrap();
            }
            None => {
                // No output for this file: ensure a stale golden is removed.
                let _ = std::fs::remove_file(&path);
            }
        }
        return;
    }

    match actual {
        Some(content) => {
            let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
                panic!(
                    "missing golden file {}; regenerate with UPDATE_GOLDEN=1 cargo test",
                    path.display()
                )
            });
            assert_eq!(
                content,
                expected,
                "generated {file} for case '{case}' does not match golden {}.\n\
                 If this change is intentional, regenerate with \
                 `UPDATE_GOLDEN=1 cargo test --test golden_output_tests`.",
                path.display()
            );
        }
        None => {
            assert!(
                !path.exists(),
                "case '{case}' produced no {file}, but a golden exists at {}; \
                 regenerate with UPDATE_GOLDEN=1 if this is intentional",
                path.display()
            );
        }
    }
}

#[test]
fn golden_outputs_match() {
    for case in CASES {
        let output = generate_case(case);
        check_golden(case.name, "goss.yml", Some(&output.goss_yml));
        check_golden(case.name, "goss_wait.yml", output.goss_wait_yml.as_deref());
    }
}

/// Sanity check that every golden goss/wait file carries at least one provenance
/// comment — the feature these goldens exist to protect (issue #15). Skipped
/// while regenerating.
#[test]
fn golden_outputs_carry_provenance_comments() {
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        return;
    }
    for case in CASES {
        let output = generate_case(case);
        // Every non-empty generated file must annotate its assertions.
        if output.goss_yml.trim() != "command: {}" {
            assert!(
                output.goss_yml.contains("# derived from ")
                    && output.goss_yml.contains("; confidence: "),
                "case '{}' goss.yml is missing provenance comments:\n{}",
                case.name,
                output.goss_yml
            );
        }
        if let Some(wait) = &output.goss_wait_yml {
            assert!(
                wait.contains("# derived from ") && wait.contains("; confidence: "),
                "case '{}' goss_wait.yml is missing provenance comments:\n{}",
                case.name,
                wait
            );
        }
    }
}
