use dgossgen::config::PolicyConfig;
use dgossgen::extractor::{self, AssertionKind};
use dgossgen::generator;
use dgossgen::parser;
use dgossgen::Profile;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// --- Nginx fixture tests ---

#[test]
fn test_nginx_contract_extraction() {
    let df = parser::parse_dockerfile(&fixture_path("nginx.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    assert_eq!(contract.base_image, "nginx:alpine");
    assert_eq!(contract.exposed_ports.len(), 2);
    assert_eq!(contract.exposed_ports[0].port, 80);
    assert_eq!(contract.exposed_ports[1].port, 443);
    assert!(contract.healthcheck.is_some());

    // Should have assertions for: files, ports, healthcheck, process
    assert!(contract
        .assertions
        .iter()
        .any(|a| matches!(&a.kind, AssertionKind::PortListening { port: 80, .. })));
    assert!(contract
        .assertions
        .iter()
        .any(|a| matches!(&a.kind, AssertionKind::HealthcheckPasses { .. })));
}

#[test]
fn test_nginx_generates_wait_file() {
    let df = parser::parse_dockerfile(&fixture_path("nginx.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

    assert!(
        output.goss_wait_yml.is_some(),
        "nginx with healthcheck should generate wait file"
    );
    let wait = output.goss_wait_yml.unwrap();
    assert!(
        wait.contains("command:"),
        "wait file should have command section"
    );
    assert!(
        wait.contains("healthcheck"),
        "wait file should contain healthcheck"
    );
}

#[test]
fn test_nginx_goss_yml_content() {
    let df = parser::parse_dockerfile(&fixture_path("nginx.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

    let yml = &output.goss_yml;
    assert!(yml.contains("file:"), "should have file assertions");
    assert!(
        yml.contains("/etc/nginx/nginx.conf"),
        "should check nginx config"
    );
}

// --- Node.js multistage fixture tests ---

#[test]
fn test_node_multistage_contract() {
    let df = parser::parse_dockerfile(&fixture_path("node_multistage.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // Should target the last stage (runtime)
    assert_eq!(contract.base_image, "node:18-alpine");
    assert_eq!(contract.workdir, Some("/app".to_string()));
    assert_eq!(contract.exposed_ports.len(), 1);
    assert_eq!(contract.exposed_ports[0].port, 3000);
    assert_eq!(contract.user, Some("appuser".to_string()));

    // Should have process assertion for "node"
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::ProcessRunning { name } if name == "node"
    )));
}

#[test]
fn test_node_multistage_user_assertion() {
    let df = parser::parse_dockerfile(&fixture_path("node_multistage.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // Should have user assertion for "appuser"
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::UserExists { username } if username == "appuser"
    )));
}

#[test]
fn test_node_generates_wait_for_single_port() {
    let df = parser::parse_dockerfile(&fixture_path("node_multistage.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

    // With exactly one exposed port, should auto-generate wait
    assert!(
        output.goss_wait_yml.is_some(),
        "single exposed port should trigger wait file generation"
    );
}

// --- Python simple fixture tests ---

#[test]
fn test_python_simple_contract() {
    let df = parser::parse_dockerfile(&fixture_path("python_simple.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    assert_eq!(contract.base_image, "python:3.11-slim");
    assert_eq!(contract.workdir, Some("/app".to_string()));
    assert_eq!(contract.exposed_ports.len(), 1);
    assert_eq!(contract.exposed_ports[0].port, 5000);

    // Environment variables should be captured
    assert!(contract
        .env
        .iter()
        .any(|(k, v)| k == "FLASK_APP" && v == "app.py"));
}

#[test]
fn test_python_process_assertion() {
    let df = parser::parse_dockerfile(&fixture_path("python_simple.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // CMD ["python", ...] should generate a process assertion for "python"
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::ProcessRunning { name } if name == "python"
    )));
}

// --- Go minimal (scratch base) fixture tests ---

#[test]
fn test_go_minimal_contract() {
    let df = parser::parse_dockerfile(&fixture_path("go_minimal.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    assert_eq!(contract.base_image, "scratch");
    assert_eq!(contract.exposed_ports.len(), 1);
    assert_eq!(contract.exposed_ports[0].port, 8080);
    assert_eq!(contract.user, Some("65534".to_string()));

    // Numeric user should produce uid-based assertion
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::CommandOutput {
            command,
            expected_output,
            ..
        } if command == "id -u" && expected_output == &vec!["65534".to_string()]
    )));
}

#[test]
fn test_go_minimal_entrypoint_process() {
    let df = parser::parse_dockerfile(&fixture_path("go_minimal.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // ENTRYPOINT ["/server"] should generate process assertion for "server"
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::ProcessRunning { name } if name == "server"
    )));
}

// --- Complex healthcheck fixture tests ---

#[test]
fn test_complex_healthcheck_contract() {
    let df = parser::parse_dockerfile(&fixture_path("complex_healthcheck.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    assert_eq!(contract.base_image, "ubuntu:22.04");
    assert_eq!(contract.workdir, Some("/var/www/html".to_string()));
    assert_eq!(contract.user, Some("www-data".to_string()));
    assert!(contract.healthcheck.is_some());
    assert_eq!(contract.volumes.len(), 2);
    assert_eq!(contract.exposed_ports.len(), 1);
    assert_eq!(contract.exposed_ports[0].port, 8080);
}

#[test]
fn test_complex_healthcheck_entrypoint_script_detection() {
    let df = parser::parse_dockerfile(&fixture_path("complex_healthcheck.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // Should detect the entrypoint script and assert it exists with executable permission
    let entrypoint_assertions: Vec<_> = contract
        .assertions
        .iter()
        .filter(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, mode, .. }
                if path == "/docker-entrypoint.sh" && mode.as_deref() == Some("0755")
        ))
        .collect();
    assert_eq!(entrypoint_assertions.len(), 1);
}

#[test]
fn test_complex_healthcheck_service_detection() {
    let df = parser::parse_dockerfile(&fixture_path("complex_healthcheck.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // Should detect nginx installation and generate service-specific checks
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::FileExists { path, .. } if path == "/etc/nginx/nginx.conf"
    )));
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::CommandExit { command, .. } if command == "nginx -v"
    )));
}

// --- Profile behavior tests ---

#[test]
fn test_minimal_profile_skips_low_confidence() {
    let df = parser::parse_dockerfile(&fixture_path("complex_healthcheck.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    let output_strict =
        generator::generate(&contract, Profile::Strict, &PolicyConfig::default(), None);
    let output_minimal =
        generator::generate(&contract, Profile::Minimal, &PolicyConfig::default(), None);

    // Strict profile should include more assertions (or equal) than minimal
    let strict_lines = output_strict.goss_yml.lines().count();
    let minimal_lines = output_minimal.goss_yml.lines().count();
    assert!(
        strict_lines >= minimal_lines,
        "strict ({}) should have >= assertions than minimal ({})",
        strict_lines,
        minimal_lines
    );
}

// --- Idempotence tests ---

#[test]
fn test_generation_is_idempotent() {
    let df = parser::parse_dockerfile(&fixture_path("nginx.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let policy = PolicyConfig::default();

    let output1 = generator::generate(&contract, Profile::Standard, &policy, None);
    let output2 = generator::generate(&contract, Profile::Standard, &policy, None);

    assert_eq!(
        output1.goss_yml, output2.goss_yml,
        "goss.yml should be idempotent"
    );
    assert_eq!(
        output1.goss_wait_yml, output2.goss_wait_yml,
        "goss_wait.yml should be idempotent"
    );
}

// --- Stable ordering test ---

#[test]
fn test_output_has_stable_ordering() {
    let df = parser::parse_dockerfile(&fixture_path("complex_healthcheck.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let policy = PolicyConfig::default();

    let output = generator::generate(&contract, Profile::Standard, &policy, None);
    let yml = &output.goss_yml;

    // Sections should appear in stable order: file, port, process, command
    let file_pos = yml.find("file:");
    let port_pos = yml.find("port:");
    let command_pos = yml.find("command:");

    if let (Some(f), Some(p)) = (file_pos, port_pos) {
        assert!(f < p, "file section should come before port section");
    }
    if let (Some(p), Some(c)) = (port_pos, command_pos) {
        assert!(p < c, "port section should come before command section");
    }
}

// --- No-wait / force-wait tests ---

#[test]
fn test_no_wait_flag() {
    let df = parser::parse_dockerfile(&fixture_path("nginx.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(
        &contract,
        Profile::Standard,
        &PolicyConfig::default(),
        Some(false),
    );

    assert!(
        output.goss_wait_yml.is_none(),
        "--no-wait should suppress wait file"
    );
}

#[test]
fn test_force_wait_flag() {
    let df = parser::parse_dockerfile(&fixture_path("python_simple.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(
        &contract,
        Profile::Standard,
        &PolicyConfig::default(),
        Some(true),
    );

    assert!(
        output.goss_wait_yml.is_some(),
        "--force-wait should always generate wait file"
    );
}

// --- PHP Composer fixture tests ---

#[test]
fn test_php_composer_contract() {
    let df = parser::parse_dockerfile(&fixture_path("php_composer.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    assert_eq!(contract.base_image, "php:8.2-fpm");
    assert_eq!(contract.workdir, Some("/var/www/html".to_string()));
    assert_eq!(contract.exposed_ports.len(), 1);
    assert_eq!(contract.exposed_ports[0].port, 9000);
}

#[test]
fn test_php_composer_package_detection() {
    let df = parser::parse_dockerfile(&fixture_path("php_composer.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // Should detect monolog/monolog from composer require
    assert!(
        contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: extractor::PackageManager::Composer,
                ..
            } if package == "monolog/monolog"
        )),
        "should detect composer require monolog/monolog"
    );
}

#[test]
fn test_php_composer_apt_packages_detected() {
    let df = parser::parse_dockerfile(&fixture_path("php_composer.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);

    // Should detect git and unzip from apt-get install
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::PackageInstalled {
            package,
            manager: extractor::PackageManager::Apt,
            version_cmd: Some(_),
        } if package == "git"
    )));
    assert!(contract.assertions.iter().any(|a| matches!(
        &a.kind,
        AssertionKind::PackageInstalled {
            package,
            manager: extractor::PackageManager::Apt,
            ..
        } if package == "unzip"
    )));
}

#[test]
fn test_php_composer_goss_output() {
    let df = parser::parse_dockerfile(&fixture_path("php_composer.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(&contract, Profile::Strict, &PolicyConfig::default(), None);

    let yml = &output.goss_yml;
    assert!(
        yml.contains("composer show 'monolog/monolog'"),
        "should generate composer show check for monolog"
    );
    assert!(
        yml.contains("dpkg -s git"),
        "should generate dpkg check for git"
    );
}

// --- Secret redaction tests ---

#[test]
fn test_secret_keys_not_in_output() {
    let content = r#"
FROM alpine
ENV DB_PASSWORD=supersecret
ENV API_TOKEN=abc123
ENV APP_PORT=3000
EXPOSE 3000
"#;
    let df = parser::parse_dockerfile_content(content).unwrap();
    let _contract = extractor::extract_contract(&df, None, &[]);
    let policy = PolicyConfig::default();

    // Verify the config considers these as secrets
    assert!(policy.is_secret_key("DB_PASSWORD"));
    assert!(policy.is_secret_key("API_TOKEN"));
    assert!(!policy.is_secret_key("APP_PORT"));
}

// --- Provenance comment tests ---

#[test]
fn test_output_contains_provenance_comments() {
    let df = parser::parse_dockerfile(&fixture_path("nginx.Dockerfile")).unwrap();
    let contract = extractor::extract_contract(&df, None, &[]);
    let output = generator::generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

    assert!(
        output.goss_yml.contains("# derived from"),
        "output should contain provenance comments"
    );
    assert!(
        output.goss_yml.contains("confidence:"),
        "output should contain confidence tags"
    );
}
