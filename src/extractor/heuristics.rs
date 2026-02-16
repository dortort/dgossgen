use crate::parser::CommandForm;
use crate::Confidence;

use super::model::{
    AssertionKind, ComponentKind, ContractAssertion, InstalledComponent, PackageManager,
};
use regex::Regex;
use std::sync::LazyLock;

static APT_INSTALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"apt-get\s+install\s+(?:-y\s+)?(.+?)(?:\s*&&|\s*$)").unwrap());
static APK_ADD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"apk\s+add\s+(?:--no-cache\s+)?(.+?)(?:\s*&&|\s*$)").unwrap());
static PIP_INSTALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"pip3?\s+install\s+(.+?)(?:\s*&&|\s*$)").unwrap());
static NPM_INSTALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"npm\s+(?:install|ci)(?:\s+(.+?))?(?:\s*&&|\s*$)").unwrap());
static COMPOSER_REQUIRE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"composer\s+require\s+(.+?)(?:\s*&&|\s*$)").unwrap());
static USERADD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:useradd|adduser)\s+(?:[^\s]+\s+)*?(\w+)\s*$").unwrap());
static COMPONENT_PATTERNS: LazyLock<Vec<(Regex, &'static str, ComponentKind)>> =
    LazyLock::new(|| {
        vec![
            (
                Regex::new(r"\bnginx\b").unwrap(),
                "nginx",
                ComponentKind::WebServer,
            ),
            (
                Regex::new(r"\bapache2\b").unwrap(),
                "apache2",
                ComponentKind::WebServer,
            ),
            (
                Regex::new(r"\bhttpd\b").unwrap(),
                "httpd",
                ComponentKind::WebServer,
            ),
            (
                Regex::new(r"\bpython3?\b").unwrap(),
                "python",
                ComponentKind::Runtime,
            ),
            (
                Regex::new(r"\bnode(js)?\b").unwrap(),
                "node",
                ComponentKind::Runtime,
            ),
            (
                Regex::new(r"\bjava\b").unwrap(),
                "java",
                ComponentKind::Runtime,
            ),
            (
                Regex::new(r"\bruby\b").unwrap(),
                "ruby",
                ComponentKind::Runtime,
            ),
            (
                Regex::new(r"\bphp\b").unwrap(),
                "php",
                ComponentKind::Runtime,
            ),
            (
                Regex::new(r"\b(go|golang)\b").unwrap(),
                "go",
                ComponentKind::Runtime,
            ),
            (
                Regex::new(r"\bredis\b").unwrap(),
                "redis",
                ComponentKind::Database,
            ),
            (
                Regex::new(r"\bpostgres(ql)?\b").unwrap(),
                "postgres",
                ComponentKind::Database,
            ),
            (
                Regex::new(r"\bmysql\b").unwrap(),
                "mysql",
                ComponentKind::Database,
            ),
            (
                Regex::new(r"\bcurl\b").unwrap(),
                "curl",
                ComponentKind::Tool,
            ),
            (
                Regex::new(r"\bwget\b").unwrap(),
                "wget",
                ComponentKind::Tool,
            ),
        ]
    });

/// Analyze a RUN command for installed packages and generate assertions.
pub fn analyze_run_command(cmd: &CommandForm, source_line: usize) -> Vec<ContractAssertion> {
    let cmd_str = cmd.to_string_lossy();
    let mut assertions = Vec::new();

    extract_package_assertions(
        &mut assertions,
        &cmd_str,
        source_line,
        &APT_INSTALL_RE,
        detect_apt_package,
    );
    extract_package_assertions(
        &mut assertions,
        &cmd_str,
        source_line,
        &APK_ADD_RE,
        detect_apk_package,
    );
    extract_package_assertions(
        &mut assertions,
        &cmd_str,
        source_line,
        &PIP_INSTALL_RE,
        detect_pip_package,
    );
    extract_package_assertions(
        &mut assertions,
        &cmd_str,
        source_line,
        &NPM_INSTALL_RE,
        detect_npm_package,
    );
    extract_package_assertions(
        &mut assertions,
        &cmd_str,
        source_line,
        &COMPOSER_REQUIRE_RE,
        detect_composer_package,
    );

    // User creation patterns
    if let Some(assertion) = detect_user_creation(&cmd_str, source_line) {
        assertions.push(assertion);
    }

    assertions
}

/// Detect installed components from a RUN command.
pub fn detect_installed_components(cmd: &CommandForm) -> Vec<InstalledComponent> {
    let cmd_str = cmd.to_string_lossy().to_lowercase();
    let mut components = Vec::new();

    for (pattern, name, kind) in COMPONENT_PATTERNS.iter() {
        if pattern.is_match(&cmd_str) {
            components.push(InstalledComponent {
                name: (*name).to_string(),
                kind: kind.clone(),
                source_line: 0, // Will be set by caller
            });
        }
    }

    dedupe_components(&mut components);
    components
}

/// Generate assertions for known service patterns.
pub fn generate_service_assertions(components: &[InstalledComponent]) -> Vec<ContractAssertion> {
    let mut assertions = Vec::new();

    for component in components {
        match component.name.as_str() {
            "nginx" => {
                assertions.push(ContractAssertion::new(
                    AssertionKind::FileExists {
                        path: "/etc/nginx/nginx.conf".to_string(),
                        filetype: Some("file".to_string()),
                        mode: None,
                    },
                    "nginx service pattern",
                    component.source_line,
                    Confidence::Medium,
                ));
                assertions.push(ContractAssertion::new(
                    AssertionKind::CommandExit {
                        command: "nginx -v".to_string(),
                        exit_status: 0,
                    },
                    "nginx service pattern",
                    component.source_line,
                    Confidence::Medium,
                ));
            }
            "apache2" | "httpd" => {
                let binary = if component.name == "apache2" {
                    "apache2"
                } else {
                    "httpd"
                };
                assertions.push(ContractAssertion::new(
                    AssertionKind::CommandExit {
                        command: format!("{} -v", binary),
                        exit_status: 0,
                    },
                    format!("{} service pattern", component.name),
                    component.source_line,
                    Confidence::Medium,
                ));
            }
            "python" | "python3" => {
                assertions.push(ContractAssertion::new(
                    AssertionKind::CommandExit {
                        command: "python3 --version".to_string(),
                        exit_status: 0,
                    },
                    "python runtime pattern",
                    component.source_line,
                    Confidence::Low,
                ));
            }
            "node" => {
                assertions.push(ContractAssertion::new(
                    AssertionKind::CommandExit {
                        command: "node --version".to_string(),
                        exit_status: 0,
                    },
                    "node runtime pattern",
                    component.source_line,
                    Confidence::Low,
                ));
            }
            "java" => {
                assertions.push(ContractAssertion::new(
                    AssertionKind::CommandExit {
                        command: "java -version".to_string(),
                        exit_status: 0,
                    },
                    "java runtime pattern",
                    component.source_line,
                    Confidence::Low,
                ));
            }
            "redis" => {
                assertions.push(ContractAssertion::new(
                    AssertionKind::CommandExit {
                        command: "redis-cli --version".to_string(),
                        exit_status: 0,
                    },
                    "redis service pattern",
                    component.source_line,
                    Confidence::Medium,
                ));
            }
            _ => {}
        }
    }

    assertions
}

/// Packages that are low-value for assertion purposes (build-time deps, meta-packages).
fn is_low_value_package(pkg: &str) -> bool {
    matches!(
        pkg,
        "ca-certificates"
            | "gnupg"
            | "gnupg2"
            | "apt-transport-https"
            | "software-properties-common"
            | "lsb-release"
            | "dirmngr"
    )
}

/// Detects remnants of pip flags after the general loop strips leading dashes.
/// E.g. "--no-cache-dir" becomes "no-cache-dir", "-r" becomes "r".
fn is_pip_flag_remnant(pkg: &str) -> bool {
    matches!(
        pkg,
        "no-cache-dir"
            | "no-deps"
            | "no-build-isolation"
            | "no-binary"
            | "prefer-binary"
            | "user"
            | "upgrade"
            | "force-reinstall"
            | "pre"
            | "quiet"
            | "verbose"
            | "r"
            | "q"
            | "U"
            | "e"
    ) || pkg.len() == 1 // single-char remnants are almost always flags
}

/// Detects remnants of composer flags after the general loop strips leading dashes.
fn is_composer_flag_remnant(pkg: &str) -> bool {
    matches!(
        pkg,
        "no-dev"
            | "no-scripts"
            | "no-plugins"
            | "no-progress"
            | "no-interaction"
            | "no-update"
            | "prefer-dist"
            | "prefer-source"
            | "prefer-stable"
            | "optimize-autoloader"
            | "dev"
            | "W"
            | "w"
            | "n"
    ) || pkg.len() == 1
}

/// Optional enrichment: known version-check commands for well-known packages.
/// Returns `None` for packages where only the package-manager check is appropriate.
fn known_version_cmd(pkg: &str) -> Option<String> {
    match pkg {
        "nginx" => Some("nginx -v".to_string()),
        "curl" => Some("curl --version".to_string()),
        "wget" => Some("wget --version".to_string()),
        "python3" | "python" => Some("python3 --version".to_string()),
        "nodejs" | "node" => Some("node --version".to_string()),
        "git" => Some("git --version".to_string()),
        "java" | "default-jre" | "default-jdk" => Some("java -version".to_string()),
        "ruby" => Some("ruby --version".to_string()),
        "php" => Some("php --version".to_string()),
        "redis" | "redis-server" => Some("redis-cli --version".to_string()),
        "postgres" | "postgresql" => Some("postgres --version".to_string()),
        "mysql-server" => Some("mysql --version".to_string()),
        "vim" => Some("vim --version".to_string()),
        "nano" => Some("nano --version".to_string()),
        "composer" => Some("composer --version".to_string()),
        _ => None,
    }
}

fn extract_package_assertions(
    assertions: &mut Vec<ContractAssertion>,
    command: &str,
    source_line: usize,
    pattern: &Regex,
    detector: fn(&str, usize) -> Option<ContractAssertion>,
) {
    if let Some(captures) = pattern.captures(command) {
        if let Some(pkgs) = captures.get(1) {
            for pkg in pkgs.as_str().split_whitespace() {
                let pkg_clean = pkg.trim_start_matches('-');
                if pkg_clean.is_empty() || pkg_clean.starts_with('-') {
                    continue;
                }
                if let Some(assertion) = detector(pkg_clean, source_line) {
                    assertions.push(assertion);
                }
            }
        }
    }
}

fn detect_apt_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if is_low_value_package(pkg) {
        return None;
    }
    Some(ContractAssertion::new(
        AssertionKind::PackageInstalled {
            package: pkg.to_string(),
            manager: PackageManager::Apt,
            version_cmd: known_version_cmd(pkg),
        },
        format!("RUN apt-get install {}", pkg),
        source_line,
        Confidence::Low,
    ))
}

fn detect_apk_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if is_low_value_package(pkg) {
        return None;
    }
    Some(ContractAssertion::new(
        AssertionKind::PackageInstalled {
            package: pkg.to_string(),
            manager: PackageManager::Apk,
            version_cmd: known_version_cmd(pkg),
        },
        format!("RUN apk add {}", pkg),
        source_line,
        Confidence::Low,
    ))
}

fn detect_pip_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if is_pip_flag_remnant(pkg) {
        return None;
    }
    if pkg.ends_with(".txt") || pkg.ends_with(".cfg") || pkg.contains('/') || pkg == "." {
        return None;
    }
    let pkg_name = pkg
        .split(&['=', '>', '<', '!', '~', '['][..])
        .next()
        .unwrap_or(pkg);
    if pkg_name.is_empty() {
        return None;
    }
    Some(ContractAssertion::new(
        AssertionKind::PackageInstalled {
            package: pkg_name.to_string(),
            manager: PackageManager::Pip,
            version_cmd: known_version_cmd(pkg_name),
        },
        format!("RUN pip install {}", pkg_name),
        source_line,
        Confidence::Low,
    ))
}

fn detect_npm_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if pkg.is_empty() || pkg.starts_with('-') {
        return None;
    }
    let pkg_name = if let Some(stripped) = pkg.strip_prefix('@') {
        if let Some(at_pos) = stripped.find('@') {
            &pkg[..at_pos + 1]
        } else {
            pkg
        }
    } else if let Some(at_pos) = pkg.find('@') {
        &pkg[..at_pos]
    } else {
        pkg
    };
    if pkg_name.is_empty() {
        return None;
    }
    Some(ContractAssertion::new(
        AssertionKind::PackageInstalled {
            package: pkg_name.to_string(),
            manager: PackageManager::Npm,
            version_cmd: known_version_cmd(pkg_name),
        },
        format!("RUN npm install {}", pkg_name),
        source_line,
        Confidence::Low,
    ))
}

fn detect_composer_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if is_composer_flag_remnant(pkg) {
        return None;
    }
    let pkg_name = pkg.split(&[':', ' '][..]).next().unwrap_or(pkg);
    if pkg_name.is_empty() || !pkg_name.contains('/') {
        return None;
    }
    Some(ContractAssertion::new(
        AssertionKind::PackageInstalled {
            package: pkg_name.to_string(),
            manager: PackageManager::Composer,
            version_cmd: None,
        },
        format!("RUN composer require {}", pkg_name),
        source_line,
        Confidence::Low,
    ))
}

/// Detect user creation commands.
fn detect_user_creation(cmd_str: &str, source_line: usize) -> Option<ContractAssertion> {
    if let Some(captures) = USERADD_RE.captures(cmd_str) {
        if let Some(username) = captures.get(1) {
            let name = username.as_str().to_string();
            // Filter out flags that look like usernames
            if !name.starts_with('-') {
                return Some(ContractAssertion::new(
                    AssertionKind::UserExists {
                        username: name.clone(),
                    },
                    format!("RUN useradd/adduser {}", name),
                    source_line,
                    Confidence::Medium,
                ));
            }
        }
    }
    None
}

fn dedupe_components(components: &mut Vec<InstalledComponent>) {
    let mut seen = std::collections::HashSet::new();
    components.retain(|component| seen.insert(component.name.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nginx_install() {
        let cmd = CommandForm::Shell("apt-get install -y nginx".to_string());
        let assertions = analyze_run_command(&cmd, 5);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Apt,
                version_cmd: Some(_),
            } if package == "nginx"
        )));
    }

    #[test]
    fn test_detect_unknown_apt_package() {
        let cmd = CommandForm::Shell("apt-get install -y myfancyapp".to_string());
        let assertions = analyze_run_command(&cmd, 10);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Apt,
                version_cmd: None,
            } if package == "myfancyapp"
        )));
    }

    #[test]
    fn test_detect_unknown_apk_package() {
        let cmd = CommandForm::Shell("apk add --no-cache somelib".to_string());
        let assertions = analyze_run_command(&cmd, 10);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Apk,
                version_cmd: None,
            } if package == "somelib"
        )));
    }

    #[test]
    fn test_detect_pip_package() {
        let cmd = CommandForm::Shell("pip install flask requests".to_string());
        let assertions = analyze_run_command(&cmd, 10);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Pip,
                ..
            } if package == "flask"
        )));
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Pip,
                ..
            } if package == "requests"
        )));
    }

    #[test]
    fn test_low_value_packages_skipped() {
        let cmd = CommandForm::Shell("apt-get install -y ca-certificates gnupg".to_string());
        let assertions = analyze_run_command(&cmd, 10);
        assert!(
            assertions
                .iter()
                .all(|a| !matches!(&a.kind, AssertionKind::PackageInstalled { .. })),
            "low-value packages should not generate assertions"
        );
    }

    #[test]
    fn test_detect_composer_package() {
        let cmd = CommandForm::Shell("composer require monolog/monolog".to_string());
        let assertions = analyze_run_command(&cmd, 10);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Composer,
                version_cmd: None,
            } if package == "monolog/monolog"
        )));
    }

    #[test]
    fn test_detect_composer_package_with_version_constraint() {
        let cmd = CommandForm::Shell("composer require symfony/console:^6.0".to_string());
        let assertions = analyze_run_command(&cmd, 10);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Composer,
                ..
            } if package == "symfony/console"
        )));
    }

    #[test]
    fn test_composer_flags_skipped() {
        let cmd = CommandForm::Shell(
            "composer require --no-dev --prefer-dist monolog/monolog".to_string(),
        );
        let assertions = analyze_run_command(&cmd, 10);
        // Should not have assertions for flag remnants like "no-dev" or "prefer-dist"
        assert!(assertions.iter().all(|a| {
            if let AssertionKind::PackageInstalled { package, .. } = &a.kind {
                package.contains('/')
            } else {
                true
            }
        }));
    }

    #[test]
    fn test_detect_installed_components() {
        let cmd = CommandForm::Shell("apt-get install -y nginx curl".to_string());
        let components = detect_installed_components(&cmd);
        assert!(components.iter().any(|c| c.name == "nginx"));
        assert!(components.iter().any(|c| c.name == "curl"));
    }

    #[test]
    fn test_component_detection_avoids_substring_false_positives() {
        let cmd = CommandForm::Shell(
            "echo download javascript && apt-get install -y ca-certificates".to_string(),
        );
        let components = detect_installed_components(&cmd);
        assert!(!components.iter().any(|c| c.name == "node"));
        assert!(!components.iter().any(|c| c.name == "java"));
    }

    #[test]
    fn test_service_assertions_nginx() {
        let components = vec![InstalledComponent {
            name: "nginx".to_string(),
            kind: ComponentKind::WebServer,
            source_line: 3,
        }];
        let assertions = generate_service_assertions(&components);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/etc/nginx/nginx.conf"
        )));
    }
}
