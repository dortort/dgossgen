use crate::parser::CommandForm;
use crate::Confidence;

use super::model::{
    AssertionKind, ComponentKind, ContractAssertion, InstalledComponent, PackageManager,
};
use regex::Regex;

/// Analyze a RUN command for installed packages and generate assertions.
pub fn analyze_run_command(cmd: &CommandForm, source_line: usize) -> Vec<ContractAssertion> {
    let cmd_str = cmd.to_string_lossy();
    let mut assertions = Vec::new();

    // Package manager installs
    for (pattern, detector) in package_install_patterns() {
        if let Some(captures) = pattern.captures(&cmd_str) {
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

    let patterns: Vec<(&str, &str, ComponentKind)> = vec![
        ("nginx", "nginx", ComponentKind::WebServer),
        ("apache2", "apache2", ComponentKind::WebServer),
        ("httpd", "httpd", ComponentKind::WebServer),
        ("python", "python", ComponentKind::Runtime),
        ("python3", "python3", ComponentKind::Runtime),
        ("node", "node", ComponentKind::Runtime),
        ("java", "java", ComponentKind::Runtime),
        ("ruby", "ruby", ComponentKind::Runtime),
        ("php", "php", ComponentKind::Runtime),
        ("go ", "go", ComponentKind::Runtime),
        ("golang", "golang", ComponentKind::Runtime),
        ("redis", "redis", ComponentKind::Database),
        ("postgres", "postgres", ComponentKind::Database),
        ("mysql", "mysql", ComponentKind::Database),
        ("curl", "curl", ComponentKind::Tool),
        ("wget", "wget", ComponentKind::Tool),
    ];

    for (pattern, name, kind) in patterns {
        if cmd_str.contains(pattern) {
            components.push(InstalledComponent {
                name: name.to_string(),
                kind,
                source_line: 0, // Will be set by caller
            });
        }
    }

    components
}

/// Generate assertions for known service patterns.
pub fn generate_service_assertions(components: &[InstalledComponent]) -> Vec<ContractAssertion> {
    let mut assertions = Vec::new();

    for component in components {
        match component.name.as_str() {
            "nginx" => {
                assertions.push(ContractAssertion {
                    kind: AssertionKind::FileExists {
                        path: "/etc/nginx/nginx.conf".to_string(),
                        filetype: Some("file".to_string()),
                        mode: None,
                    },
                    provenance: "nginx service pattern".to_string(),
                    source_line: component.source_line,
                    confidence: Confidence::Medium,
                });
                assertions.push(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "nginx -v".to_string(),
                        exit_status: 0,
                    },
                    provenance: "nginx service pattern".to_string(),
                    source_line: component.source_line,
                    confidence: Confidence::Medium,
                });
            }
            "apache2" | "httpd" => {
                let binary = if component.name == "apache2" {
                    "apache2"
                } else {
                    "httpd"
                };
                assertions.push(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: format!("{} -v", binary),
                        exit_status: 0,
                    },
                    provenance: format!("{} service pattern", component.name),
                    source_line: component.source_line,
                    confidence: Confidence::Medium,
                });
            }
            "python" | "python3" => {
                assertions.push(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "python3 --version".to_string(),
                        exit_status: 0,
                    },
                    provenance: "python runtime pattern".to_string(),
                    source_line: component.source_line,
                    confidence: Confidence::Low,
                });
            }
            "node" => {
                assertions.push(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "node --version".to_string(),
                        exit_status: 0,
                    },
                    provenance: "node runtime pattern".to_string(),
                    source_line: component.source_line,
                    confidence: Confidence::Low,
                });
            }
            "java" => {
                assertions.push(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "java -version".to_string(),
                        exit_status: 0,
                    },
                    provenance: "java runtime pattern".to_string(),
                    source_line: component.source_line,
                    confidence: Confidence::Low,
                });
            }
            "redis" => {
                assertions.push(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "redis-cli --version".to_string(),
                        exit_status: 0,
                    },
                    provenance: "redis service pattern".to_string(),
                    source_line: component.source_line,
                    confidence: Confidence::Medium,
                });
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

/// Package install pattern detectors.
type PatternDetector = Box<dyn Fn(&str, usize) -> Option<ContractAssertion>>;

fn package_install_patterns() -> Vec<(Regex, PatternDetector)> {
    vec![
        // apt-get install
        (
            Regex::new(r"apt-get\s+install\s+(?:-y\s+)?(.+?)(?:\s*&&|\s*$)").unwrap(),
            Box::new(|pkg: &str, line: usize| -> Option<ContractAssertion> {
                if is_low_value_package(pkg) {
                    return None;
                }
                Some(ContractAssertion {
                    kind: AssertionKind::PackageInstalled {
                        package: pkg.to_string(),
                        manager: PackageManager::Apt,
                        version_cmd: known_version_cmd(pkg),
                    },
                    provenance: format!("RUN apt-get install {}", pkg),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
        // apk add
        (
            Regex::new(r"apk\s+add\s+(?:--no-cache\s+)?(.+?)(?:\s*&&|\s*$)").unwrap(),
            Box::new(|pkg: &str, line: usize| -> Option<ContractAssertion> {
                if is_low_value_package(pkg) {
                    return None;
                }
                Some(ContractAssertion {
                    kind: AssertionKind::PackageInstalled {
                        package: pkg.to_string(),
                        manager: PackageManager::Apk,
                        version_cmd: known_version_cmd(pkg),
                    },
                    provenance: format!("RUN apk add {}", pkg),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
        // pip install
        (
            Regex::new(r"pip3?\s+install\s+(.+?)(?:\s*&&|\s*$)").unwrap(),
            Box::new(|pkg: &str, line: usize| -> Option<ContractAssertion> {
                // The general loop already strips leading dashes, so we see
                // flag remnants like "no-cache-dir", "r", "q" etc. Filter them.
                if is_pip_flag_remnant(pkg) {
                    return None;
                }
                // Skip requirements file references
                if pkg.ends_with(".txt") || pkg.ends_with(".cfg") || pkg.contains('/') || pkg == "." {
                    return None;
                }
                // Strip version specifiers (e.g. "flask==2.0" -> "flask")
                let pkg_name = pkg.split(&['=', '>', '<', '!', '~', '['][..]).next().unwrap_or(pkg);
                if pkg_name.is_empty() {
                    return None;
                }
                Some(ContractAssertion {
                    kind: AssertionKind::PackageInstalled {
                        package: pkg_name.to_string(),
                        manager: PackageManager::Pip,
                        version_cmd: known_version_cmd(pkg_name),
                    },
                    provenance: format!("RUN pip install {}", pkg_name),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
        // npm install (global or named packages)
        (
            Regex::new(r"npm\s+(?:install|ci)(?:\s+(.+?))?(?:\s*&&|\s*$)").unwrap(),
            Box::new(|pkg: &str, line: usize| -> Option<ContractAssertion> {
                // npm ci / npm install (no args) installs from package.json — no specific package to assert
                if pkg.is_empty() || pkg.starts_with('-') {
                    return None;
                }
                // Strip version specifiers (@scope/pkg@version -> @scope/pkg)
                let pkg_name = if pkg.starts_with('@') {
                    // Scoped package: @scope/name@version
                    if let Some(at_pos) = pkg[1..].find('@') {
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
                Some(ContractAssertion {
                    kind: AssertionKind::PackageInstalled {
                        package: pkg_name.to_string(),
                        manager: PackageManager::Npm,
                        version_cmd: known_version_cmd(pkg_name),
                    },
                    provenance: format!("RUN npm install {}", pkg_name),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
        // composer require (PHP)
        (
            Regex::new(r"composer\s+require\s+(.+?)(?:\s*&&|\s*$)").unwrap(),
            Box::new(|pkg: &str, line: usize| -> Option<ContractAssertion> {
                // Skip flags (remnants after dash-stripping)
                if is_composer_flag_remnant(pkg) {
                    return None;
                }
                // Composer packages are vendor/package — keep as-is
                // Strip version constraint if present (e.g. "monolog/monolog:^2.0" -> "monolog/monolog")
                let pkg_name = pkg.split(&[':', ' '][..]).next().unwrap_or(pkg);
                if pkg_name.is_empty() || !pkg_name.contains('/') {
                    // Valid composer packages always have vendor/name format
                    return None;
                }
                Some(ContractAssertion {
                    kind: AssertionKind::PackageInstalled {
                        package: pkg_name.to_string(),
                        manager: PackageManager::Composer,
                        version_cmd: None,
                    },
                    provenance: format!("RUN composer require {}", pkg_name),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
    ]
}

/// Detect user creation commands.
fn detect_user_creation(cmd_str: &str, source_line: usize) -> Option<ContractAssertion> {
    let useradd_re = Regex::new(r"(?:useradd|adduser)\s+(?:[^\s]+\s+)*?(\w+)\s*$").ok()?;
    if let Some(captures) = useradd_re.captures(cmd_str) {
        if let Some(username) = captures.get(1) {
            let name = username.as_str().to_string();
            // Filter out flags that look like usernames
            if !name.starts_with('-') {
                return Some(ContractAssertion {
                    kind: AssertionKind::UserExists {
                        username: name.clone(),
                    },
                    provenance: format!("RUN useradd/adduser {}", name),
                    source_line,
                    confidence: Confidence::Medium,
                });
            }
        }
    }
    None
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
            assertions.iter().all(|a| !matches!(
                &a.kind,
                AssertionKind::PackageInstalled { .. }
            )),
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
        let cmd = CommandForm::Shell("composer require --no-dev --prefer-dist monolog/monolog".to_string());
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
