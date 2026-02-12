use crate::parser::CommandForm;
use crate::Confidence;

use super::model::*;
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

/// Package install pattern detectors.
type PatternDetector = Box<dyn Fn(&str, usize) -> Option<ContractAssertion>>;

fn package_install_patterns() -> Vec<(Regex, PatternDetector)> {
    vec![
        // apt-get install
        (
            Regex::new(r"apt-get\s+install\s+(?:-y\s+)?(.+?)(?:\s*&&|\s*$)").unwrap(),
            Box::new(|pkg: &str, line: usize| -> Option<ContractAssertion> {
                let known = known_apt_package_version_cmd(pkg)?;
                Some(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: known,
                        exit_status: 0,
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
                let known = known_apk_package_version_cmd(pkg)?;
                Some(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: known,
                        exit_status: 0,
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
            Box::new(|_pkg: &str, line: usize| -> Option<ContractAssertion> {
                Some(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "python3 --version".to_string(),
                        exit_status: 0,
                    },
                    provenance: "RUN pip install".to_string(),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
        // npm install
        (
            Regex::new(r"npm\s+(?:install|ci)(?:\s+(.+?))?(?:\s*&&|\s*$)").unwrap(),
            Box::new(|_pkg: &str, line: usize| -> Option<ContractAssertion> {
                Some(ContractAssertion {
                    kind: AssertionKind::CommandExit {
                        command: "node --version".to_string(),
                        exit_status: 0,
                    },
                    provenance: "RUN npm install".to_string(),
                    source_line: line,
                    confidence: Confidence::Low,
                })
            }),
        ),
    ]
}

fn known_apt_package_version_cmd(pkg: &str) -> Option<String> {
    match pkg {
        "nginx" => Some("nginx -v".to_string()),
        "curl" => Some("curl --version".to_string()),
        "wget" => Some("wget --version".to_string()),
        "python3" => Some("python3 --version".to_string()),
        "nodejs" | "node" => Some("node --version".to_string()),
        "git" => Some("git --version".to_string()),
        "vim" | "nano" | "ca-certificates" | "gnupg" => None, // Skip low-value
        _ => None,
    }
}

fn known_apk_package_version_cmd(pkg: &str) -> Option<String> {
    match pkg {
        "nginx" => Some("nginx -v".to_string()),
        "curl" => Some("curl --version".to_string()),
        "wget" => Some("wget --version".to_string()),
        "python3" => Some("python3 --version".to_string()),
        "nodejs" | "node" => Some("node --version".to_string()),
        "git" => Some("git --version".to_string()),
        _ => None,
    }
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
            AssertionKind::CommandExit { command, .. } if command == "nginx -v"
        )));
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
