use crate::config::ServicePattern;
use crate::parser::CommandForm;
use crate::Confidence;

use super::model::{
    AssertionKind, ComponentKind, ContractAssertion, InstalledComponent, PackageManager,
};
use regex::Regex;
use std::sync::LazyLock;

// Each install regex captures the package list lazily and terminates it at the
// next shell boundary — `&&`, `||`, `;`, `|`, a background `&`, or a subshell
// `(`/`)` — or end of string. Bounding on all of these (not just `&&`/`$`)
// keeps shell control syntax out of the captured package names, both for the
// first invocation and for every later one scanned by `captures_iter`.
static APT_INSTALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"apt-get\s+install\s+(?:-y\s+)?(.+?)(?:\s*[;|&()]|\s*$)").unwrap()
});
static APK_ADD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"apk\s+add\s+(?:--no-cache\s+)?(.+?)(?:\s*[;|&()]|\s*$)").unwrap()
});
static PIP_INSTALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"pip3?\s+install\s+(.+?)(?:\s*[;|&()]|\s*$)").unwrap());
static NPM_INSTALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"npm\s+(?:install|ci)(?:\s+(.+?))?(?:\s*[;|&()]|\s*$)").unwrap());
static COMPOSER_REQUIRE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"composer\s+require\s+(.+?)(?:\s*[;|&()]|\s*$)").unwrap());
static USERADD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:useradd|adduser)\s+(?:[^\s]+\s+)*?(\w+)\s*$").unwrap());
/// One row of service knowledge, unifying what used to be three parallel and
/// already-drifted encodings: component detection, service-assertion payloads,
/// and package version-command enrichment. Collapsing them here means adding or
/// correcting a service is a single-row edit, and a detected component can no
/// longer silently generate zero assertions (the postgres/mysql/php drift).
#[derive(Debug, Clone)]
pub struct ServiceRule {
    /// Canonical component name (e.g. "nginx").
    name: String,
    /// Regex matched against the lowercased RUN command to detect this
    /// component. `None` marks an enrichment-only row: the service is recognized
    /// by package name for a version command (via [`known_version_cmd`]) but is
    /// not itself detected as a component — this preserves the historical
    /// detection surface for package-only entries such as git, vim and nano.
    detect: Option<Regex>,
    /// Component classification; also selects the default assertion confidence.
    kind: ComponentKind,
    /// Confidence assigned to this service's generated assertions.
    confidence: Confidence,
    /// Config file whose existence is asserted when the component is detected.
    config_path: Option<String>,
    /// Version command asserted to exit 0 when the component is detected, and
    /// returned by [`known_version_cmd`] for this service's `packages`.
    version_cmd: Option<String>,
    /// Process asserted running when the component is detected. Unused by the
    /// built-in rules (none historically emitted a process check); populated by
    /// user-configured `service_patterns`.
    process: Option<String>,
    /// Package-manager package names that install this service, driving
    /// [`known_version_cmd`] enrichment of `PackageInstalled` assertions.
    packages: Vec<String>,
}

impl ServiceRule {
    fn new(name: &str, detect: Option<&str>, kind: ComponentKind) -> Self {
        let confidence = confidence_for(&kind);
        Self {
            name: name.to_string(),
            detect: detect.map(|p| Regex::new(p).expect("built-in service regex must compile")),
            kind,
            confidence,
            config_path: None,
            version_cmd: None,
            process: None,
            packages: Vec::new(),
        }
    }

    fn config(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    fn version(mut self, cmd: &str) -> Self {
        self.version_cmd = Some(cmd.to_string());
        self
    }

    fn packages(mut self, pkgs: &[&str]) -> Self {
        self.packages = pkgs.iter().map(|p| p.to_string()).collect();
        self
    }

    /// Provenance string matching the historical messages exactly: runtimes read
    /// "<name> runtime pattern", everything else "<name> service pattern".
    fn provenance(&self) -> String {
        let word = match self.kind {
            ComponentKind::Runtime => "runtime",
            _ => "service",
        };
        format!("{} {} pattern", self.name, word)
    }
}

/// Default assertion confidence by component kind, preserving the historical
/// levels: web servers and databases are Medium, everything else Low.
fn confidence_for(kind: &ComponentKind) -> Confidence {
    match kind {
        ComponentKind::WebServer | ComponentKind::Database => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// The single source of truth for built-in service knowledge.
///
/// Detected rows (those with a `detect` regex) must each carry at least one of
/// `config_path`/`version_cmd`/`process`, so every detectable component yields
/// an assertion — the invariant that the `known_services_*` consistency tests
/// pin. Enrichment-only rows (`detect: None`) exist solely so `known_version_cmd`
/// recognizes package names that are not themselves component-detected.
static BUILTIN_RULES: LazyLock<Vec<ServiceRule>> = LazyLock::new(|| {
    vec![
        ServiceRule::new("nginx", Some(r"\bnginx\b"), ComponentKind::WebServer)
            .config("/etc/nginx/nginx.conf")
            .version("nginx -v")
            .packages(&["nginx"]),
        ServiceRule::new("apache2", Some(r"\bapache2\b"), ComponentKind::WebServer)
            .version("apache2 -v"),
        ServiceRule::new("httpd", Some(r"\bhttpd\b"), ComponentKind::WebServer).version("httpd -v"),
        ServiceRule::new("python", Some(r"\bpython3?\b"), ComponentKind::Runtime)
            .version("python3 --version")
            .packages(&["python", "python3"]),
        ServiceRule::new("node", Some(r"\bnode(js)?\b"), ComponentKind::Runtime)
            .version("node --version")
            .packages(&["node", "nodejs"]),
        ServiceRule::new("java", Some(r"\bjava\b"), ComponentKind::Runtime)
            .version("java -version")
            .packages(&["java", "default-jre", "default-jdk"]),
        ServiceRule::new("ruby", Some(r"\bruby\b"), ComponentKind::Runtime)
            .version("ruby --version")
            .packages(&["ruby"]),
        ServiceRule::new("php", Some(r"\bphp\b"), ComponentKind::Runtime)
            .version("php --version")
            .packages(&["php"]),
        ServiceRule::new("go", Some(r"\b(go|golang)\b"), ComponentKind::Runtime)
            .version("go version"),
        ServiceRule::new("redis", Some(r"\bredis\b"), ComponentKind::Database)
            .version("redis-cli --version")
            .packages(&["redis", "redis-server"]),
        ServiceRule::new(
            "postgres",
            Some(r"\bpostgres(ql)?\b"),
            ComponentKind::Database,
        )
        .version("postgres --version")
        .packages(&["postgres", "postgresql"]),
        ServiceRule::new("mysql", Some(r"\bmysql\b"), ComponentKind::Database)
            .version("mysql --version")
            .packages(&["mysql-server"]),
        ServiceRule::new("curl", Some(r"\bcurl\b"), ComponentKind::Tool)
            .version("curl --version")
            .packages(&["curl"]),
        ServiceRule::new("wget", Some(r"\bwget\b"), ComponentKind::Tool)
            .version("wget --version")
            .packages(&["wget"]),
        // Enrichment-only rows: known by package name for a version command, but
        // deliberately not component-detected (matching the historical surface).
        ServiceRule::new("git", None, ComponentKind::Tool)
            .version("git --version")
            .packages(&["git"]),
        ServiceRule::new("vim", None, ComponentKind::Tool)
            .version("vim --version")
            .packages(&["vim"]),
        ServiceRule::new("nano", None, ComponentKind::Tool)
            .version("nano --version")
            .packages(&["nano"]),
        ServiceRule::new("composer", None, ComponentKind::Tool)
            .version("composer --version")
            .packages(&["composer"]),
    ]
});

/// Merge user-configured `service_patterns` over the built-in rules to form the
/// effective rule set for one extraction.
///
/// A user row whose `name` matches a built-in **replaces** that service's
/// generated assertions (reusing the built-in detection regex); a new name is
/// appended and detected by its own name as a whole word. User-configured
/// services are deliberate, trusted configuration, so they carry Medium
/// confidence and thus survive the default `standard` profile's filter — a
/// configured pattern that produced only filtered-out Low assertions would be
/// the very silent no-op this wiring exists to remove.
pub fn effective_service_rules(user_patterns: &[ServicePattern]) -> Vec<ServiceRule> {
    let mut rules: Vec<ServiceRule> = BUILTIN_RULES.clone();
    for pattern in user_patterns {
        // A nameless pattern cannot be matched (its `\b\b` regex would match
        // everything); skip it rather than taint every RUN line.
        if pattern.name.trim().is_empty() {
            continue;
        }
        if let Some(existing) = rules.iter_mut().find(|r| r.name == pattern.name) {
            existing.config_path = pattern.config_path.clone();
            existing.version_cmd = pattern.version_cmd.clone();
            existing.process = pattern.process.clone();
            existing.confidence = Confidence::Medium;
            if existing.detect.is_none() {
                existing.detect = Some(word_boundary_regex(&pattern.name));
            }
        } else {
            let mut rule = ServiceRule::new(&pattern.name, None, ComponentKind::Package);
            rule.detect = Some(word_boundary_regex(&pattern.name));
            rule.config_path = pattern.config_path.clone();
            rule.version_cmd = pattern.version_cmd.clone();
            rule.process = pattern.process.clone();
            rule.confidence = Confidence::Medium;
            rules.push(rule);
        }
    }
    rules
}

/// Compile a whole-token detection regex for a user service: the lowercased,
/// regex-escaped name delimited by a string boundary or any non-identifier
/// character on each side. This matches the configured name literally (never as
/// a pattern) and, unlike a bare `\b...\b`, still anchors correctly for names
/// whose first or last character is not a word character (e.g. `c++`), which a
/// word boundary would silently fail to match.
fn word_boundary_regex(name: &str) -> Regex {
    let escaped = regex::escape(&name.to_lowercase());
    Regex::new(&format!(r"(?:^|[^0-9A-Za-z_]){escaped}(?:$|[^0-9A-Za-z_])"))
        .expect("an escaped literal is always a valid regex")
}

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

/// Detect installed components from a RUN command, using the built-in rules.
pub fn detect_installed_components(cmd: &CommandForm) -> Vec<InstalledComponent> {
    detect_components_with(cmd, &BUILTIN_RULES)
}

/// Detect installed components from a RUN command against an explicit rule set,
/// so user-configured `service_patterns` participate in detection too.
pub(crate) fn detect_components_with(
    cmd: &CommandForm,
    rules: &[ServiceRule],
) -> Vec<InstalledComponent> {
    let cmd_str = cmd.to_string_lossy().to_lowercase();
    let mut components = Vec::new();

    for rule in rules {
        if let Some(pattern) = &rule.detect {
            if pattern.is_match(&cmd_str) {
                components.push(InstalledComponent {
                    name: rule.name.clone(),
                    kind: rule.kind.clone(),
                    source_line: 0, // Will be set by caller
                });
            }
        }
    }

    dedupe_components(&mut components);
    components
}

/// Generate assertions for known service patterns, using the built-in rules.
pub fn generate_service_assertions(components: &[InstalledComponent]) -> Vec<ContractAssertion> {
    service_assertions_with(components, &BUILTIN_RULES)
}

/// Generate service assertions against an explicit rule set. Each detected
/// component contributes, in a fixed order, a config-file, a version-command and
/// a process assertion for whichever of those its rule defines — so the output
/// is derived entirely from the one table rather than a hand-maintained match.
pub(crate) fn service_assertions_with(
    components: &[InstalledComponent],
    rules: &[ServiceRule],
) -> Vec<ContractAssertion> {
    let mut assertions = Vec::new();

    for component in components {
        let Some(rule) = rules.iter().find(|r| r.name == component.name) else {
            continue;
        };
        let provenance = rule.provenance();

        if let Some(path) = &rule.config_path {
            assertions.push(ContractAssertion::new(
                AssertionKind::FileExists {
                    path: path.clone(),
                    filetype: Some("file".to_string()),
                    mode: None,
                },
                provenance.clone(),
                component.source_line,
                rule.confidence,
            ));
        }
        if let Some(cmd) = &rule.version_cmd {
            assertions.push(ContractAssertion::new(
                AssertionKind::CommandExit {
                    command: cmd.clone(),
                    exit_status: 0,
                },
                provenance.clone(),
                component.source_line,
                rule.confidence,
            ));
        }
        if let Some(process) = &rule.process {
            assertions.push(ContractAssertion::new(
                AssertionKind::ProcessRunning {
                    name: process.clone(),
                },
                provenance.clone(),
                component.source_line,
                rule.confidence,
            ));
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

/// Optional enrichment: known version-check commands for well-known packages,
/// derived from the one [`BUILTIN_RULES`] table via each rule's `packages`.
/// Returns `None` for packages where only the package-manager check is appropriate.
fn known_version_cmd(pkg: &str) -> Option<String> {
    BUILTIN_RULES
        .iter()
        .find(|rule| rule.packages.iter().any(|p| p == pkg))
        .and_then(|rule| rule.version_cmd.clone())
}

fn extract_package_assertions(
    assertions: &mut Vec<ContractAssertion>,
    command: &str,
    source_line: usize,
    pattern: &Regex,
    detector: fn(&str, usize) -> Option<ContractAssertion>,
) {
    // Iterate over every match so repeated same-manager invocations in one
    // RUN line (e.g. `apt-get install -y git && apt-get install -y curl`) are
    // all scanned, not just the first. Each regex's package-list capture
    // terminates at the next `&&` or end of string, so successive matches
    // delimit each invocation.
    for captures in pattern.captures_iter(command) {
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

fn make_package_assertion(
    pkg_name: &str,
    manager: PackageManager,
    provenance_prefix: &str,
    source_line: usize,
) -> ContractAssertion {
    ContractAssertion::new(
        AssertionKind::PackageInstalled {
            package: pkg_name.to_string(),
            manager,
            version_cmd: known_version_cmd(pkg_name),
        },
        format!("{} {}", provenance_prefix, pkg_name),
        source_line,
        Confidence::Low,
    )
}

fn detect_apt_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if is_low_value_package(pkg) {
        return None;
    }
    Some(make_package_assertion(
        pkg,
        PackageManager::Apt,
        "RUN apt-get install",
        source_line,
    ))
}

fn detect_apk_package(pkg: &str, source_line: usize) -> Option<ContractAssertion> {
    if is_low_value_package(pkg) {
        return None;
    }
    Some(make_package_assertion(
        pkg,
        PackageManager::Apk,
        "RUN apk add",
        source_line,
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
    Some(make_package_assertion(
        pkg_name,
        PackageManager::Pip,
        "RUN pip install",
        source_line,
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
    Some(make_package_assertion(
        pkg_name,
        PackageManager::Npm,
        "RUN npm install",
        source_line,
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
    Some(make_package_assertion(
        pkg_name,
        PackageManager::Composer,
        "RUN composer require",
        source_line,
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
    fn test_detect_multiple_apt_installs_in_one_run() {
        let cmd = CommandForm::Shell(
            "apt-get update && apt-get install -y git && apt-get install -y curl".to_string(),
        );
        let assertions = analyze_run_command(&cmd, 5);
        assert!(
            assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::PackageInstalled {
                    package,
                    manager: PackageManager::Apt,
                    ..
                } if package == "git"
            )),
            "first apt-get install should be detected"
        );
        assert!(
            assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::PackageInstalled {
                    package,
                    manager: PackageManager::Apt,
                    ..
                } if package == "curl"
            )),
            "second apt-get install should also be detected"
        );
    }

    #[test]
    fn test_detect_multiple_apk_adds_in_one_run() {
        let cmd =
            CommandForm::Shell("apk add --no-cache git && apk add --no-cache curl".to_string());
        let assertions = analyze_run_command(&cmd, 5);
        assert!(
            assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::PackageInstalled {
                    package,
                    manager: PackageManager::Apk,
                    ..
                } if package == "git"
            )),
            "first apk add should be detected"
        );
        assert!(
            assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::PackageInstalled {
                    package,
                    manager: PackageManager::Apk,
                    ..
                } if package == "curl"
            )),
            "second apk add should also be detected"
        );
    }

    #[test]
    fn test_install_capture_stops_at_shell_boundaries() {
        // A later same-manager install ending at a shell boundary other than
        // `&&` (a subshell close, or `;` inside if/then/fi) must not capture
        // shell syntax as part of the package name.
        for cmd_str in [
            "apt-get install -y git && (apt-get install -y curl)",
            "apt-get install -y git ; then apt-get install -y curl ; fi",
        ] {
            let cmd = CommandForm::Shell(cmd_str.to_string());
            let assertions = analyze_run_command(&cmd, 5);
            // The real package names are present...
            assert!(
                assertions.iter().any(|a| matches!(
                    &a.kind,
                    AssertionKind::PackageInstalled { package, .. } if package == "curl"
                )),
                "curl should be detected cleanly in: {cmd_str}"
            );
            // ...and no assertion carries shell punctuation as a package name.
            assert!(
                assertions.iter().all(|a| {
                    if let AssertionKind::PackageInstalled { package, .. } = &a.kind {
                        !package.contains([';', '|', '&', '(', ')'])
                    } else {
                        true
                    }
                }),
                "no package name should contain shell syntax in: {cmd_str}"
            );
        }
    }

    #[test]
    fn test_cross_manager_installs_still_detected() {
        // Pins the already-working cross-manager behavior against regressions.
        let cmd = CommandForm::Shell("apt-get install -y git && pip install flask".to_string());
        let assertions = analyze_run_command(&cmd, 5);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Apt,
                ..
            } if package == "git"
        )));
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::PackageInstalled {
                package,
                manager: PackageManager::Pip,
                ..
            } if package == "flask"
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
        // The config-file and version-command assertions, in that fixed order,
        // both at Medium confidence with the historical provenance string.
        assert!(matches!(
            &assertions[0].kind,
            AssertionKind::FileExists { path, filetype, .. }
                if path == "/etc/nginx/nginx.conf" && filetype.as_deref() == Some("file")
        ));
        assert!(matches!(
            &assertions[1].kind,
            AssertionKind::CommandExit { command, exit_status: 0 } if command == "nginx -v"
        ));
        assert!(
            assertions
                .iter()
                .all(|a| a.confidence == Confidence::Medium
                    && a.provenance == "nginx service pattern")
        );
    }

    /// Helper: the service assertions a single named component would generate
    /// against the built-in rules.
    fn builtin_assertions_for(name: &str, kind: ComponentKind) -> Vec<ContractAssertion> {
        service_assertions_with(
            &[InstalledComponent {
                name: name.to_string(),
                kind,
                source_line: 0,
            }],
            &BUILTIN_RULES,
        )
    }

    #[test]
    fn test_every_detected_service_generates_at_least_one_assertion() {
        // The invariant that would have caught the postgres/mysql/php drift:
        // a component that can be detected must never produce zero assertions.
        for rule in BUILTIN_RULES.iter() {
            if rule.detect.is_none() {
                continue; // enrichment-only rows are intentionally non-detected
            }
            let assertions = builtin_assertions_for(&rule.name, rule.kind.clone());
            assert!(
                !assertions.is_empty(),
                "detected service '{}' generated no assertions",
                rule.name
            );
        }
    }

    #[test]
    fn test_builtin_detection_surface_is_the_expected_set() {
        // Pins exactly which services are component-detected, so adding or
        // dropping a detectable row is a deliberate, reviewed change.
        let mut detected: Vec<&str> = BUILTIN_RULES
            .iter()
            .filter(|r| r.detect.is_some())
            .map(|r| r.name.as_str())
            .collect();
        detected.sort_unstable();
        let mut expected = vec![
            "apache2", "curl", "go", "httpd", "java", "mysql", "nginx", "node", "php", "postgres",
            "python", "redis", "ruby", "wget",
        ];
        expected.sort_unstable();
        assert_eq!(detected, expected, "detection surface drifted");
    }

    #[test]
    fn test_orphaned_services_now_generate_assertions() {
        // The core drift fix (#25): these services were detected as components
        // but historically fell through to zero assertions. Each must now emit
        // its version-command check.
        let cases = [
            ("postgres", ComponentKind::Database, "postgres --version"),
            ("mysql", ComponentKind::Database, "mysql --version"),
            ("php", ComponentKind::Runtime, "php --version"),
            ("ruby", ComponentKind::Runtime, "ruby --version"),
            ("go", ComponentKind::Runtime, "go version"),
            ("curl", ComponentKind::Tool, "curl --version"),
            ("wget", ComponentKind::Tool, "wget --version"),
        ];
        for (name, kind, expected_cmd) in cases {
            let assertions = builtin_assertions_for(name, kind);
            assert!(
                assertions.iter().any(|a| matches!(
                    &a.kind,
                    AssertionKind::CommandExit { command, exit_status: 0 } if command == expected_cmd
                )),
                "service '{name}' should emit `{expected_cmd}`, got: {assertions:?}"
            );
        }
    }

    #[test]
    fn test_detected_postgres_mysql_php_through_run_command() {
        // End-to-end through detection: a RUN that installs these services now
        // yields their service assertions, where before it yielded none.
        for (pkg, expected_cmd) in [
            ("postgresql", "postgres --version"),
            ("mysql-server", "mysql --version"),
            ("php", "php --version"),
        ] {
            let cmd = CommandForm::Shell(format!("apt-get install -y {pkg}"));
            let components = detect_installed_components(&cmd);
            let assertions = generate_service_assertions(&components);
            assert!(
                assertions.iter().any(|a| matches!(
                    &a.kind,
                    AssertionKind::CommandExit { command, .. } if command == expected_cmd
                )),
                "installing '{pkg}' should produce `{expected_cmd}`, got: {assertions:?}"
            );
        }
    }

    #[test]
    fn test_known_version_cmd_mapping_is_preserved() {
        // `known_version_cmd` now derives from the unified table; its output must
        // remain byte-for-byte what the hand-written match returned, including
        // the package aliases and the deliberate gaps (apache/go/bare-mysql).
        let expected: &[(&str, Option<&str>)] = &[
            ("nginx", Some("nginx -v")),
            ("curl", Some("curl --version")),
            ("wget", Some("wget --version")),
            ("python", Some("python3 --version")),
            ("python3", Some("python3 --version")),
            ("node", Some("node --version")),
            ("nodejs", Some("node --version")),
            ("git", Some("git --version")),
            ("java", Some("java -version")),
            ("default-jre", Some("java -version")),
            ("default-jdk", Some("java -version")),
            ("ruby", Some("ruby --version")),
            ("php", Some("php --version")),
            ("redis", Some("redis-cli --version")),
            ("redis-server", Some("redis-cli --version")),
            ("postgres", Some("postgres --version")),
            ("postgresql", Some("postgres --version")),
            ("mysql-server", Some("mysql --version")),
            ("vim", Some("vim --version")),
            ("nano", Some("nano --version")),
            ("composer", Some("composer --version")),
            // Deliberate gaps preserved exactly: no enrichment for these.
            ("mysql", None),
            ("go", None),
            ("golang", None),
            ("apache2", None),
            ("httpd", None),
            ("unknown-pkg", None),
        ];
        for (pkg, want) in expected {
            assert_eq!(
                known_version_cmd(pkg).as_deref(),
                *want,
                "known_version_cmd({pkg}) drifted"
            );
        }
    }

    #[test]
    fn test_enrichment_only_rows_are_not_detected() {
        // git/vim/nano/composer enrich package version commands but must not be
        // detected as components (preserving the historical detection surface).
        for pkg in ["git", "vim", "nano", "composer"] {
            let cmd = CommandForm::Shell(format!("apt-get install -y {pkg}"));
            let components = detect_installed_components(&cmd);
            assert!(
                !components.iter().any(|c| c.name == pkg),
                "'{pkg}' must not be component-detected"
            );
        }
    }

    #[test]
    fn test_user_service_pattern_is_detected_and_asserted() {
        // A user-configured service is detected by its name and emits the
        // configured process/config/version assertions at Medium confidence
        // (so it survives the default `standard` profile filter).
        let patterns = vec![ServicePattern {
            name: "myservice".to_string(),
            process: Some("myserviced".to_string()),
            config_path: Some("/etc/myservice.conf".to_string()),
            version_cmd: Some("myservice --version".to_string()),
        }];
        let rules = effective_service_rules(&patterns);

        let cmd = CommandForm::Shell("apt-get install -y myservice".to_string());
        let components = detect_components_with(&cmd, &rules);
        assert!(
            components.iter().any(|c| c.name == "myservice"),
            "user service should be detected, got: {components:?}"
        );

        let assertions = service_assertions_with(&components, &rules);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/etc/myservice.conf"
        )));
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::CommandExit { command, .. } if command == "myservice --version"
        )));
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::ProcessRunning { name } if name == "myserviced"
        )));
        assert!(
            assertions
                .iter()
                .all(|a| a.confidence == Confidence::Medium),
            "user-configured assertions should be Medium confidence"
        );
    }

    #[test]
    fn test_user_service_pattern_overrides_builtin() {
        // A user row named like a built-in replaces that service's assertions
        // rather than duplicating it; detection still works via the built-in regex.
        let patterns = vec![ServicePattern {
            name: "nginx".to_string(),
            process: Some("nginx".to_string()),
            config_path: Some("/custom/nginx.conf".to_string()),
            version_cmd: None,
        }];
        let rules = effective_service_rules(&patterns);
        let nginx_rules = rules.iter().filter(|r| r.name == "nginx").count();
        assert_eq!(nginx_rules, 1, "override must not duplicate the nginx row");

        let cmd = CommandForm::Shell("apt-get install -y nginx".to_string());
        let components = detect_components_with(&cmd, &rules);
        let assertions = service_assertions_with(&components, &rules);
        assert!(assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/custom/nginx.conf"
        )));
        // The built-in default config path and version command are replaced.
        assert!(!assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/etc/nginx/nginx.conf"
        )));
        assert!(!assertions
            .iter()
            .any(|a| matches!(&a.kind, AssertionKind::CommandExit { .. })));
    }

    #[test]
    fn test_nameless_user_pattern_is_ignored() {
        // A blank name would compile to a `\b\b` regex matching every command;
        // it must be skipped so it cannot taint every RUN line.
        let patterns = vec![ServicePattern {
            name: "   ".to_string(),
            process: Some("x".to_string()),
            config_path: None,
            version_cmd: None,
        }];
        let rules = effective_service_rules(&patterns);
        let cmd = CommandForm::Shell("apt-get install -y nginx".to_string());
        let components = detect_components_with(&cmd, &rules);
        // Only the real nginx component is detected; no blank-named ghost.
        assert!(components.iter().all(|c| !c.name.trim().is_empty()));
        assert!(components.iter().any(|c| c.name == "nginx"));
    }

    #[test]
    fn test_user_pattern_name_is_matched_literally_not_as_regex() {
        // Regex metacharacters in a configured name are escaped, so the name is
        // matched literally rather than interpreted as a pattern.
        let patterns = vec![ServicePattern {
            name: "c++".to_string(),
            process: None,
            config_path: None,
            version_cmd: Some("c++ --version".to_string()),
        }];
        let rules = effective_service_rules(&patterns);
        // The literal token "c++" is present...
        let hit = CommandForm::Shell("apt-get install -y c++".to_string());
        assert!(detect_components_with(&hit, &rules)
            .iter()
            .any(|c| c.name == "c++"));
        // ...but a bare "c" (which `c++` as a regex could match) is not.
        let miss = CommandForm::Shell("apt-get install -y c".to_string());
        assert!(!detect_components_with(&miss, &rules)
            .iter()
            .any(|c| c.name == "c++"));
    }
}
