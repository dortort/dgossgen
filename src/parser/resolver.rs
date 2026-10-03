use std::collections::{HashMap, HashSet};

use super::ast::ArgInstruction;

/// Internal marker the parser substitutes for an escaped `\$` in an ENV value so
/// resolution treats it as a literal `$` instead of a variable reference. Uses a
/// Unicode noncharacter (never valid for interchange) to avoid colliding with
/// real Dockerfile text.
pub(crate) const ESCAPED_DOLLAR: char = '\u{FDD0}';

/// Outcome of resolving a string against the variables in scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub value: String,
    /// An undefined, defaultless reference was left verbatim in `value`.
    pub unresolved: bool,
    /// A secret-derived variable was substituted into `value`.
    pub secret: bool,
}

/// Resolve ARG/ENV variable references in a stage.
/// Best-effort substitution: unknown variables remain as ${VAR} literals.
#[derive(Default)]
pub struct VariableResolver {
    vars: HashMap<String, String>,
    /// Names locked by a build-arg or ENV, outranking an ARG default (a re-declared one may win).
    locked: HashSet<String>,
    /// Names set to an unknown value (e.g. `ENV DIR=$MISSING`); resolve unresolved, no defaults.
    tainted: HashSet<String>,
    /// Names whose value came from a secret-named build-arg, directly or via another binding.
    secret: HashSet<String>,
}

impl VariableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load CLI --build-arg values (locked against a later ARG default); `is_secret` keys are secret.
    pub fn load_build_args(&mut self, args: &[(String, String)], is_secret: impl Fn(&str) -> bool) {
        for (k, v) in args {
            self.vars.insert(k.clone(), v.clone());
            self.locked.insert(k.clone());
            if is_secret(k) {
                self.secret.insert(k.clone());
            }
        }
    }

    /// Load pre-FROM ARG defaults in order, so one default may reference an earlier global.
    pub fn load_global_args(&mut self, args: &[ArgInstruction]) {
        for arg in args {
            if self.locked.contains(&arg.name) {
                continue;
            }
            if let Some(default) = &arg.default {
                let resolved = self.resolve_checked(default);
                if resolved.unresolved {
                    self.vars.remove(&arg.name);
                    self.secret.remove(&arg.name);
                } else {
                    self.bind(&arg.name, resolved.value, resolved.secret);
                }
            }
        }
    }

    /// Declare a stage ARG default; a locked value wins, else it overwrites any inherited default.
    pub fn declare_arg(&mut self, name: &str, default: Option<&str>, secret: bool) {
        if self.locked.contains(name) {
            return;
        }
        if let Some(val) = default {
            self.bind(name, val.to_string(), secret);
        }
    }

    /// Whether a name is locked (so a failed re-declaration isn't treated as unresolved).
    pub fn is_locked(&self, name: &str) -> bool {
        self.locked.contains(name)
    }

    /// Bind an ENV value, overwriting any prior binding and locking it against a later ARG.
    pub fn set_var(&mut self, key: &str, value: &str, secret: bool) {
        self.bind(key, value.to_string(), secret);
        self.locked.insert(key.to_string());
        self.tainted.remove(key);
    }

    fn bind(&mut self, key: &str, value: String, secret: bool) {
        self.vars.insert(key.to_string(), value);
        if secret {
            self.secret.insert(key.to_string());
        } else {
            self.secret.remove(key);
        }
    }

    /// Remove a binding and its lock/taint; used when an ARG re-declaration was unresolved.
    pub fn unset(&mut self, key: &str) {
        self.locked.remove(key);
        self.tainted.remove(key);
        self.secret.remove(key);
        self.vars.remove(key);
    }

    /// Mark a var set-but-unknown (unresolvable ENV); locks the name but resolves unresolved.
    pub fn taint(&mut self, key: &str) {
        self.vars.remove(key);
        self.secret.remove(key);
        self.locked.insert(key.to_string());
        self.tainted.insert(key.to_string());
    }

    /// Resolve ${VAR} and $VAR references in a string.
    pub fn resolve(&self, input: &str) -> String {
        self.resolve_checked(input).value
    }

    /// Like [`VariableResolver::resolve`], also flagging unresolved and secret-derived references.
    pub fn resolve_checked(&self, input: &str) -> Resolution {
        let mut result = String::with_capacity(input.len());
        let mut unresolved = false;
        let mut secret = false;
        let mut iter = input.char_indices().peekable();

        while let Some((idx, ch)) = iter.next() {
            if ch == ESCAPED_DOLLAR {
                result.push('$');
                continue;
            }

            if ch != '$' {
                result.push(ch);
                continue;
            }

            let Some((next_idx, next_ch)) = iter.peek().copied() else {
                result.push('$');
                continue;
            };

            if next_ch == '{' {
                iter.next(); // consume '{'
                let expr_start = next_idx + next_ch.len_utf8();
                let mut close_idx = None;

                for (pos, current) in iter.by_ref() {
                    if current == '}' {
                        close_idx = Some(pos);
                        break;
                    }
                }

                if let Some(end_idx) = close_idx {
                    let var_expr = &input[expr_start..end_idx];
                    let (var_name, default) = if let Some(sep) = var_expr.find(":-") {
                        (&var_expr[..sep], Some(&var_expr[sep + 2..]))
                    } else if let Some(sep) = var_expr.find('-') {
                        (&var_expr[..sep], Some(&var_expr[sep + 1..]))
                    } else {
                        (var_expr, None)
                    };

                    if let Some(val) = self.vars.get(var_name) {
                        result.push_str(val);
                        secret |= self.secret.contains(var_name);
                    } else if self.tainted.contains(var_name) {
                        // Tainted: its dash-default doesn't apply since the name is set.
                        result.push_str(&input[idx..end_idx + 1]);
                        unresolved = true;
                    } else if let Some(def) = default {
                        // Resolve the default recursively so nested `$OTHER` refs expand too.
                        let resolved_def = self.resolve_checked(def);
                        result.push_str(&resolved_def.value);
                        unresolved |= resolved_def.unresolved;
                        secret |= resolved_def.secret;
                    } else {
                        result.push_str(&input[idx..end_idx + 1]);
                        unresolved = true;
                    }
                } else {
                    // Unterminated `${...}`: preserve the tail literally and flag it as unresolved.
                    result.push_str(&input[idx..]);
                    unresolved = true;
                    break;
                }
                continue;
            }

            if next_ch.is_ascii_alphabetic() || next_ch == '_' {
                iter.next(); // consume first var-name char
                let name_start = next_idx;
                let mut name_end = name_start + next_ch.len_utf8();

                while let Some((pos, current)) = iter.peek().copied() {
                    if current.is_ascii_alphanumeric() || current == '_' {
                        name_end = pos + current.len_utf8();
                        iter.next();
                    } else {
                        break;
                    }
                }

                let var_name = &input[name_start..name_end];
                if let Some(val) = self.vars.get(var_name) {
                    result.push_str(val);
                    secret |= self.secret.contains(var_name);
                } else {
                    result.push_str(&input[idx..name_end]);
                    unresolved = true;
                }
                continue;
            }

            result.push('$');
        }

        Resolution {
            value: result,
            unresolved,
            secret,
        }
    }

    /// Check if a string contains unresolved variables.
    pub fn has_unresolved(&self, input: &str) -> bool {
        self.resolve_checked(input).unresolved
    }

    /// Get current variable map.
    pub fn variables(&self) -> &HashMap<String, String> {
        &self.vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_simple_var() {
        let mut resolver = VariableResolver::new();
        resolver.vars.insert("PORT".to_string(), "8080".to_string());
        assert_eq!(resolver.resolve("$PORT"), "8080");
        assert_eq!(resolver.resolve("${PORT}"), "8080");
    }

    #[test]
    fn test_resolve_default() {
        let resolver = VariableResolver::new();
        assert_eq!(resolver.resolve("${PORT:-3000}"), "3000");
    }

    #[test]
    fn test_resolve_unknown_kept() {
        let resolver = VariableResolver::new();
        assert_eq!(resolver.resolve("${UNKNOWN}"), "${UNKNOWN}");
        assert!(resolver.has_unresolved("${UNKNOWN}"));
    }

    #[test]
    fn test_resolve_mixed() {
        let mut resolver = VariableResolver::new();
        resolver.vars.insert("APP".to_string(), "myapp".to_string());
        assert_eq!(resolver.resolve("/opt/$APP/config"), "/opt/myapp/config");
    }

    #[test]
    fn test_resolve_unicode_input_without_panicking() {
        let mut resolver = VariableResolver::new();
        resolver
            .vars
            .insert("APP".to_string(), "servico".to_string());
        assert_eq!(resolver.resolve("π/$APP/ß"), "π/servico/ß");
    }

    #[test]
    fn test_resolve_escaped_dollar_marker_stays_literal() {
        // The marker must resolve to a literal `$` and must NOT expand, even when
        // a matching variable is defined.
        let mut resolver = VariableResolver::new();
        resolver
            .vars
            .insert("ROOT".to_string(), "/data".to_string());
        assert_eq!(resolver.resolve(&format!("{ESCAPED_DOLLAR}ROOT")), "$ROOT");
    }

    #[test]
    fn test_has_unresolved_ignores_literal_dollar_usage() {
        let resolver = VariableResolver::new();
        assert!(!resolver.has_unresolved("Price is $5.00"));
        assert!(!resolver.has_unresolved("echo $$"));
        assert!(!resolver.has_unresolved("status is $?"));
    }

    #[test]
    fn test_resolve_checked_default_with_defined_nested_var() {
        let mut resolver = VariableResolver::new();
        resolver.vars.insert("SUB".to_string(), "inner".to_string());
        // The default is resolved recursively, and the reference is satisfied.
        let resolved = resolver.resolve_checked("${MISSING:-/opt/$SUB}");
        assert_eq!(resolved.value, "/opt/inner");
        assert!(!resolved.unresolved);
    }

    #[test]
    fn test_resolve_checked_default_with_undefined_nested_var_is_unresolved() {
        let resolver = VariableResolver::new();
        // The default text's own unresolved reference flags the whole result unresolved.
        let resolved = resolver.resolve_checked("${MISSING:-/x$BAR}");
        assert_eq!(resolved.value, "/x$BAR");
        assert!(resolved.unresolved);
    }

    #[test]
    fn test_resolve_checked_unterminated_brace_is_unresolved() {
        let resolver = VariableResolver::new();
        let resolved = resolver.resolve_checked("/a/${UNTERM");
        assert_eq!(resolved.value, "/a/${UNTERM");
        assert!(resolved.unresolved);
    }

    #[test]
    fn test_tainted_var_reference_is_unresolved_ignoring_default() {
        let mut resolver = VariableResolver::new();
        resolver.taint("DIR");
        // A set-but-unknown var is unresolved for a bare ref and for both default forms.
        assert!(resolver.resolve_checked("$DIR").unresolved);
        assert!(resolver.resolve_checked("/srv/${DIR-fallback}").unresolved);
        assert!(resolver.resolve_checked("/srv/${DIR:-fallback}").unresolved);
        // A later resolvable binding clears the taint.
        resolver.set_var("DIR", "real", false);
        let resolved = resolver.resolve_checked("/srv/${DIR-fallback}");
        assert_eq!(resolved.value, "/srv/real");
        assert!(!resolved.unresolved);
    }

    fn resolver_with_secret_build_arg() -> VariableResolver {
        let mut resolver = VariableResolver::new();
        resolver.load_build_args(
            &[
                ("DB_PASSWORD".to_string(), "s3cr3t".to_string()),
                ("APP_PORT".to_string(), "8080".to_string()),
            ],
            |k| k.contains("PASSWORD"),
        );
        resolver
    }

    #[test]
    fn test_secret_build_arg_reference_is_flagged_secret() {
        let resolver = resolver_with_secret_build_arg();
        for input in [
            "$DB_PASSWORD",
            "/srv/${DB_PASSWORD}",
            "${NOPE:-$DB_PASSWORD}",
        ] {
            let resolved = resolver.resolve_checked(input);
            assert!(resolved.secret, "{input} should be secret-derived");
            assert!(!resolved.unresolved);
        }
        assert!(!resolver.resolve_checked("$APP_PORT").secret);
        assert!(!resolver.resolve_checked("/literal").secret);
    }

    #[test]
    fn test_secret_taint_propagates_through_bindings_and_clears_on_literal_rebind() {
        let mut resolver = resolver_with_secret_build_arg();
        let dsn = resolver.resolve_checked("/srv/$DB_PASSWORD");
        resolver.set_var("DSN", &dsn.value, dsn.secret);
        let alias = resolver.resolve_checked("$DSN");
        resolver.declare_arg("ALIAS", Some(&alias.value), alias.secret);
        assert!(resolver.resolve_checked("$ALIAS").secret);

        resolver.set_var("DB_PASSWORD", "/literal", false);
        assert!(!resolver.resolve_checked("$DB_PASSWORD").secret);
        assert!(resolver.resolve_checked("$DSN").secret);
    }

    #[test]
    fn test_locked_secret_build_arg_keeps_taint_over_arg_default() {
        let mut resolver = resolver_with_secret_build_arg();
        resolver.declare_arg("DB_PASSWORD", Some("dockerfile-default"), false);
        let resolved = resolver.resolve_checked("$DB_PASSWORD");
        assert_eq!(resolved.value, "s3cr3t");
        assert!(resolved.secret);
    }
}
