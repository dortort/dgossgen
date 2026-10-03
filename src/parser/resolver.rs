use std::collections::{HashMap, HashSet};

use super::ast::ArgInstruction;

/// Internal marker the parser substitutes for an escaped `\$` in an ENV value so
/// resolution treats it as a literal `$` instead of a variable reference. Uses a
/// Unicode noncharacter (never valid for interchange) to avoid colliding with
/// real Dockerfile text.
pub(crate) const ESCAPED_DOLLAR: char = '\u{FDD0}';

/// Resolve ARG/ENV variable references in a stage.
/// Best-effort substitution: unknown variables remain as ${VAR} literals.
#[derive(Default)]
pub struct VariableResolver {
    vars: HashMap<String, String>,
    /// Names locked by a build-arg or ENV, outranking an ARG default (a re-declared one may win).
    locked: HashSet<String>,
    /// Names set to an unknown value (e.g. `ENV DIR=$MISSING`); resolve unresolved, no defaults.
    tainted: HashSet<String>,
    /// CLI `--build-arg` values awaiting their `ARG` declaration before they enter scope.
    /// Docker only binds a build arg at its global or stage `ARG`, not up front.
    supplied_build_args: HashMap<String, String>,
}

impl VariableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store CLI `--build-arg` values. They do not enter scope here: a build arg is
    /// bound only when its matching global or stage `ARG` declaration is reached
    /// (see [`VariableResolver::declare_arg`]), matching Docker's scoping. A value
    /// with no corresponding `ARG` declaration is never in scope.
    pub fn load_build_args(&mut self, args: &[(String, String)]) {
        for (k, v) in args {
            self.supplied_build_args.insert(k.clone(), v.clone());
        }
    }

    /// Whether a `--build-arg` value was supplied for `name` (whether or not it is yet in scope).
    pub fn has_supplied_build_arg(&self, name: &str) -> bool {
        self.supplied_build_args.contains_key(name)
    }

    /// Load pre-FROM ARG defaults in order, so one default may reference an earlier global.
    pub fn load_global_args(&mut self, args: &[ArgInstruction]) {
        for arg in args {
            if self.locked.contains(&arg.name) {
                continue;
            }
            // A supplied build arg enters scope at its global ARG declaration and
            // outranks the default (which Docker never evaluates in that case).
            if let Some(val) = self.supplied_build_args.get(&arg.name).cloned() {
                self.vars.insert(arg.name.clone(), val);
                self.locked.insert(arg.name.clone());
                continue;
            }
            if let Some(default) = &arg.default {
                let (resolved, unresolved) = self.resolve_checked(default);
                if unresolved {
                    self.vars.remove(&arg.name);
                } else {
                    self.vars.insert(arg.name.clone(), resolved);
                }
            }
        }
    }

    /// Declare a stage ARG: a supplied build arg enters scope (and locks) here, else a
    /// locked value wins, else the given default overwrites any inherited default.
    pub fn declare_arg(&mut self, name: &str, default: Option<&str>) {
        if self.locked.contains(name) {
            return;
        }
        // A supplied build arg comes into scope at its ARG declaration, overriding the
        // default, and locks the name against any later ARG default.
        if let Some(val) = self.supplied_build_args.get(name).cloned() {
            self.vars.insert(name.to_string(), val);
            self.locked.insert(name.to_string());
            self.tainted.remove(name);
            return;
        }
        if let Some(val) = default {
            self.vars.insert(name.to_string(), val.to_string());
        }
    }

    /// Whether a name is locked (so a failed re-declaration isn't treated as unresolved).
    pub fn is_locked(&self, name: &str) -> bool {
        self.locked.contains(name)
    }

    /// Bind an ENV value, overwriting any prior binding and locking it against a later ARG.
    pub fn set_var(&mut self, key: &str, value: &str) {
        self.vars.insert(key.to_string(), value.to_string());
        self.locked.insert(key.to_string());
        self.tainted.remove(key);
    }

    /// Remove a binding and its lock/taint; used when an ARG re-declaration was unresolved.
    pub fn unset(&mut self, key: &str) {
        self.locked.remove(key);
        self.tainted.remove(key);
        self.vars.remove(key);
    }

    /// Mark a var set-but-unknown (unresolvable ENV); locks the name but resolves unresolved.
    pub fn taint(&mut self, key: &str) {
        self.vars.remove(key);
        self.locked.insert(key.to_string());
        self.tainted.insert(key.to_string());
    }

    /// Resolve ${VAR} and $VAR references in a string.
    pub fn resolve(&self, input: &str) -> String {
        self.resolve_checked(input).0
    }

    /// Like [`VariableResolver::resolve`], also flags an undefined, defaultless reference.
    pub fn resolve_checked(&self, input: &str) -> (String, bool) {
        let mut result = String::with_capacity(input.len());
        let mut unresolved = false;
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
                    } else if self.tainted.contains(var_name) {
                        // Tainted: its dash-default doesn't apply since the name is set.
                        result.push_str(&input[idx..end_idx + 1]);
                        unresolved = true;
                    } else if let Some(def) = default {
                        // Resolve the default recursively so nested `$OTHER` refs expand too.
                        let (resolved_def, def_unresolved) = self.resolve_checked(def);
                        result.push_str(&resolved_def);
                        unresolved |= def_unresolved;
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
                } else {
                    result.push_str(&input[idx..name_end]);
                    unresolved = true;
                }
                continue;
            }

            result.push('$');
        }

        (result, unresolved)
    }

    /// Check if a string contains unresolved variables.
    pub fn has_unresolved(&self, input: &str) -> bool {
        self.resolve_checked(input).1
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
        assert_eq!(
            resolver.resolve_checked("${MISSING:-/opt/$SUB}"),
            ("/opt/inner".to_string(), false)
        );
    }

    #[test]
    fn test_resolve_checked_default_with_undefined_nested_var_is_unresolved() {
        let resolver = VariableResolver::new();
        // The default text's own unresolved reference flags the whole result unresolved.
        let (value, unresolved) = resolver.resolve_checked("${MISSING:-/x$BAR}");
        assert_eq!(value, "/x$BAR");
        assert!(unresolved);
    }

    #[test]
    fn test_resolve_checked_unterminated_brace_is_unresolved() {
        let resolver = VariableResolver::new();
        let (value, unresolved) = resolver.resolve_checked("/a/${UNTERM");
        assert_eq!(value, "/a/${UNTERM");
        assert!(unresolved);
    }

    #[test]
    fn test_build_arg_not_in_scope_before_its_arg_declaration() {
        // A supplied build arg must not resolve until its ARG declaration is reached.
        let mut resolver = VariableResolver::new();
        resolver.load_build_args(&[("DIR".to_string(), "child".to_string())]);
        let (value, unresolved) = resolver.resolve_checked("/base/$DIR");
        assert_eq!(value, "/base/$DIR");
        assert!(unresolved);
        assert!(resolver.has_supplied_build_arg("DIR"));
    }

    #[test]
    fn test_build_arg_enters_scope_at_arg_declaration() {
        // declare_arg brings the supplied build arg into scope and locks it.
        let mut resolver = VariableResolver::new();
        resolver.load_build_args(&[("DIR".to_string(), "child".to_string())]);
        resolver.declare_arg("DIR", None);
        assert_eq!(resolver.resolve("/base/$DIR"), "/base/child");
        assert!(resolver.is_locked("DIR"));
    }

    #[test]
    fn test_build_arg_overrides_default_at_declaration() {
        // The build arg outranks the ARG default, which Docker never evaluates.
        let mut resolver = VariableResolver::new();
        resolver.load_build_args(&[("DIR".to_string(), "child".to_string())]);
        resolver.declare_arg("DIR", Some("/fallback"));
        assert_eq!(resolver.resolve("$DIR"), "child");
    }

    #[test]
    fn test_global_build_arg_enters_scope_at_global_arg() {
        // A build arg matching a global ARG enters scope when the globals are loaded.
        let mut resolver = VariableResolver::new();
        resolver.load_build_args(&[("TAG".to_string(), "3.18".to_string())]);
        resolver.load_global_args(&[ArgInstruction {
            name: "TAG".to_string(),
            default: Some("latest".to_string()),
        }]);
        assert_eq!(resolver.resolve("alpine:$TAG"), "alpine:3.18");
        assert!(resolver.is_locked("TAG"));
    }

    #[test]
    fn test_build_arg_without_declaration_never_resolves() {
        // With no global and no stage ARG, a supplied build arg stays out of scope.
        let mut resolver = VariableResolver::new();
        resolver.load_build_args(&[("TAG".to_string(), "3.18".to_string())]);
        resolver.load_global_args(&[]);
        let (value, unresolved) = resolver.resolve_checked("alpine:$TAG");
        assert_eq!(value, "alpine:$TAG");
        assert!(unresolved);
    }

    #[test]
    fn test_tainted_var_reference_is_unresolved_ignoring_default() {
        let mut resolver = VariableResolver::new();
        resolver.taint("DIR");
        // A set-but-unknown var is unresolved for a bare ref and for both default forms.
        assert!(resolver.resolve_checked("$DIR").1);
        assert!(resolver.resolve_checked("/srv/${DIR-fallback}").1);
        assert!(resolver.resolve_checked("/srv/${DIR:-fallback}").1);
        // A later resolvable binding clears the taint.
        resolver.set_var("DIR", "real");
        assert_eq!(
            resolver.resolve_checked("/srv/${DIR-fallback}"),
            ("/srv/real".to_string(), false)
        );
    }
}
