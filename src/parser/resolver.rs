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
    /// Names whose value is *locked* by a CLI `--build-arg` or an `ENV` binding.
    /// Docker gives both precedence over an `ARG` instruction's default, so a
    /// later `ARG NAME=default` must not overwrite a locked value. An `ARG`
    /// default binding is *not* locked, so a re-declaration in a child stage can
    /// replace it.
    locked: HashSet<String>,
    /// Names that are *set to an unknown value* — bound by an ENV whose value
    /// could not be resolved (e.g. `ENV DIR=$MISSING`). The name is set (so a
    /// `${DIR-word}`/`${DIR:-word}` default must not be substituted for it), but we
    /// have no usable value, so any reference to it resolves as unresolved and is
    /// dropped. A later resolvable binding clears the taint.
    tainted: HashSet<String>,
}

impl VariableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load build args (from CLI --build-arg flags). These lock the name so a
    /// later `ARG NAME=default` cannot overwrite the command-line value.
    pub fn load_build_args(&mut self, args: &[(String, String)]) {
        for (k, v) in args {
            self.vars.insert(k.clone(), v.clone());
            self.locked.insert(k.clone());
        }
    }

    /// Load ARGs declared before the first FROM. These are ARG defaults (not
    /// locked): a stage that re-declares the name with a new default overrides
    /// them, while a build arg still wins. Defaults are resolved in declaration
    /// order against the args loaded before them, so a global default that
    /// references an earlier global (`ARG ACTUAL=base` / `ARG BASE=${ACTUAL}`) is
    /// expanded rather than stored verbatim.
    pub fn load_global_args(&mut self, args: &[ArgInstruction]) {
        for arg in args {
            if !self.vars.contains_key(&arg.name) {
                if let Some(default) = &arg.default {
                    let resolved = self.resolve(default);
                    self.vars.insert(arg.name.clone(), resolved);
                }
            }
        }
    }

    /// Declare a stage-body `ARG NAME[=default]`. A value locked by a build arg
    /// or ENV always wins, so the default is ignored there. Otherwise the default
    /// (when present) becomes the binding, *overwriting* an inherited ARG default
    /// so a child stage's `ARG NAME=other` re-declaration takes effect. A bare
    /// `ARG NAME` only brings the name into scope and leaves any binding untouched.
    pub fn declare_arg(&mut self, name: &str, default: Option<&str>) {
        if self.locked.contains(name) {
            return;
        }
        if let Some(val) = default {
            self.vars.insert(name.to_string(), val.to_string());
        }
    }

    /// Whether a name's value is locked by a build arg or ENV (and so must not be
    /// treated as an undefined ARG default even when a re-declaration fails to
    /// resolve).
    pub fn is_locked(&self, name: &str) -> bool {
        self.locked.contains(name)
    }

    /// Bind an ENV variable to an already-resolved value, overwriting any prior
    /// binding and locking it against a later ARG default. The binding takes
    /// effect only for instructions that follow it.
    pub fn set_var(&mut self, key: &str, value: &str) {
        self.vars.insert(key.to_string(), value.to_string());
        self.locked.insert(key.to_string());
        self.tainted.remove(key);
    }

    /// Remove a binding and any lock/taint, if present. Used for an ARG re-declared
    /// with an unresolved default: the ARG carries no precedence, so a later
    /// ARG/ENV of the same name may legitimately rebind it.
    pub fn unset(&mut self, key: &str) {
        self.locked.remove(key);
        self.tainted.remove(key);
        self.vars.remove(key);
    }

    /// Mark a variable set-but-unknown. Used when an ENV assignment is
    /// unresolvable: Docker still binds the name and keeps ENV precedence over any
    /// later ARG of the same name (so it is locked), but we have no usable value —
    /// any reference to it resolves as unresolved (and is dropped), a `-`/`:-`
    /// default is not substituted for it (the name is set), and a later ARG cannot
    /// override it. A later resolvable ENV clears the taint via `set_var`.
    pub fn taint(&mut self, key: &str) {
        self.vars.remove(key);
        self.locked.insert(key.to_string());
        self.tainted.insert(key.to_string());
    }

    /// Resolve ${VAR} and $VAR references in a string.
    pub fn resolve(&self, input: &str) -> String {
        self.resolve_checked(input).0
    }

    /// Resolve like [`VariableResolver::resolve`], additionally reporting whether
    /// any `$VAR`/`${VAR}` reference could not be substituted (the variable was
    /// undefined and carried no `:-`/`-` default).
    ///
    /// The flag is set during substitution, so a literal dollar produced by an
    /// escaped `\$` never counts as unresolved — a value that legitimately
    /// contains a literal `$NAME` is distinguished from one whose variable was
    /// simply undefined. A textual scan of the *resolved* string cannot make that
    /// distinction, because by then the escape marker has become a real `$`.
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
                        // The name is set to an unknown value, so its `-`/`:-`
                        // default does not apply and we cannot resolve it: flag
                        // unresolved so the assertion is dropped.
                        result.push_str(&input[idx..end_idx + 1]);
                        unresolved = true;
                    } else if let Some(def) = default {
                        // Resolve the default recursively so `${VAR:-$OTHER}`
                        // expands `$OTHER` (and is flagged unresolved when `$OTHER`
                        // is itself undefined) instead of emitting the literal
                        // default text, which would leak a `$`-bearing value.
                        let (resolved_def, def_unresolved) = self.resolve_checked(def);
                        result.push_str(&resolved_def);
                        unresolved |= def_unresolved;
                    } else {
                        result.push_str(&input[idx..end_idx + 1]);
                        unresolved = true;
                    }
                } else {
                    // Unterminated ${...}: preserve the tail literally and flag it,
                    // so a malformed reference is never treated as fully resolved.
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
        // The default text itself carries an unresolved reference, so the whole
        // result must be flagged unresolved rather than reported as clean.
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
    fn test_tainted_var_reference_is_unresolved_ignoring_default() {
        let mut resolver = VariableResolver::new();
        resolver.taint("DIR");
        // A set-but-unknown var is unresolved for a bare reference and for both
        // default forms — the default must not be substituted for a set name.
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
