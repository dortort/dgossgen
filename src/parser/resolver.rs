use std::collections::HashMap;

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
}

impl VariableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load build args (from CLI --build-arg flags).
    pub fn load_build_args(&mut self, args: &[(String, String)]) {
        for (k, v) in args {
            self.vars.insert(k.clone(), v.clone());
        }
    }

    /// Load ARGs declared before the first FROM.
    pub fn load_global_args(&mut self, args: &[ArgInstruction]) {
        for arg in args {
            if !self.vars.contains_key(&arg.name) {
                if let Some(default) = &arg.default {
                    self.vars.insert(arg.name.clone(), default.clone());
                }
            }
        }
    }

    /// Declare a stage-body ARG, adopting its default only when the name is not
    /// already bound. A build arg or an earlier declaration therefore wins, and a
    /// bare `ARG NAME` (no default) leaves any prior binding untouched.
    pub fn declare_arg(&mut self, name: &str, default: Option<&str>) {
        if !self.vars.contains_key(name) {
            if let Some(val) = default {
                self.vars.insert(name.to_string(), val.to_string());
            }
        }
    }

    /// Bind an ENV variable to an already-resolved value, overwriting any prior
    /// binding. The binding takes effect only for instructions that follow it.
    pub fn set_var(&mut self, key: &str, value: &str) {
        self.vars.insert(key.to_string(), value.to_string());
    }

    /// Resolve ${VAR} and $VAR references in a string.
    pub fn resolve(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
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
                    } else if let Some(def) = default {
                        result.push_str(def);
                    } else {
                        result.push_str(&input[idx..end_idx + 1]);
                    }
                } else {
                    // Unterminated ${...}: preserve the tail literally.
                    result.push_str(&input[idx..]);
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
                }
                continue;
            }

            result.push('$');
        }

        result
    }

    /// Check if a string contains unresolved variables.
    pub fn has_unresolved(&self, input: &str) -> bool {
        let resolved = self.resolve(input);
        contains_variable_reference(&resolved)
    }

    /// Get current variable map.
    pub fn variables(&self) -> &HashMap<String, String> {
        &self.vars
    }
}

fn contains_variable_reference(input: &str) -> bool {
    let mut iter = input.char_indices().peekable();
    while let Some((_, ch)) = iter.next() {
        if ch != '$' {
            continue;
        }

        let Some((_, next_ch)) = iter.peek().copied() else {
            continue;
        };

        if next_ch == '{' {
            iter.next(); // consume '{'
            let mut name = String::new();
            while let Some((_, current)) = iter.peek().copied() {
                iter.next();
                if current == '}' {
                    if is_valid_var_name(&name) {
                        return true;
                    }
                    break;
                }
                name.push(current);
            }
            continue;
        }

        if next_ch.is_ascii_alphabetic() || next_ch == '_' {
            return true;
        }
    }
    false
}

fn is_valid_var_name(expr: &str) -> bool {
    let var_name = if let Some(sep) = expr.find(":-") {
        &expr[..sep]
    } else if let Some(sep) = expr.find('-') {
        &expr[..sep]
    } else {
        expr
    };

    let mut chars = var_name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
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
}
