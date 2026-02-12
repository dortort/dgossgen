use std::collections::HashMap;

use super::ast::{ArgInstruction, Instruction, Stage};

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

    /// Process a stage's instructions, collecting ARG/ENV values.
    pub fn process_stage(&mut self, stage: &Stage) {
        for inst in &stage.instructions {
            match &inst.instruction {
                Instruction::Arg { name, default } => {
                    // Only set if not already provided by build args
                    if !self.vars.contains_key(name) {
                        if let Some(val) = default {
                            self.vars.insert(name.clone(), val.clone());
                        }
                    }
                }
                Instruction::Env(pairs) => {
                    for (key, value) in pairs {
                        let resolved = self.resolve(value);
                        self.vars.insert(key.clone(), resolved);
                    }
                }
                _ => {}
            }
        }
    }

    /// Resolve ${VAR} and $VAR references in a string.
    pub fn resolve(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '$' && i + 1 < chars.len() {
                if chars[i + 1] == '{' {
                    // ${VAR} or ${VAR:-default} form
                    if let Some(close) = input[i..].find('}') {
                        let var_expr = &input[i + 2..i + close];
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
                            // Keep the original reference (symbolic)
                            result.push_str(&input[i..i + close + 1]);
                        }
                        i += close + 1;
                        continue;
                    }
                } else if chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_' {
                    // $VAR form
                    let start = i + 1;
                    let mut end = start;
                    while end < chars.len()
                        && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                    {
                        end += 1;
                    }
                    let var_name = &input[start..end];
                    if let Some(val) = self.vars.get(var_name) {
                        result.push_str(val);
                    } else {
                        result.push_str(&input[i..end]);
                    }
                    i = end;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }

        result
    }

    /// Check if a string contains unresolved variables.
    pub fn has_unresolved(&self, input: &str) -> bool {
        let resolved = self.resolve(input);
        resolved.contains('$')
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
}
