use std::path::Path;

use anyhow::{Context, Result};
use console::style;

use crate::generator;

pub fn write_output(output_dir: &Path, output: &generator::GeneratorOutput) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output directory {}", output_dir.display()))?;

    let goss_path = output_dir.join("goss.yml");
    std::fs::write(&goss_path, &output.goss_yml)
        .with_context(|| format!("writing {}", goss_path.display()))?;
    eprintln!("{} {}", style("wrote").green(), goss_path.display());

    if let Some(wait_content) = &output.goss_wait_yml {
        let wait_path = output_dir.join("goss_wait.yml");
        std::fs::write(&wait_path, wait_content)
            .with_context(|| format!("writing {}", wait_path.display()))?;
        eprintln!("{} {}", style("wrote").green(), wait_path.display());
    }

    Ok(())
}
