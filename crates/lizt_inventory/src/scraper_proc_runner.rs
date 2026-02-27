use tracing::error;

pub fn run(cmd: &str) -> Option<String> {
    let output = std::process::Command::new("sh").arg("-c").arg(cmd).output();

    match output {
        Ok(out) if out.status.success() => Some(String::from_utf8_lossy(&out.stdout).to_string()),
        Ok(out) => {
            error!("Command `{}` failed: {}", cmd, String::from_utf8_lossy(&out.stderr));
            None
        }
        Err(e) => {
            error!("Failed to run command `{}`: {}", cmd, e);
            None
        }
    }
}
