//! Keeps the Mac from idle-sleeping during a direct send (design section
//! 6.7).  Nothing in Drop's dependencies wraps IOKit's power assertions and
//! Drop has no `unsafe` code, so this runs the system's own
//! `/usr/bin/caffeinate -i -w <Drop's pid>`, which holds the
//! `PreventUserIdleSystemSleep` assertion until it is stopped or Drop exits
//! (so a crash cannot leave it running).  The display may still sleep.
//! Elsewhere it does nothing.

/// Holds the assertion while it lives.
#[derive(Debug)]
pub struct Awake(Option<std::process::Child>);

impl Awake {
    pub fn hold() -> Self {
        #[cfg(target_os = "macos")]
        {
            let child = std::process::Command::new("/usr/bin/caffeinate")
                .arg("-i")
                .arg("-w")
                .arg(std::process::id().to_string())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
            Self(child)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self(None)
        }
    }

    /// Holds nothing (tests, and where there is no assertion to hold).
    pub fn none() -> Self {
        Self(None)
    }
}

impl Drop for Awake {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
