//! Durable host recovery material for a management-key replacement.

use super::CliResult;
use ckman_core::piv::ManagementKeyAlgorithm;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(super) struct ManagementKeyRecovery {
    path: PathBuf,
}

impl ManagementKeyRecovery {
    pub(super) fn create(
        requested: Option<&Path>,
        serial: Option<u32>,
        reader: &str,
        algorithm: ManagementKeyAlgorithm,
        key: &[u8; 24],
        protect: bool,
        touch: bool,
    ) -> CliResult<Self> {
        let algorithm = match algorithm {
            ManagementKeyAlgorithm::Tdes => "tdes",
            ManagementKeyAlgorithm::Aes192 => "aes192",
        };
        let key = Zeroizing::new(super::piv::hex_encode(key));
        let contents = Zeroizing::new(format!(
            "CanoKey PIV management key recovery\nreader: {reader:?}\nserial: {serial:?}\nalgorithm: {algorithm}\nprotect: {protect}\ntouch: {touch}\nnew-management-key: {}\n\nThe replacement may or may not have committed. Keep the original credentials.\nTo finish, repeat change-management-key with the saved algorithm and new-management-key.\nIf the new key is active, also supply it as --management-key; otherwise use the original credentials.\nUse --protect again if protect is true, and --touch if touch is true.\nUse a fresh --recovery-file path; existing recovery files are never overwritten.\nDo not reset PIV to recover this key.\n",
            key.as_str()
        ));
        for _ in 0..8 {
            let path = match requested {
                Some(path) => path.to_path_buf(),
                None => {
                    let mut random = [0; 16];
                    getrandom::fill(&mut random)?;
                    std::env::current_dir()?.join(format!(
                        "ckman-piv-management-{algorithm}-{:032x}.recovery",
                        u128::from_be_bytes(random)
                    ))
                }
            };
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .canonicalize()?;
            let path = parent.join(path.file_name().ok_or("recovery file has no file name")?);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error)
                    if requested.is_none() && error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue
                }
                Err(error) => {
                    return Err(format!(
                        "cannot create management key recovery file {}: {error}",
                        path.display()
                    )
                    .into())
                }
            };
            let saved = (|| -> io::Result<()> {
                file.write_all(contents.as_bytes())?;
                file.sync_all()?;
                sync_directory(&parent)
            })();
            drop(file);
            if let Err(error) = saved {
                let _ = std::fs::remove_file(&path);
                return Err(format!("cannot persist management key recovery file {}: {error}; management key was not changed", path.display()).into());
            }
            return Ok(Self { path });
        }
        Err("cannot allocate a management key recovery file".into())
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    // There is deliberately no Drop cleanup: a panic or process exit must
    // leave the durable file available, even if no operation result arrives.
    pub(super) fn run(self, operation: impl FnOnce() -> CliResult<()>) -> CliResult<()> {
        operation().map_err(|error| -> Box<dyn std::error::Error> {
            format!(
                "{error}; management key recovery file retained at {}",
                self.path.display()
            )
            .into()
        })?;
        if let Err(error) = std::fs::remove_file(&self.path)
            .and_then(|_| sync_directory(self.path.parent().expect("absolute recovery path")))
        {
            eprintln!("WARNING: management key updated successfully, but recovery-file cleanup failed: {error}; check {}", self.path.display());
        }
        Ok(())
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::output::tests::TestDirectory;

    fn create(path: &Path) -> CliResult<ManagementKeyRecovery> {
        ManagementKeyRecovery::create(
            Some(path),
            Some(42),
            "audit reader",
            ManagementKeyAlgorithm::Aes192,
            &[0x42; 24],
            true,
            false,
        )
    }

    #[test]
    fn recovery_is_durable_before_mutation_and_retained_on_error_or_panic() {
        let directory = TestDirectory::new();
        let path = directory.0.join("key.recovery");
        let recovery = create(&path).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("algorithm: aes192"));
        assert!(contents.contains(&format!("new-management-key: {}", "42".repeat(24))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let error = recovery
            .run(|| {
                assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
                Err("connection lost after key replacement".into())
            })
            .unwrap_err();
        assert!(error.to_string().contains(path.to_str().unwrap()));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
        let panic_path = directory.0.join("panic.recovery");
        let recovery = create(&panic_path).unwrap();
        assert!(std::panic::catch_unwind(|| recovery.run(|| panic!("interrupted"))).is_err());
        assert!(panic_path.exists());
    }

    #[test]
    fn recovery_creation_never_overwrites_and_success_cleans_up() {
        let directory = TestDirectory::new();
        let path = directory.0.join("key.recovery");
        std::fs::write(&path, "existing recovery").unwrap();
        assert!(create(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing recovery");
        std::fs::remove_file(&path).unwrap();
        let recovery = create(&path).unwrap();
        recovery
            .run(|| {
                assert!(path.exists());
                Ok(())
            })
            .unwrap();
        assert!(!path.exists());
        assert!(create(&directory.0.join("missing/key.recovery")).is_err());
        #[cfg(unix)]
        {
            let target = directory.0.join("target");
            std::fs::write(&target, "preserve").unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            assert!(create(&path).is_err());
            assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve");
        }
    }
}
