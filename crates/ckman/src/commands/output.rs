//! Prepare file destinations before mutating a device, then replace each file
//! only after its complete contents have been written successfully.

use super::CliResult;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Finish stdout output before reporting success. Small binary outputs can
/// remain buffered even after write_all succeeds; exit-time errors are lost.
pub(super) fn write_stdout(bytes: &[u8]) -> CliResult<()> {
    Ok(write_and_flush(&mut io::stdout().lock(), bytes)?)
}

fn write_and_flush(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

pub(super) struct PreparedFile {
    destination: PathBuf,
    temporary: PathBuf,
    file: Option<File>,
}

impl PreparedFile {
    pub(super) fn new(path: &Path) -> CliResult<Self> {
        Self::prepare(path, false)
    }

    fn prepare(path: &Path, private: bool) -> CliResult<Self> {
        // Follow existing symbolic links, as ordinary file output does.
        let mut destination = match path.symlink_metadata() {
            Ok(metadata) if metadata.is_symlink() => path.canonicalize()?,
            Ok(_) => path.to_owned(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => path.to_owned(),
            Err(error) => return Err(error.into()),
        };
        let permissions = match destination.metadata() {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(format!("output is not a regular file: {}", path.display()).into());
                }
                // Check access without truncating the current contents.
                OpenOptions::new().write(true).open(&destination)?;
                Some(metadata.permissions())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()?;
        destination = parent.join(destination.file_name().ok_or("output has no file name")?);
        for _ in 0..8 {
            let mut random = [0; 16];
            getrandom::fill(&mut random)?;
            let temporary = parent.join(format!(".ckman-{:032x}.tmp", u128::from_be_bytes(random)));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            if private {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&temporary) {
                Ok(file) => {
                    let output = Self {
                        destination,
                        temporary,
                        file: Some(file),
                    };
                    if let Some(permissions) = permissions.filter(|_| !private) {
                        output
                            .file
                            .as_ref()
                            .expect("new output")
                            .set_permissions(permissions)?;
                    }
                    return Ok(output);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("cannot allocate a temporary output file".into())
    }

    pub(super) fn destination(&self) -> &Path {
        &self.destination
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> CliResult<()> {
        let file = self
            .file
            .as_mut()
            .ok_or("output file was already written")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(self.file.take());
        if let Err(error) = std::fs::rename(&self.temporary, &self.destination) {
            // Retain the complete output for recovery if publishing fails.
            let saved = std::mem::take(&mut self.temporary);
            return Err(format!(
                "cannot replace {}: {error}; output saved at {}",
                self.destination.display(),
                saved.display()
            )
            .into());
        }
        self.temporary.clear();
        Ok(())
    }
}

/// A destination prepared before requesting sensitive data from the card.
/// On Unix both the temporary and published file are private, even when
/// replacing an existing file with broader permissions.
pub(super) enum SecretOutput {
    Stdout,
    File(PreparedFile),
}

impl SecretOutput {
    pub(super) fn new(path: &str) -> CliResult<Self> {
        if path == "-" {
            Ok(Self::Stdout)
        } else {
            Ok(Self::File(PreparedFile::prepare(Path::new(path), true)?))
        }
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> CliResult<()> {
        match self {
            Self::Stdout => write_stdout(bytes),
            Self::File(file) => file.write(bytes),
        }
    }
}

impl Drop for PreparedFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.temporary.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.temporary);
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn buffered_stdout_errors_are_reported_before_success() {
        struct ClosedPipe;
        impl Write for ClosedPipe {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut buffered = io::BufWriter::new(ClosedPipe);
        // A successful write alone can hide that the receiving end is closed.
        buffered.write_all(b"previous buffered data").unwrap();
        let error = write_and_flush(&mut buffered, b"binary output").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);

        struct FlushFailure(Vec<u8>);
        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::Other.into())
            }
        }
        let mut destination = FlushFailure(Vec::new());
        assert!(write_and_flush(&mut destination, b"output").is_err());
        assert_eq!(destination.0, b"output");
        let mut successful = Vec::new();
        write_and_flush(&mut successful, b"complete output").unwrap();
        assert_eq!(successful, b"complete output");
    }

    pub(crate) struct TestDirectory(pub PathBuf);

    impl TestDirectory {
        pub(crate) fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "ckman-output-test-{:032x}",
                u128::from_be_bytes(random)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unfinished_outputs_preserve_existing_files_and_clean_up() {
        let directory = TestDirectory::new();
        let existing = directory.0.join("existing.pem");
        let missing = directory.0.join("missing.pem");
        std::fs::write(&existing, b"original public key").unwrap();
        {
            let _existing_output = PreparedFile::new(&existing).unwrap();
            let _new_output = PreparedFile::new(&missing).unwrap();
            assert_eq!(std::fs::read(&existing).unwrap(), b"original public key");
            assert!(!missing.exists());
        }
        assert_eq!(std::fs::read(&existing).unwrap(), b"original public key");
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn completed_output_replaces_the_whole_file() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("key.pem");
        std::fs::write(&destination, b"previous public key with longer contents").unwrap();
        let mut output = PreparedFile::new(&destination).unwrap();
        output.write(b"new key").unwrap();
        drop(output);
        assert_eq!(std::fs::read(destination).unwrap(), b"new key");
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_existing_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let destination = directory.0.join("csr.pem");
        for mode in [0o600, 0o750] {
            std::fs::write(&destination, b"previous CSR").unwrap();
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(mode)).unwrap();
            let mut output = PreparedFile::new(&destination).unwrap();
            assert_eq!(
                output
                    .file
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
            output.write(b"new CSR").unwrap();
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
    }

    #[test]
    fn failed_replacement_retains_complete_data_for_recovery() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("key.pem");
        let mut output = PreparedFile::new(&destination).unwrap();
        // Simulate a destination becoming invalid after preflight.
        std::fs::create_dir(&destination).unwrap();
        let temporary = output.temporary.clone();
        let error = output.write(b"generated public key").unwrap_err();
        assert!(error.to_string().contains(&temporary.display().to_string()));
        drop(output);
        assert_eq!(std::fs::read(temporary).unwrap(), b"generated public key");
        assert!(destination.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn secret_outputs_are_private_during_and_after_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let destination = directory.0.join("shared-secret.bin");
        for existing_mode in [None, Some(0o644), Some(0o777), Some(0o600)] {
            if let Some(mode) = existing_mode {
                std::fs::write(&destination, b"old contents").unwrap();
                std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(mode))
                    .unwrap();
            }
            let mut output = SecretOutput::new(destination.to_str().unwrap()).unwrap();
            let SecretOutput::File(file) = &output else {
                panic!("expected a file output")
            };
            assert_eq!(
                std::fs::metadata(&file.temporary)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            if existing_mode.is_some() {
                assert_eq!(std::fs::read(&destination).unwrap(), b"old contents");
            } else {
                assert!(!destination.exists());
            }
            output.write(b"new secret").unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"new secret");
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_secret_replacement_retains_a_private_recovery_file() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let destination = directory.0.join("secret.bin");
        let mut output = SecretOutput::new(destination.to_str().unwrap()).unwrap();
        let SecretOutput::File(file) = &output else {
            panic!("expected a file output")
        };
        let temporary = file.temporary.clone();
        std::fs::create_dir(&destination).unwrap();
        assert!(output.write(b"secret recovery data").is_err());
        drop(output);
        assert_eq!(std::fs::read(&temporary).unwrap(), b"secret recovery data");
        assert_eq!(
            std::fs::metadata(temporary).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
