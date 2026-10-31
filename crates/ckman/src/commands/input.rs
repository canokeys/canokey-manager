//! Keep file and stdin secrets protected while reading, including partial I/O.

use super::CliResult;
use std::io::{self, Read};
use zeroize::Zeroizing;

pub(super) fn read_secret(path: &str) -> CliResult<Zeroizing<Vec<u8>>> {
    if path == "-" {
        Ok(read_secret_from(io::stdin().lock())?)
    } else {
        Ok(read_secret_from(std::fs::File::open(path)?)?)
    }
}

fn read_secret_from(mut reader: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    let mut block = Zeroizing::new([0; 8192]);
    loop {
        let count = match reader.read(block.as_mut()) {
            Ok(0) => return Ok(data),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let needed = data
            .len()
            .checked_add(count)
            .ok_or_else(|| io::Error::other("secret input is too large"))?;
        if needed > data.capacity() {
            // Growing a Vec in place can free its previous allocation without
            // clearing it. Copy into a protected replacement and drop the old
            // buffer explicitly instead.
            let mut replacement = Zeroizing::new(Vec::with_capacity(
                needed.max(data.capacity().saturating_mul(2)),
            ));
            replacement.extend_from_slice(&data);
            data = replacement;
        }
        data.extend_from_slice(&block[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reads_preserve_bytes_across_growth_and_short_reads() {
        let source: Vec<_> = (0..100_000).map(|i| (i % 251) as u8).collect();
        for chunk in [1, 13, 8192, 10_000] {
            let result = read_secret_from(ShortReads {
                remaining: &source,
                chunk,
            })
            .unwrap();
            assert_eq!(*result, source);
        }
        assert!(read_secret_from(io::empty()).unwrap().is_empty());
    }

    struct ShortReads<'a> {
        remaining: &'a [u8],
        chunk: usize,
    }

    impl Read for ShortReads<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.chunk);
            self.remaining.read(&mut buffer[..count])
        }
    }

    #[test]
    fn secret_reads_retry_interruptions_and_propagate_partial_failure() {
        struct InterruptedThenData(u8);
        impl Read for InterruptedThenData {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                match self.0 {
                    1 => Err(io::ErrorKind::Interrupted.into()),
                    2 => b"audit-only-key".as_slice().read(buffer),
                    _ => Ok(0),
                }
            }
        }
        assert_eq!(
            read_secret_from(InterruptedThenData(0)).unwrap().as_slice(),
            b"audit-only-key"
        );
        struct DataThenError(bool);
        impl Read for DataThenError {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    buffer[0] = 0x42;
                    return Ok(1);
                }
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input failed"))
            }
        }
        let error = read_secret_from(DataThenError(false)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(error.to_string(), "input failed");
    }
}
