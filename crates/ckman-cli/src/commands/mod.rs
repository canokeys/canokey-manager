pub mod config;
pub mod info;
pub mod list;

use ckman_core::probe;
use ckman_transport::pcsc::{Pcsc, PcscConnection, Reader};

use canokey::DeviceProfile;

pub type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A probed CanoKey: exclusive connection plus its immutable profile.
pub struct Target {
    pub connection: PcscConnection,
    pub profile: DeviceProfile,
}

impl Target {
    pub fn serial(&self) -> Option<u32> {
        let bytes: [u8; 4] = self.profile.info().serial()?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
}

/// Connect to and probe one reader; returns `None` when the card is not a
/// CanoKey or probing fails (foreign cards must not break listing).
fn try_probe(pcsc: &Pcsc, reader: &Reader) -> Option<Target> {
    let mut connection = pcsc.connect(reader).ok()?;
    if !connection.is_canokey() {
        return None;
    }
    let profile = probe(&mut |command| connection.exchange(command)).ok()?;
    Some(Target {
        connection,
        profile,
    })
}

/// All reachable CanoKeys, in reader order.
pub fn all_targets(pcsc: &Pcsc) -> CliResult<Vec<Target>> {
    let mut targets = Vec::new();
    for reader in pcsc.readers()? {
        if let Some(target) = try_probe(pcsc, &reader) {
            targets.push(target);
        }
    }
    Ok(targets)
}

/// The single CanoKey selected by `--reader` / `--device`, or the only one
/// attached when no filter is given.
pub fn single_target(
    pcsc: &Pcsc,
    device: Option<u32>,
    reader_name: Option<&str>,
) -> CliResult<Target> {
    if let Some(name) = reader_name {
        let reader = pcsc
            .readers()?
            .into_iter()
            .find(|reader| reader.name() == name)
            .ok_or_else(|| format!("no such reader: {name}"))?;
        return try_probe(pcsc, &reader)
            .ok_or_else(|| format!("no CanoKey found in reader {name}").into());
    }
    let targets = all_targets(pcsc)?;
    if let Some(serial) = device {
        return targets
            .into_iter()
            .find(|target| target.serial() == Some(serial))
            .ok_or_else(|| format!("no CanoKey with serial number {serial} found").into());
    }
    match targets.len() {
        0 => Err("no CanoKey found".into()),
        1 => Ok(targets.into_iter().next().unwrap()),
        _ => Err("multiple CanoKeys found; use --device or --reader to select one".into()),
    }
}
