# Storage accounting

Audited against canokey-core commit `a349b268`, in particular
`applets/admin/admin.c`, `include/admin.h`, `src/fs.c` and `src/pin.c`.
ckman uses the records from libcanokey without recalculating their sizes.

| Output | Firmware calculation | Meaning |
| --- | --- | --- |
| Flash usage | `lfs_fs_size() * block_size / 1024` | Allocated filesystem blocks, integer KiB |
| Flash capacity | `block_count * block_size / 1024` | Mounted filesystem capacity, integer KiB |
| Applet storage | File lengths plus selected user-attribute lengths | Logical payload bytes, including any preallocated file contents |
| Filesystem overhead/other | `max(physical_used_bytes - sum(applet_payload_bytes), 0)` | Physical allocation not attributed to the listed payloads |

The applet manifest covers Admin, OpenPGP, PIV (fixed objects, special slots,
retired slots and management key), OATH, CTAP, NDEF and PASS. Sources are
assigned once; no duplicate source was found. Missing files/attributes count
as zero. The missing-source flag is not a corruption indicator: unused slots
and optional objects routinely do not exist. ckman therefore displays sizes
without a missing-source warning or approximation marker.

The residual includes filesystem metadata, allocation slack, copy-on-write
overhead, and payloads outside the manifest. In this firmware, OpenPGP's
`pgp-pw1`, `pgp-pw3` and `pgp-rc` sources have no attribute kind in the usage
manifest, although PIN retry attributes 0 and 1 are stored on those files.
Their attribute bytes, when present, are consequently included in the residual.
Thus the residual must not be described as exclusively filesystem overhead or system
file contents. Improving per-applet attribution requires a firmware change;
the aggregate physical allocation remains authoritative.

For the reported example, the seven applets sum to 6180 B, and the residual
is 10204 B: together they equal 16384 B, exactly 16 KiB. The calculation is
consistent. In general the total KiB field truncates sub-KiB allocation, so
converting it back to bytes is not an exact substitute for the firmware's
byte-level residual calculation (the virtual card uses 512-byte blocks).

Capacity here is the mounted LittleFS volume, not all device flash. Firmware,
reserved regions and the separate 512-byte platform configuration page are
outside this accounting. The latter stores shared device settings and SM2/PIV
configuration through platform hooks, not LittleFS files, and therefore does
not belong in either applet payloads or the filesystem residual.

This is a useful payload breakdown and physical capacity indicator, not a
measurement of per-applet physical allocation or reclaimable space. Console
uses the same firmware records; ckman keeps the residual separate from the
logical applet payloads and retains exact byte counts.
