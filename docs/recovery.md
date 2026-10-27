# Failure and recovery notes

There is no proven universal rollback procedure. The original 4 MiB exposed
SPI-region backup and internal-file copies preserve useful evidence, but are
not a complete NAND backup or a guarantee of recovery without hardware access.

## Before a modifying stage

An identity, geometry, image-hash or backup-integrity failure is a stop condition.
Do not remove the check merely to make another model pass. The scripts cover
one narrow product/firmware pair. Backup and verification temporarily change a
RAM service gate; they are not purely read-only at the SCSI command level.

The output directory is private. A failed operation still has logs there.
Use a new directory for a new read-only status query, but do not treat a new
directory as authorization to repeat a flash or format.

## Native unformatted record written, firmware download not yet attempted

The old logical mapping is no longer selected by the persistent format record.
The script closes the service gate when possible, but does not automatically
restore the original record. Do not reboot casually or run another format while
investigating. The original file `file-0a.bin` belongs to this drive alone.

The original investigation demonstrated an exact-original file-10 write through
WRITE BUFFER mode 31. It did not validate every interrupted-conversion rollback
case. Restoration requires confirming which firmware copies and mapping state
are present; a raw SPI write at a guessed address is not equivalent.

## Firmware download attempted

The marker `DOWNLOAD_ATTEMPTED` is created before the command is sent. A timeout,
lost SSH connection, transport reset, or nonzero exit code can have an ambiguous
outcome. Do not immediately repeat the download, restore a format record, or
escalate to a host/bus reset.

First use standard INQUIRY and TEST UNIT READY. The `status` stage performs these
queries without opening the service gate:

```bash
sudo python3 optimus.py status --device /dev/sgX \
  --expect-serial YOUR_SERIAL --expect-wwn YOUR_LOGICAL_UNIT_WWN \
  --out work/failure-status-01
```

- **IBM GB7H + Medium format corrupted:** this was the expected intermediate
  state after a successful download. Inspect the flash log and preserved key
  records, then use the documented format stage if all checks pass.
- **IBM GB7H + format in progress:** monitor; do not restart the operation.
- **IBM GB7H + Good:** inspect capacity and run the verify stage. Do not flash again.
- **Original firmware still visible:** this alone does not establish whether
  another image copy was partially or fully programmed. Inspect the command
  result and configuration before deciding a recovery action.
- **No device response:** stop automatic commands. Collect HBA/kernel evidence
  and establish the hardware recovery path. Repeated resets are not a recovery plan.

The scripts intentionally do not automate rollback, firmware retries, raw-SPI
writes, bootloader replacement, or host-wide reset operations.

## Format started

The format stage uses `--early`, so a successful process exit means the command
was launched, not that all work finished. Use status until TEST UNIT READY is
Good. A transient `0xffffffff` block count is a placeholder. Do not use it to
resize the disk or conclude that the drive has gained capacity.

If format fails, save sense data and error logs. Do not restore the old completed
format record over a partially rebuilt NAND mapping: that could claim an old
mapping is valid when it no longer exists.

## Kernel reports old identity or zero size

Compare direct `sg_inq` and `sg_readcap` results with `lsblk`. If the drive itself
reports the expected IBM identity, completed format and 800 GB capacity, use the
documented single-LU refresh. Recheck device names afterward. Do not reboot the
whole server or reset unrelated disks to refresh one cached inquiry response.

## Reporting a problem

Provide a manually reviewed excerpt containing the product/revision, stage,
return code and relevant sense text. Remove serials, WWNs, hostnames, network
addresses, usernames and local paths. Do not upload `work/`, flash dumps,
firmware binaries, full INQUIRY/VPD pages or an entire diagnostic archive.
