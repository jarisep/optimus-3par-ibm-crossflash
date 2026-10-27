# Original Optimus: 3PAR 920 GB to IBM 800 GB

An experimental Linux workflow for converting an original SMART Storage Systems
Optimus SSD from **3PAR 3P03** to **IBM GB7H**, then rebuilding its flash translation
layer (FTL) using the firmware's **800 GB** profile.

This worked on one drive. The resulting drive identified as
`IBM-ESXS TXA2D20800GA6I`, exposed **800,166,076,416 bytes** with **512-byte sectors**,
and passed a small direct write/read check at four locations, including the end
of the device. The internal FTL capacity also changed to the IBM profile;
this was not just an INQUIRY string edit or a host capacity limit.

**Experimental and destructive.** This is not a manufacturer-supported crossflash.
Firmware download or an incorrect internal record can leave a drive inaccessible.
Use an expendable, unmounted drive and preserve its own backups. The scripts
deliberately accept only the narrow combination below.

## Tested scope

| Item | Original | Converted |
|---|---|---|
| SCSI vendor | `SmrtStor` | `IBM-ESXS` |
| SCSI product | `DOPA0920S5xnNMRI` | `TXA2D20800GA6I` |
| Firmware | `3P03` | `GB7H` |
| Physical model in identity record | `TXA2D20920GA60HP` | Preserved |
| Host sector size | 520 bytes | 512 bytes |
| Host block count | 1,788,974,512 | 1,562,824,368 |
| Internal logical pages | 223,621,814 | 196,482,171 |
| Tested NAND ID | `98 3a a5 82 7a d6` | Same hardware |

This is the **original Optimus** platform, not Optimus.2. Similar branding,
capacity, or a firmware filename is not sufficient evidence of compatibility.
The IBM image contains a native 800 GB CPU1 variant. That fact does not make
the conversion officially supported for the original HP part number.

No cold power-cycle, long endurance test, full-media write/read, power-loss test,
or RAID-controller compatibility matrix has been completed. Four successful
1 MiB checks establish basic I/O only. The generalized scripts in this repository
were tested offline; the hardware result used the earlier device-specific
implementation of the same command sequence.

## What is included

- `firmware.py`: validates the exact original IBM image and creates a container
  with unchanged CPU0, CUST, and only the 800 GB CPU1. **BOOT is excluded.**
- `optimus.py`: explicit backup, flash, format, status, verify, refresh, and
  optional destructive I/O-test stages.
- [Technical findings](docs/technical-notes.md): file layouts, access mechanism,
  capacity accounting, and the reasoning behind the sequence.
- [Failure and recovery notes](docs/recovery.md): what to do if a stage stops.
- [Privacy and publishing](docs/privacy.md): keeping your own device data private.

No firmware binaries, flash dumps, real serial numbers, WWNs, network addresses,
or machine-specific logs are distributed here. Generated outputs contain private
device data and must not be published.

## Requirements

- Linux, Python 3.9 or later, and `sg3_utils` (`sg3-utils` on Debian/Ubuntu).
- Direct SCSI access through a suitable SAS HBA. A RAID controller or USB bridge
  may filter vendor commands; neither was validated for this workflow.
- Root access for the device operations.
- The exact IBM `gb7h_all.dob` supplied in the
  [IBM GB7H package](https://public.dhe.ibm.com/systems/support/bp_system_x/pe_optimus1_gb7h.zip).
  Extract it from your copy of the package. No claim is made that GB7H is the
  newest firmware available for every Optimus variant.
- Retain your original 3PAR 3P03 update package as an additional recovery resource.
  An update package is distinct from your drive's individual configuration backup.

Expected **IBM DOB file** SHA-256 (not the ZIP hash):

```text
4c4bb135318360daf3c16f28bd7f3a2acaf1356f17deea4d5731190ede03eb59
```

The builder refuses other images. It does not patch firmware instructions or
change the selected component bodies. It changes the outer container and its
digests to select one capacity variant.

## Procedure

Run these commands on the Linux machine connected to the SSD. No DOS, EFI boot,
or server reboot was needed for the successful conversion.

### 1. Identify the drive and prepare the image

Read the standard INQUIRY, serial page, and designator page for your candidate
SCSI generic device:

```bash
sudo sg_inq /dev/sgX
sudo sg_inq --page=0x80 /dev/sgX
sudo sg_inq --page=0x83 /dev/sgX
```

Use the **logical-unit NAA/WWN**, not either SAS port address. Check that the
block device has no partitions, mounts, RAID/LVM holders, swap, or active users.
The scripts also check these conditions, but cannot prevent another process
from starting I/O later. Keep the drive dedicated to this operation.

Set your values, using the actual `/dev/sgN` name in place of `/dev/sgX`:

```bash
OPTIMUS_DEVICE=/dev/sgX
OPTIMUS_SERIAL='YOUR_SERIAL'
OPTIMUS_WWN='YOUR_LOGICAL_UNIT_WWN'
target=(--device "$OPTIMUS_DEVICE" --expect-serial "$OPTIMUS_SERIAL" --expect-wwn "$OPTIMUS_WWN")

python3 firmware.py /path/to/gb7h_all.dob --out work/ibm800
```

All output directories must be new. The prepared package SHA-256 is:

```text
c50ee13f372d4ad93c09df96cda59a39b1a98a86f605635aacfda1dba3efb909
```

### 2. Back up this specific drive

```bash
sudo python3 optimus.py backup "${target[@]}" --out work/original
```

This opens the volatile service gate, reads bounded internal files and exposed
regions twice, verifies matching copies, then closes the gate. It excludes file
`0x1b`, whose read wrapper has a conditional state-changing side effect.
The observed complete `0xff` region is 4 MiB. This is **not a complete NAND/FTL
media backup** and does not guarantee recovery from every failure.

An unstable read, unexpected geometry, or incomplete backup aborts the workflow.
Copy the entire private backup directory to another machine or disk before
proceeding. It contains the drive's identity and original firmware/configuration
material; do not attach it to a public issue.

### 3. Download IBM firmware

**This step invalidates the existing logical mapping and writes firmware.**

```bash
sudo python3 optimus.py flash "${target[@]}" \
  --backup work/original --prepared work/ibm800 --out work/flash --execute
```

The script compares live key records with the backup, sets the native
unformatted state in internal file **10 decimal / `0x0a`**, verifies it twice,
then sends the IBM package once using WRITE BUFFER mode 5. It preserves the
bootloader and does not overwrite the factory descriptor or NAND settings.

On the tested drive, firmware activated automatically and INQUIRY changed to
IBM GB7H. `Medium format corrupted` at this point was expected: the FTL had
intentionally been marked unformatted. A timeout or transport error is **not**
permission to repeat the firmware command. See [recovery notes](docs/recovery.md).

### 4. Rebuild the FTL with 512-byte sectors

```bash
sudo python3 optimus.py format "${target[@]}" \
  --backup work/original --out work/format --execute
```

The underlying command is:

```text
sg_format --format --size=512 --count=-1 --cmplst=0 --early --quick --verbose DEVICE
```

`--count=-1` asks for the firmware's recommended maximum block count, rather
than carrying over the old count. `--cmplst=0` requests retention of the existing
grown defect list at the SCSI interface; it is not a proof of every internal
NAND defect-list policy. No fast-format option is used. `--early` returns after
launching the operation; **it does not mean the format has completed**.
See the [sg_format manual](https://github.com/hreinecke/sg3_utils/blob/master/doc/sg_format.8).

Monitor with a new output directory each time:

```bash
sudo python3 optimus.py status "${target[@]}" --out work/status-01
```

Do not reset, power-cycle, or disconnect the SSD while it reports format in
progress. During format, a capacity query may return `0xffffffff` blocks;
that placeholder is not a real 2.2 TB capacity. Continue only after TEST UNIT
READY reports `Good`.

### 5. Verify capacity and internal configuration

```bash
sudo python3 optimus.py verify "${target[@]}" \
  --backup work/original --out work/verified
```

Expected results:

- 1,562,824,368 host blocks of 512 bytes: **800,166,076,416 bytes**.
- Completed FTL format, 196,482,171 internal logical pages, erase-block range
  0 through 4163, internal sector field 516 (distinct from host sector size).
- Original factory descriptor and NAND-settings file unchanged.
- Only the expected OEM-selector migration and checksum change in the identity file.

The identity file's manufacturing model/nominal 920 value can remain unchanged.
The successful conversion did **not** require rewriting it to 800. IBM selects
its host personality and capacity from the new firmware profile.

### 6. Refresh Linux's cached identity

`lsblk` may still show the old model or a zero/stale capacity until rediscovery.
With the drive still unused and the format finished:

```bash
sudo python3 optimus.py refresh "${target[@]}" --out work/refresh --execute
lsblk -d -o NAME,MODEL,REV,SERIAL,SIZE,LOG-SEC,PHY-SEC
```

This removes and rescans only that drive's H:C:T:L, not the entire SAS bus.
Device names can change. Repeat the INQUIRY checks and update `OPTIMUS_DEVICE`
and the `target` array if needed before subsequent commands.

### 7. Optional small, destructive I/O check

```bash
sudo python3 optimus.py io-test "${target[@]}" --out work/io-test --execute
```

This writes random data to four 1 MiB regions (start, one-third, two-thirds,
and end), flushes, and checks direct-I/O readback. It leaves those regions
containing test data. Compare the saved before/after SCSI error logs. It is
neither a full-media test nor a performance benchmark.

The tested drive retained write cache disabled. The scripts record MODE pages
but do not silently change cache policy; check the settings required by your
application separately. Plan a cold power-cycle and longer validation before
relying on a converted drive.

## Development and evidence limits

Run the offline tests with:

```bash
python3 -m unittest discover -s tests -v
```

Tests do not access a drive. They check package construction helpers, target
parsing, geometry gates, and failure-path behavior. They cannot establish
crossflash compatibility for another hardware revision.

The publication intentionally omits real per-unit artifacts. Useful bug reports
include model, firmware revision, stage, exit code and redacted sense data.
Never upload an unreviewed backup, command log, flash image, or screenshot.

The scripts and documentation are MIT licensed. Vendor firmware is not included
and is not covered by this license.
