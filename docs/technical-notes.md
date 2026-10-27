# Technical findings

These notes distinguish static code analysis, isolated ARM emulation, and
observations on one physical drive. Function addresses refer only to the
specified firmware pair. They are not host commands or portable entry points.

## Why selecting an 800 GB image is not enough

The IBM distribution contains CPU1 variants for 200, 400, 800 and 1600 GB.
The original 3PAR drive advertises capacity selector `0x20` (920 GB); IBM's
800 GB CPU1 uses `0x08`.

Executing the actual 3P03 admission code in an isolated emulator showed:

| Input | Service level | Result |
|---|---:|---|
| Original multi-capacity IBM package, current 920 selector | 2 | No matching CPU1, `0x0526020d` |
| Original multi-capacity IBM package | 255 | Duplicate CPU1 components, `0x05260212` |
| IBM package containing only 800 GB CPU1, plus CPU0/CUST | 255 | Accepted |

Level 255 bypasses compatibility filtering; it does not remove the duplicate
component check. The prepared container therefore includes only the intended
CPU1. Every selected component is copied unchanged. The outer CFRM lengths and
digests are regenerated. BOOT is omitted, avoiding a bootloader write.

The original source hash and prepared result hash are pinned in `firmware.py`.
The prepared package was then accepted on the physical drive and activated
automatically through WRITE BUFFER mode 5.

## Service gate

A 512-byte DOB `UNLK` object is accepted by the firmware-download path.
All listed integer fields are little-endian.

| Offset | Content |
|---|---|
| `0x00` | ASCII `DOB ` |
| `0x04` | ASCII `UNLK` |
| `0x08` | Total size: 512 |
| `0x0c` | Header size: 256 |
| `0x10`, `0x14` | Body lengths: 256 |
| `0x18` | Flags: `0x22` |
| `0x50` | Service argument |
| `0xc0` | MD5 of the body |
| `0xe0` | MD5 of ASCII `These go to eleven.` followed by header bytes `[0:0xe0]` |
| `0x100` | 256 zero body bytes |

The salt has no terminating NUL. The remaining fields are zero in this object.
The transfer uses WRITE BUFFER mode 5, buffer ID 0, offset 0.

- Argument **2** enables the internal-file access needed for backup/verification.
- Argument **255** enables the admission behavior used for this conversion.
- Argument **256** closes the gate: the positive argument is truncated to byte 0.
- Argument **0 is not close**; it cycles access levels.

These objects change a RAM service gate. Ordinary file reads/writes use READ
BUFFER / WRITE BUFFER mode **31** with the internal file ID as buffer ID.
The firmware's file layer handles its physical headers, checksums and redundant
records. Do not write a logical payload directly into guessed SPI offsets.

The gate-open and gate-close paths were first emulated, then observed on the
physical drive. Before crossflash, a byte-identical write of the original file
10 was checked by readback and a raw-region comparison: it created new versioned
records rather than merely returning a RAM echo.

## Internal file IDs: decimal versus hexadecimal

**File 10 decimal is `0x0a`. File `0x10` is 16 decimal. They are different.**

| Decimal | Hex | Role / observed length |
|---:|---:|---|
| 9 | `0x09` | Factory/NAND descriptor, 24 bytes |
| 10 | `0x0a` | FTL format/layout record, 24 bytes |
| 16 | `0x10` | Per-unit identity SDF, 288 bytes |
| 21 | `0x15` | NAND settings, 1772 bytes |
| 27 | `0x1b` | Excluded from reads: conditional side effect in its wrapper |
| 255 | `0xff` | Exposed SPI-region read, 4 MiB on the tested drive |

Other internal files include defect, diagnostic and counter data. Backup captures
bounded files 1 through `0x22` except `0x1b`, plus regions `0xf4` through `0xff`.
Some regions are empty; some are overlapping or have implementation-specific
tails. In particular, do not concatenate `0xfa` and `0xfb` into a supposed full
flash image. The raw `0xff` capture is the observed exposed region, not proof of
every nonvolatile state in the SSD. Internal-file backups contain identifiers.

### Factory descriptor: file 9

| Offset | Length | Interpretation |
|---|---:|---|
| `0x00` | 4 | Factory marker `0x000055aa` |
| `0x04` | 6 | NAND ID |
| `0x0a` | 2 | Selection mask over 16 positions |
| `0x0c` | 2 | Selection mask over 4 positions |
| `0x0e` | 1 | Complement-encoded defect DB version; `0xfd` means 2 |
| `0x0f` | 1 | Not interpreted by the examined reader |
| `0x10` | 4 | Factory defect count |
| `0x14` | 4 | Manufacturing-grown defect count |

The masks are consistent with channel/chip-select geometry, but do not prove
the physical package count. The actual defect lists are elsewhere. Preserving
this descriptor alone is not a full bad-block backup. The public tools never
synthesize this record or copy it from another unit.

### Format record: file 10 (`0x0a`)

| Offset | Length | Interpretation |
|---|---:|---|
| `0x00` | 4 | State: completed `0xa5a5a5a5`, in progress `0x000000a5`, unformatted `0xffffffff` |
| `0x04` | 2 | Internal sector-size field |
| `0x06` | 1 | Sectors per logical page |
| `0x07..0x0e` | 8 | Layout parameters; not all semantics are named |
| `0x0f` | 1 | Internal layout revision; both writers set 3 |
| `0x10` | 2 | First erase block |
| `0x12` | 2 | Last erase block |
| `0x14` | 4 | Logical-page capacity |

The internal sector field was 524 with 520-byte host sectors, and became 516
with 512-byte host sectors. Do not interpret it as the host block size. The
precise purpose of the extra four bytes is not established here.

Both native unformat serializers produce 24 bytes: fifteen `0xff` bytes, one
`0x03` byte, and eight more `0xff` bytes. Both native loaders accept it. The
unformatted loader sets the state without loading the old mapping geometry.

This was established by executing the actual serializer and loader instructions
with SPI calls intercepted in RAM. The resulting record was then written through
the drive's file API and verified twice before downloading IBM firmware.

At IBM boot, the unformatted state bypasses the completed-mapping startup path.
The SCSI format handler selects erase blocks 0 through 4163 for this state.
FORMAT UNIT then builds a new mapping and stores the completed record. Merely
shrinking READ CAPACITY or writing a fabricated completed record would not prove
that the spare-space policy or mapping had been rebuilt.

### Identity file 16 (`0x10`)

The SDF contains a 208-byte schema and an 80-byte payload. The schema is identical
in the examined images; both actual parsers accepted the captured record in
emulation. It contains the unit's WWN, NAND ID, nominal capacity, serial,
manufacturing model and OEM fields. Real contents are deliberately not published.

IBM's initializer changes payload offsets `0x12..0x13` to `01 02`, and
`0x3c..0x3f` to `0f 01 0f 00`, then persists the identity record. The observed
migration matched the emulated result. The physical model, nominal 920 capacity,
serial, WWN and old count field at payload `0x40` remained unchanged.

Thus editing every visible `920` or old capacity field is unnecessary and may
damage identity data. The successful conversion lets IBM perform its own migration.

### NAND settings: file 21 (`0x15`)

The IBM loader accepts the observed 1772-byte record with marker `0xffffffff`,
version 3 and subtype bytes `00 02` at offsets 12 and 13. The actual record was
unchanged after conversion. Invalid settings can lead to default reconstruction;
there is no justification here for replacing valid per-unit settings with defaults.

## Capacity accounting

The original descriptor selects 16 × 4 positions and erase blocks 0 through 4163.
The firmware's capacity base is:

```text
4164 × 1024 × 16 × 4 = 272,891,904 logical-page equivalents
272,891,904 × 4096 = 1,117,765,238,784 bytes = 1041 GiB
```

This is a geometry-derived calculation, not a direct inventory of physical NAND
cells or a count of good, freely assignable blocks.

IBM computes `N - floor(N × 28 / 100)` and caps at 196,482,171 pages.
3PAR uses 15 in that subtraction and additionally caps at 223,621,814 pages.
The separate 3PAR cap is why 15% is not its final non-host fraction.

| Level | Bytes |
|---|---:|
| Geometry-derived base | 1,117,765,238,784 |
| Original host capacity, including 520 bytes per block | 930,266,746,240 |
| Original 512-byte payload equivalent | 915,954,950,144 |
| IBM internal page ceiling × 8 × 512 | 804,790,972,416 |
| IBM host profile, measured after format | 800,166,076,416 |

The difference between the geometry base and host payload is approximately
18.1% for the original profile and 28.4% for IBM. It includes all non-host
allocations, potentially protection, metadata and other reservations. It must
not be presented as a measured free replacement-block pool.

## Error handling and code similarity

The original 3PAR MODE page already had AWRE and ARRE enabled. No evidence here
establishes that 3PAR disables internal bad-block management or delegates all of
it to the array. Those settings alone do not prove every error path works.

The two firmwares share substantial NAND initialization, record parsing and
serialization logic. The OEM layer and capacity build differ. Choosing the IBM
800 GB profile is justified by its explicit code/configuration path; it does
not establish that all algorithms are different or that all generic RAID
controllers will accept the resulting device.

## Useful addresses for reproduction

CPU1 executable alias is `0x84680000`; main CPU1 code is at `0x01800200`.
CPU0 extended code is at `0x43140000`. Addresses apply to these exact images.

| Function | 3PAR 3P03 | IBM GB7H |
|---|---|---|
| DOB admission | `0x43147724` | Not used for the original download |
| DOB processor | `0x43147eb8` | — |
| Service gate setter | `0x431476e8` | — |
| Factory/format record loader | `0x846978d6` | `0x8469751a` |
| Format-record serializer | `0x8469747e` | `0x846970be` |
| Native unformat | `0x84697502` | `0x84697142` |
| Default capacity calculation | `0x84691222` | `0x8469167a` |
| Full format body | — | `0x84695bb4` |
| SCSI-format handler | — | `0x84681522` |
| OEM identity initializer | — | CPU0 `0x2cd26` |
| Default 800 GB OEM profile | — | CPU0 `0x2e558` |

Original 3PAR DOB SHA-256:

```text
bd7417eb822193ad25e565590ac51c5ebe6458499bfbd5c9b0fc46554f98d851
```

The emulator and instruction traces used private decoded images and per-unit
inputs. Those are not distributed. These addresses, input hashes, documented
fields and the deterministic builder provide reference points for independent
analysis without publishing the unit's identity or firmware blobs.
