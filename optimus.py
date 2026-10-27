#!/usr/bin/env python3
"""Experimental, identity-guarded original Optimus 3P03 -> GB7H workflow.

Run locally on the Linux machine with direct SCSI access. No SSH, host reset,
automatic retry, or automatic rollback is implemented. Outputs are PRIVATE.
"""
import argparse
import datetime
import json
import mmap
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

from firmware import PREPARED_SHA256, UNFORMATTED, require, sha, unlock

HOST_BYTES = 800166076416
KEY_LENGTHS = {9: 24, 10: 24, 16: 288, 21: 1772}
REGION_CAPS = {0xf4: 0x200000, 0xf5: 0x200000, 0xf6: 0x10000,
               0xf7: 0x10000, 0xf8: 0x10000, 0xf9: 0xe000,
               0xfa: 0x70000, 0xfb: 0x70000, 0xfc: 0x80000,
               0xfd: 0x60000, 0xfe: 0x200000, 0xff: 0x410000}
FILE_IDS = [i for i in range(1, 0x23) if i != 0x1b] + list(REGION_CAPS)


def wwn_bytes(text):
    text = text.lower().removeprefix('0x')
    require(len(text) == 16, 'WWN must contain 16 hex digits')
    return bytes.fromhex(text)


def lu_wwns(vpd):
    require(len(vpd) >= 4 and vpd[1] == 0x83, 'Invalid VPD 0x83')
    end = 4 + int.from_bytes(vpd[2:4], 'big')
    require(end <= len(vpd), 'Truncated VPD 0x83')
    pos, result = 4, []
    while pos + 4 <= end:
        length = vpd[pos + 3]
        require(pos + 4 + length <= end, 'Truncated VPD descriptor')
        # Binary NAA designator associated with this logical unit, not a port.
        if vpd[pos] & 15 == 1 and vpd[pos + 1] & 0x3f == 3 and length == 8:
            result.append(vpd[pos + 4:pos + 12])
        pos += 4 + length
    require(pos == end, 'Trailing partial VPD descriptor')
    return result


def geometry(record):
    require(len(record) == 24, 'Wrong format-record size')
    return dict(state=int.from_bytes(record[:4], 'little'),
                internal_sector=int.from_bytes(record[4:6], 'little'),
                sectors_per_page=record[6], layout=record[15],
                first=int.from_bytes(record[16:18], 'little'),
                last=int.from_bytes(record[18:20], 'little'),
                pages=int.from_bytes(record[20:24], 'little'))


def original_profile(records):
    factory, identity, nand = records[9], records[16], records[21]
    require(len(factory) == 24 and factory[:4] == b'\xaa\x55\x00\x00', 'Factory marker mismatch')
    require(factory[4:10] == bytes.fromhex('983aa5827ad6'), 'Untested NAND ID')
    require(factory[10:15] == bytes.fromhex('ffff0f00fd'), 'Untested geometry/defect DB version')
    require(geometry(records[10]) == dict(state=0xa5a5a5a5, internal_sector=524,
            sectors_per_page=8, layout=3, first=0, last=4163, pages=223621814),
            'Untested original FTL geometry')
    require(len(identity) == 288 and identity[:4] == b'SDF\x01', 'Untested identity record')
    require(identity[208+28:208+44].rstrip(b'\0 ') == b'TXA2D20920GA60HP', 'Untested physical model')
    require(int.from_bytes(identity[224:226], 'little') == 920, 'Unexpected nominal capacity')
    require(len(nand) == 1772 and nand[:4] == b'\xff' * 4 and
            nand[4:8] == b'\x03\0\0\0' and nand[12:14] == b'\0\x02',
            'Untested NAND-settings version')


class Session:
    def __init__(self, args):
        self.a = args
        self.device = str(Path(args.device).resolve())
        require(Path(self.device).name.startswith('sg') and Path(self.device).parent == Path('/dev'),
                'Use an explicit /dev/sgN SCSI generic device')
        self.expected_wwn = wwn_bytes(args.expect_wwn)
        require(args.expect_serial and args.expect_serial.isascii(), 'Supply the exact ASCII serial')
        self.out = args.out
        self.out.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.counter = 0
        self.identity = None
        for tool in ('sg_inq', 'sg_raw', 'sg_readcap', 'sg_modes', 'sg_write_buffer', 'sg_logs'):
            require(shutil.which(tool), 'Missing sg3_utils program: ' + tool)

    def call(self, label, argv, timeout=40, okay=(0,)):
        self.counter += 1
        stem = f'{self.counter:04d}-{label}'
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            r = subprocess.run(argv, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (self.out / (stem + '.timeout')).write_text(str(exc))
            raise RuntimeError('Command timed out; outcome unknown. Do not automatically retry.') from exc
        (self.out / (stem + '.bin')).write_bytes(r.stdout)
        (self.out / (stem + '.stderr')).write_bytes(r.stderr)
        with (self.out / 'commands.jsonl').open('a') as f:
            f.write(json.dumps(dict(label=label, argv=argv, utc=started, rc=r.returncode,
                                   bytes=len(r.stdout), sha256=sha(r.stdout))) + '\n')
        if okay is not None:
            require(r.returncode in okay, f'{label} failed (rc={r.returncode}); inspect private stderr log')
        return r

    def identify(self, revision=None):
        serial = self.call('serial', ['sg_inq', '--raw', '--page=0x80', self.device]).stdout
        wwn = self.call('wwn', ['sg_inq', '--raw', '--page=0x83', self.device]).stdout
        info = self.call('inquiry', ['sg_inq', '--raw', self.device]).stdout
        require(len(serial) >= 4 and serial[4:].rstrip(b'\0 ') == self.a.expect_serial.encode(),
                'Serial mismatch: refusing device access')
        require(self.expected_wwn in lu_wwns(wwn), 'Logical-unit WWN mismatch')
        require(len(info) >= 36, 'Truncated INQUIRY')
        rev = info[32:36].decode('ascii')
        vendor, product = info[8:16].decode().strip(), info[16:32].decode().strip()
        require((vendor, product, rev) in [('SmrtStor', 'DOPA0920S5xnNMRI', '3P03'),
                                          ('IBM-ESXS', 'TXA2D20800GA6I', 'GB7H')],
                'Device is outside the tested product/firmware pair')
        if revision:
            require(rev == revision, 'Wrong running firmware for this stage')
        self.identity = dict(serial=self.a.expect_serial, wwn=self.expected_wwn.hex(),
                             vendor=vendor, product=product, revision=rev)
        return self.identity

    def idle_block(self):
        device = Path('/sys/class/scsi_generic') / Path(self.device).name / 'device'
        blocks = list((device / 'block').iterdir())
        require(len(blocks) == 1, 'Expected one block device for the SCSI LU')
        block = Path('/dev') / blocks[0].name
        sysblock = Path('/sys/class/block') / blocks[0].name
        require(not list((sysblock / 'holders').iterdir()), 'Device has holders (RAID/LVM/etc.)')
        require(not any(p.is_file() for p in sysblock.glob('*/partition')), 'Device has partitions')
        devno = (sysblock / 'dev').read_text().strip()
        require(not any(line.split()[2] == devno for line in Path('/proc/self/mountinfo').read_text().splitlines()),
                'Device is mounted')
        for line in Path('/proc/swaps').read_text().splitlines()[1:]:
            require(Path(line.split()[0]).resolve() != block, 'Device is active swap')
        # Raw users of the block/sg node are not necessarily mounted or holders.
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid():
                continue
            try:
                for fd in (proc / 'fd').iterdir():
                    try:
                        require(fd.resolve() not in (block, Path(self.device)),
                                'Another process has the device open')
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, PermissionError):
                continue
        return device, block

    def gate(self, level):
        p = self.out / f'gate-{level}.dob'
        p.write_bytes(unlock(level))
        self.call('gate-' + str(level), ['sg_write_buffer', '--mode=5', '--id=0',
                  '--offset=0', '--length=512', '--timeout=30', '--in=' + str(p), self.device], timeout=45)

    def read_part(self, fid, offset, length, okay=(0,)):
        cdb = bytes([0x3c, 31, fid]) + offset.to_bytes(3, 'big') + length.to_bytes(3, 'big') + b'\0'
        return self.call(f'read-{fid:02x}-{offset:06x}',
                         ['sg_raw', '--readonly', '--binary', '--timeout=10', '--request=' + str(length),
                          self.device] + [f'{x:02x}' for x in cdb], timeout=15, okay=okay)

    def closed(self):
        r = self.read_part(9, 0, 24, okay=None)
        # sg3_utils exit 5 = illegal request; arbitrary transport failures do not prove a closed gate.
        require(r.returncode == 5, 'Expected closed service gate (Illegal Request)')

    def close(self):
        self.gate(256)
        self.closed()

    def keys(self):
        records = {}
        for fid, n in KEY_LENGTHS.items():
            b = self.read_part(fid, 0, n).stdout
            require(len(b) == n, 'Short key-record read')
            records[fid] = b
        return records

    def ready(self):
        self.call('tur', ['sg_raw', '--readonly', self.device, '00', '00', '00', '00', '00', '00'])

    def capacity(self):
        b = self.call('capacity', ['sg_readcap', '--long', '--raw', self.device]).stdout
        require(len(b) >= 12, 'Short READ CAPACITY')
        count, sector = int.from_bytes(b[:8], 'big') + 1, int.from_bytes(b[8:12], 'big')
        return dict(blocks=count, sector=sector, bytes=count * sector)

    def metadata(self):
        for label, argv in [('mode-current', ['sg_modes', '--all', '--page=0x3f,0xff', '--raw']),
                            ('mode-saved', ['sg_modes', '--all', '--page=0x3f,0xff', '--control=3', '--raw']),
                            ('logs', ['sg_logs', '--readonly', '--all'])]:
            self.call(label, argv + [self.device], okay=None)


def load_backup(path, identity):
    m = json.loads((path / 'manifest.json').read_text())
    require(m.get('complete') is True, 'Backup did not complete')
    require(m['identity']['serial'] == identity['serial'] and m['identity']['wwn'] == identity['wwn'],
            'Backup belongs to another drive')
    require(m['identity']['revision'] == '3P03', 'Need the original 3P03 backup')
    require(set(m['files']) == {f'file-{i:02x}.bin' for i in FILE_IDS}, 'Incomplete backup file inventory')
    for name, row in m['files'].items():
        b = (path / name).read_bytes()
        require(len(b) == row['bytes'] and sha(b) == row['sha256'], 'Backup integrity mismatch: ' + name)
    require(m['files']['file-ff.bin']['bytes'] == 4194304, 'Expected complete exposed 4 MiB SPI region')
    records = {i: (path / f'file-{i:02x}.bin').read_bytes() for i in KEY_LENGTHS}
    original_profile(records)
    return records


def backup(s):
    s.identify('3P03')
    s.idle_block()
    s.ready()
    cap = s.capacity()
    require(cap == dict(blocks=1788974512, sector=520, bytes=930266746240), 'Untested initial capacity')
    s.metadata()
    s.closed()
    rows = {}
    try:
        s.gate(2)
        original_profile(s.keys())
        for fid in FILE_IDS:
            copies = []
            cap = REGION_CAPS.get(fid, 0x200000)
            for passno in (1, 2):
                data = bytearray()
                ending = 'bound reached'
                while len(data) < cap:
                    n = min(32768, cap - len(data))
                    b = s.read_part(fid, len(data), n).stdout
                    require(len(b) <= n, 'Unexpected read length')
                    data.extend(b)
                    if len(b) < n:
                        ending = 'short read'
                        break
                copies.append(bytes(data))
            require(copies[0] == copies[1], f'Unstable backup of file {fid:02x}; stop and investigate')
            name = f'file-{fid:02x}.bin'
            (s.out / name).write_bytes(copies[0])
            rows[name] = dict(bytes=len(copies[0]), sha256=sha(copies[0]), ending=ending)
            print(f'Captured file {fid:02x}: {len(copies[0])} bytes, two equal reads', flush=True)
        require(rows['file-ff.bin']['bytes'] == 4194304 and rows['file-ff.bin']['ending'] == 'short read',
                'Untested exposed SPI size; backup not marked complete')
    finally:
        s.close()
    s.identify('3P03')
    (s.out / 'manifest.json').write_text(json.dumps(dict(complete=True, identity=s.identity, files=rows), indent=2) + '\n')
    print('Backup complete. Keep this entire PRIVATE directory off public GitHub.')


def mutation_guard(s):
    require(s.a.execute, 'Destructive stage requires --execute; nothing has been changed')
    require(os.geteuid() == 0, 'Run device-changing stages as root')
    s.idle_block()


def flash(s):
    mutation_guard(s)
    s.identify('3P03')
    original = load_backup(s.a.backup, s.identity)
    image = (s.a.prepared / 'gb7h-800-only-no-boot.dob').read_bytes()
    require(sha(image) == PREPARED_SHA256, 'Prepared firmware hash mismatch')
    s.ready()
    s.closed()
    attempted = False
    try:
        s.gate(255)
        require(s.keys() == original, 'Key records changed since backup')
        p = s.out / 'native-unformatted-file0a.bin'
        p.write_bytes(UNFORMATTED)
        s.call('write-unformatted', ['sg_write_buffer', '--mode=31', '--id=10', '--offset=0',
               '--length=24', '--timeout=30', '--in=' + str(p), s.device])
        for _ in range(2):
            require(s.read_part(10, 0, 24).stdout == UNFORMATTED, 'Unformat readback mismatch')
        require(s.read_part(9, 0, 24).stdout == original[9], 'Factory descriptor changed')
        # Use our verified copy; do not re-open a caller-supplied path for download.
        p = s.out / 'firmware-to-download.dob'
        p.write_bytes(image)
        (s.out / 'DOWNLOAD_ATTEMPTED').write_text('One attempt only. Inspect logs before any further mutation.\n')
        attempted = True
        s.call('download', ['sg_write_buffer', '--mode=5', '--id=0', '--offset=0',
               '--length=' + str(len(image)), '--timeout=300', '--in=' + str(p), s.device], timeout=315)
    finally:
        # After download starts, a timeout/error can mean partial or completed programming.
        # Do not blindly restore, reset, or send more writes to an unknown firmware state.
        if not attempted:
            s.close()
    s.identify('GB7H')
    s.close()
    print('IBM GB7H is running. Medium format corrupted is expected before FORMAT UNIT.')
    print('Next: format stage. Do not repeat the flash stage.')


def format_drive(s):
    mutation_guard(s)
    s.identify('GB7H')
    original = load_backup(s.a.backup, s.identity)
    require(shutil.which('sg_format'), 'Missing sg_format')
    s.closed()
    try:
        s.gate(2)
        keys = s.keys()
        require(keys[9] == original[9] and keys[21] == original[21], 'Factory/NAND settings changed')
        require(keys[10] == UNFORMATTED, 'Not the expected unformatted state; do not reformat automatically')
    finally:
        s.close()
    (s.out / 'FORMAT_ATTEMPTED').write_text('One FORMAT UNIT attempt; inspect status instead of repeating.\n')
    r = s.call('format', ['sg_format', '--format', '--size=512', '--count=-1', '--cmplst=0',
                         '--early', '--quick', '--verbose', s.device], timeout=90)
    print(r.stdout.decode(errors='replace'))
    print('Format launched. Use status; do not reset or disconnect during format.')


def status(s):
    print(json.dumps(s.identify(), indent=2))
    r = s.call('tur', ['sg_raw', '--readonly', s.device, '00', '00', '00', '00', '00', '00'], okay=None)
    print(r.stderr.decode(errors='replace'))
    if r.returncode == 0:
        print(json.dumps(s.capacity(), indent=2))
    else:
        print('Not ready: capacity may be a placeholder. Inspect the sense response above.')


def verify(s):
    s.identify('GB7H')
    original = load_backup(s.a.backup, s.identity)
    s.ready()
    cap = s.capacity()
    require(cap == dict(blocks=1562824368, sector=512, bytes=HOST_BYTES), 'Unexpected IBM capacity')
    s.closed()
    try:
        s.gate(2)
        keys = s.keys()
        require(keys == s.keys(), 'Unstable key-record readback')
        for fid, data in keys.items():
            (s.out / f'file-{fid:02x}.bin').write_bytes(data)
    finally:
        s.close()
    require(keys[9] == original[9] and keys[21] == original[21], 'Factory/NAND settings differ')
    require(geometry(keys[10]) == dict(state=0xa5a5a5a5, internal_sector=516,
            sectors_per_page=8, layout=3, first=0, last=4163, pages=196482171), 'Unexpected IBM FTL geometry')
    # IBM migrates OEM selectors itself. Preserve per-unit identity and factory strings.
    allowed = {7, 0xe2, 0xe3, 0x10c, 0x10d, 0x10e, 0x10f}
    diff = [i for i, (a, b) in enumerate(zip(original[16], keys[16])) if a != b]
    require(set(diff) <= allowed, 'Unexpected identity changes; inspect private records')
    require(keys[16][0xe2:0xe4] == bytes([1, 2]) and keys[16][0x10c:0x110] == bytes([15, 1, 15, 0]),
            'Unexpected IBM OEM selectors')
    s.metadata()
    result = dict(identity=s.identity, capacity=cap, geometry=geometry(keys[10]),
                  factory_descriptor_unchanged=True, nand_settings_unchanged=True,
                  identity_changed_offsets=diff)
    (s.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


def refresh(s):
    mutation_guard(s)
    s.identify('GB7H')
    s.ready()
    require(s.capacity()['bytes'] == HOST_BYTES, 'Unexpected capacity')
    device, block = s.idle_block()
    hctl = device.resolve().name
    host, channel, target, lun = hctl.split(':')
    require(all(x.isdigit() for x in (host, channel, target, lun)), 'Invalid H:C:T:L')
    (s.out / 'rediscovery.json').write_text(json.dumps(dict(hctl=hctl, old_block=str(block))) + '\n')
    (device / 'delete').write_text('1\n')
    (Path('/sys/class/scsi_host') / ('host' + host) / 'scan').write_text(f'{channel} {target} {lun}\n')
    print('Rediscovered only ' + hctl + '. Recheck sg/block names and identity; names can change.')


def io_test(s):
    mutation_guard(s)
    s.identify('GB7H')
    s.ready()
    require(s.capacity()['bytes'] == HOST_BYTES, 'Unexpected capacity')
    _, block = s.idle_block()
    require(int((Path('/sys/class/block') / block.name / 'size').read_text()) * 512 == HOST_BYTES,
            'Kernel capacity is stale; refresh and recheck device names first')
    for page in (2, 3, 6):
        s.call(f'before-log-{page}', ['sg_logs', '--readonly', '--page=' + str(page), s.device])
    n = 1024 * 1024
    offsets = [0, HOST_BYTES // 3 // 4096 * 4096,
               (HOST_BYTES * 2 // 3) // 4096 * 4096, HOST_BYTES - n]
    data = []
    fd = os.open(block, os.O_RDWR | os.O_DIRECT)
    try:
        for offset in offsets:
            payload = os.urandom(n)
            with mmap.mmap(-1, n) as buf:
                buf[:] = payload
                require(os.pwritev(fd, [buf], offset) == n, 'Short direct write')
            data.append((offset, payload))
        os.fsync(fd)
        for offset, payload in data:
            with mmap.mmap(-1, n) as buf:
                require(os.preadv(fd, [buf], offset) == n and buf[:] == payload, 'Readback mismatch')
    finally:
        os.close(fd)
    for page in (2, 3, 6):
        s.call(f'after-log-{page}', ['sg_logs', '--readonly', '--page=' + str(page), s.device])
    result = [dict(offset=offset, bytes=n, sha256=sha(payload), matched=True) for offset, payload in data]
    (s.out / 'io-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Four 1 MiB direct write/read checks passed. Compare before/after error logs.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('stage', choices=['backup', 'flash', 'format', 'status', 'verify', 'refresh', 'io-test'])
    ap.add_argument('--device', required=True, help='Explicit /dev/sgN; never guessed')
    ap.add_argument('--expect-serial', required=True)
    ap.add_argument('--expect-wwn', required=True, help='Logical-unit WWN, not SAS port address')
    ap.add_argument('--out', type=Path, required=True, help='New PRIVATE directory; never reused')
    ap.add_argument('--backup', type=Path)
    ap.add_argument('--prepared', type=Path)
    ap.add_argument('--execute', action='store_true', help='Allow destructive flash/format/refresh/I/O stage')
    args = ap.parse_args()
    if args.stage in ('flash', 'format', 'verify'):
        require(args.backup is not None, 'This stage requires --backup')
    if args.stage == 'flash':
        require(args.prepared is not None, 'Flash requires --prepared')
    if args.stage in ('flash', 'format', 'refresh', 'io-test'):
        require(args.execute, 'Add --execute only after reviewing the documented destructive stage')
    os.umask(0o077)
    session = Session(args)
    {'backup': backup, 'flash': flash, 'format': format_drive, 'status': status,
     'verify': verify, 'refresh': refresh, 'io-test': io_test}[args.stage](session)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print('STOP:', exc, file=sys.stderr)
        print('Inspect the PRIVATE output directory. Do not automatically repeat a modifying stage.', file=sys.stderr)
        sys.exit(1)
