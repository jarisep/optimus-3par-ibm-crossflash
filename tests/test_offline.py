"""Offline tests only. All identifiers and device interactions are synthetic."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import firmware
import optimus


def records():
    factory = struct.pack('<I6sHHBBII', 0x55aa, bytes.fromhex('983aa5827ad6'),
                          0xffff, 15, 0xfd, 255, 0, 0)
    fmt = bytearray(24)
    struct.pack_into('<IH', fmt, 0, 0xa5a5a5a5, 524)
    fmt[6], fmt[15] = 8, 3
    struct.pack_into('<HHI', fmt, 16, 0, 4163, 223621814)
    identity = bytearray(288)
    identity[:4] = b'SDF\x01'
    struct.pack_into('<H', identity, 224, 920)
    identity[236:252] = b'TXA2D20920GA60HP'
    nand = bytearray(1772)
    nand[:4], nand[4:8], nand[12:14] = b'\xff'*4, b'\x03\0\0\0', b'\0\x02'
    return {9: factory, 10: bytes(fmt), 16: bytes(identity), 21: bytes(nand)}


class PackageTests(unittest.TestCase):
    def test_unlock_digest_and_lengths(self):
        for level in (2, 255, 256):
            b = firmware.unlock(level)
            self.assertEqual(len(b), 512)
            self.assertEqual(b[:8], b'DOB UNLK')
            self.assertEqual(struct.unpack_from('<IIII', b, 8), (512, 256, 256, 256))
            self.assertEqual(struct.unpack_from('<I', b, 0x50)[0], level)
            self.assertEqual(b[0xc0:0xd0], hashlib.md5(b[256:]).digest())
            self.assertEqual(b[0xe0:0xf0], hashlib.md5(firmware.SALT+b[:224]).digest())

    def test_zero_is_not_close(self):
        with self.assertRaises(ValueError):
            firmware.unlock(0)

    def test_wrong_image_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Wrong source'):
            firmware.build(b'DOB CFRM'+bytes(1024))

    def test_native_unformatted_record(self):
        self.assertEqual(len(firmware.UNFORMATTED), 24)
        self.assertEqual(firmware.UNFORMATTED[:15]+firmware.UNFORMATTED[16:], b'\xff'*23)
        self.assertEqual(firmware.UNFORMATTED[15], 3)


class IdentityTests(unittest.TestCase):
    def test_naa_lu_not_port(self):
        # Synthetic, deliberately distinct LU and target-port designators.
        lu = bytes.fromhex('5000000000000001')
        port = bytes.fromhex('5000000000000002')
        data = bytes([1, 3, 0, 8])+lu+bytes([1, 0x13, 0, 8])+port
        vpd = bytes([0, 0x83, 0, len(data)])+data
        self.assertEqual(optimus.lu_wwns(vpd), [lu])

    def test_truncated_designator_rejected(self):
        with self.assertRaises(ValueError):
            optimus.lu_wwns(bytes.fromhex('0083000c01030008'))

    def test_wwn_format(self):
        self.assertEqual(optimus.wwn_bytes('0x5000000000000001'), bytes.fromhex('5000000000000001'))
        for bad in ('abc', 'YOUR_WWN', '0xZZ00000000000001'):
            with self.assertRaises(ValueError):
                optimus.wwn_bytes(bad)

    def test_profile_not_just_model_name(self):
        r = records()
        optimus.original_profile(r)
        for fid, offset in [(9, 4), (9, 10), (10, 20), (16, 224), (21, 12)]:
            altered = dict(r)
            b = bytearray(altered[fid]); b[offset] ^= 1; altered[fid] = bytes(b)
            with self.subTest(file=fid, offset=offset), self.assertRaises(ValueError):
                optimus.original_profile(altered)

    def test_refuse_mutation_without_execute_before_session(self):
        argv = ['optimus.py', 'flash', '--device', '/dev/sg999', '--expect-serial', 'DEMO0001',
                '--expect-wwn', '5000000000000001', '--out', 'unused', '--backup', 'unused', '--prepared', 'unused']
        with patch('sys.argv', argv), patch.object(optimus, 'Session') as session:
            with self.assertRaisesRegex(ValueError, '--execute'):
                optimus.main()
            session.assert_not_called()

    def test_incomplete_backup_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/'manifest.json').write_text(json.dumps({'complete':False}))
            with self.assertRaisesRegex(ValueError, 'did not complete'):
                optimus.load_backup(p, {})


class FakeSession:
    def __init__(self, root, mismatch=False, timeout=False, bad_readback=False):
        self.out = root/'output'; self.out.mkdir()
        prepared = root/'prepared'; prepared.mkdir()
        (prepared/'gb7h-800-only-no-boot.dob').write_bytes(b'synthetic-image')
        self.a = argparse.Namespace(execute=True, backup=root/'backup', prepared=prepared)
        self.device = '/dev/sg999'
        self.identity = {}
        self.events = []
        self.mismatch, self.timeout, self.bad_readback = mismatch, timeout, bad_readback

    def idle_block(self): pass
    def ready(self): self.events.append('ready')
    def closed(self): self.events.append('closed-check')
    def close(self): self.events.append('close')
    def identify(self, revision): self.events.append('identify-'+revision)
    def gate(self, level): self.events.append('gate-'+str(level))
    def keys(self): return {} if self.mismatch else records()
    def read_part(self, fid, offset, length):
        data = records()[9] if fid == 9 else (b'bad' if self.bad_readback else firmware.UNFORMATTED)
        return argparse.Namespace(stdout=data)
    def call(self, label, argv, **kwargs):
        self.events.append(label)
        if label == 'download' and self.timeout:
            raise RuntimeError('Outcome unknown')
        return argparse.Namespace(stdout=b'', returncode=0)


class FailurePathTests(unittest.TestCase):
    def run_flash(self, root, **kwargs):
        s = FakeSession(root, **kwargs)
        with patch.object(optimus.os, 'geteuid', return_value=0), \
             patch.object(optimus, 'load_backup', return_value=records()), \
             patch.object(optimus, 'sha', return_value=firmware.PREPARED_SHA256):
            try:
                optimus.flash(s)
            except (ValueError, RuntimeError):
                pass
        return s.events

    def test_changed_key_record_prevents_any_persistent_write(self):
        with tempfile.TemporaryDirectory() as d:
            events = self.run_flash(Path(d), mismatch=True)
        self.assertNotIn('write-unformatted', events)
        self.assertNotIn('download', events)
        self.assertEqual(events[-1], 'close')

    def test_bad_unformat_readback_prevents_download(self):
        with tempfile.TemporaryDirectory() as d:
            events = self.run_flash(Path(d), bad_readback=True)
        self.assertIn('write-unformatted', events)
        self.assertNotIn('download', events)
        self.assertEqual(events[-1], 'close')

    def test_uncertain_download_is_not_retried_or_followed_by_writes(self):
        with tempfile.TemporaryDirectory() as d:
            events = self.run_flash(Path(d), timeout=True)
        self.assertEqual(events.count('download'), 1)
        self.assertEqual(events[-1], 'download')
        self.assertNotIn('close', events)

    def test_success_checks_new_identity_and_closes_gate(self):
        with tempfile.TemporaryDirectory() as d:
            events = self.run_flash(Path(d))
        self.assertLess(events.index('write-unformatted'), events.index('download'))
        self.assertEqual(events[-2:], ['identify-GB7H', 'close'])


if __name__ == '__main__':
    unittest.main()
