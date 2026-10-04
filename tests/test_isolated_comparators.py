"""Synthetic checks of the separate structural and published-pattern arms."""

from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/isolated_tls13"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/offline_memory"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from comparators import anderson_nss_adjacent, structure_only, xray_full_snapshot_entropy
from core_memory import CoreMemory
from test_offline_memory import make_core


class ComparatorTests(unittest.TestCase):
    def test_structure_only_retains_low_entropy_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core"
            data = bytearray(512)
            secret = bytes(48)
            struct.pack_into("<QQQ", data, 0, 0x11, 0x10080, 48)
            data[128:176] = secret
            make_core(path, data)
            with CoreMemory(path) as core:
                rows, summary = structure_only(core)
            self.assertEqual([row["hex"] for row in rows], [secret.hex()])
            self.assertEqual(summary["unique_candidates"], 1)

    def test_published_adjacency_and_pointer_method_have_distinct_recall(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core"
            data = bytearray(512)
            pointer_secret = bytes(range(48))
            adjacent_secret = bytes(range(48, 96))
            struct.pack_into("<QQQ", data, 0, 0x11, 0x10080, 48)
            data[128:176] = pointer_secret
            struct.pack_into("<Q", data, 256, 0x11)
            struct.pack_into("<I", data, 272, 48)
            data[280:328] = adjacent_secret
            make_core(path, data)
            with CoreMemory(path) as core:
                pointer_rows, _ = structure_only(core)
                adjacent_rows, _ = anderson_nss_adjacent(core)
            self.assertIn(pointer_secret.hex(), {row["hex"] for row in pointer_rows})
            self.assertIn(adjacent_secret.hex(), {row["hex"] for row in adjacent_rows})
            self.assertNotIn(pointer_secret.hex(), {row["hex"] for row in adjacent_rows})

    def test_candidate_limit_is_reported_as_incomplete_search(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core"
            data = bytearray(512)
            struct.pack_into("<Q", data, 64, 0x11)
            struct.pack_into("<I", data, 80, 48)
            data[88:136] = bytes(range(48))
            struct.pack_into("<Q", data, 192, 0x11)
            struct.pack_into("<I", data, 208, 48)
            data[216:264] = bytes(range(48, 96))
            make_core(path, data)
            with CoreMemory(path) as core:
                rows, summary = anderson_nss_adjacent(core, limit=1)
            self.assertEqual(len(rows), 1)
            self.assertTrue(summary["candidate_cap_reached"])
            self.assertFalse(summary["search_exhausted"])

    def test_xray_full_snapshot_baseline_uses_hex_entropy_and_eight_byte_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core"
            data = bytearray(512)
            secret = bytes.fromhex("0123456789abcdef" * 6)
            data[128:176] = secret
            make_core(path, data)
            with CoreMemory(path) as core:
                rows, summary = xray_full_snapshot_entropy(core)
            self.assertIn(secret.hex(), {row["hex"] for row in rows})
            self.assertEqual(summary["entropy_unit"], "bits_per_hex_character")
            self.assertTrue(summary["search_exhausted"])


if __name__ == "__main__":
    unittest.main()
