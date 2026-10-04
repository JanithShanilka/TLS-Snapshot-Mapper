"""Additional saved-image candidate discovery methods for a separate study.

These methods do not replace or change the frozen blind-study algorithms.
Anderson et al.'s published NSS regex is a TLS 1.2 extraction pattern. The
adjacent candidates here are its explicit 48-byte, TLS 1.3 discovery
adaptation; the shared record-authentication stage must assign their roles.
https://arxiv.org/html/1805.11544
"""

import hashlib
import heapq
import math
import struct
from collections import Counter


SECRET_BYTES = 48
MAX_ENUMERATED = 10_000


def _candidate(value, location):
    return {"id": hashlib.sha256(value).hexdigest(), "hex": value.hex(),
            "length": SECRET_BYTES, "locations": [location]}


def structure_only(core, limit=MAX_ENUMERATED):
    """Enumerate valid NSS CKA_VALUE pointers without entropy admission."""
    if not 1 <= limit <= MAX_ENUMERATED:
        raise ValueError("Candidate limit must be between 1 and 10000")
    result = {}
    examined = 0
    timed_out = False
    cap_reached = False
    try:
        for address in core.find(struct.pack("<Q", SECRET_BYTES)):
            item = address - 16
            if item % 8:
                continue
            try:
                kind, pointer, length = struct.unpack("<QQQ", core.read(item, 24))
                if kind != 0x11 or length != SECRET_BYTES or pointer < 4096:
                    continue
                value = core.read(pointer, SECRET_BYTES)
            except (ValueError, struct.error):
                continue
            examined += 1
            row = _candidate(value, {"item": hex(item), "data": hex(pointer)})
            if row["id"] in result:
                result[row["id"]]["locations"].extend(row["locations"])
            else:
                result[row["id"]] = row
                if len(result) == limit:
                    cap_reached = True
                    break
    except TimeoutError:
        timed_out = True
    return list(result.values()), {"structures_examined": examined,
                                   "unique_candidates": len(result),
                                   "search_exhausted": not (timed_out or cap_reached),
                                   "search_timed_out": timed_out,
                                   "candidate_cap_reached": cap_reached}


def anderson_nss_adjacent(core, limit=MAX_ENUMERATED):
    """Adapt the two documented NSS adjacency regex alternatives.

    After the 0x11 marker, the published alternatives place a 0x30 length at
    offsets 12 or 16 and the 48-byte buffer at offsets 16 or 24, respectively.
    No reference secret, packet, entropy filter, or NSS pointer is consulted.
    """
    if not 1 <= limit <= MAX_ENUMERATED:
        raise ValueError("Candidate limit must be between 1 and 10000")
    result = {}
    matches = 0
    timed_out = False
    cap_reached = False
    try:
        for address in core.find(b"\x11\x00\x00\x00"):
            for length_offset, secret_offset in ((12, 16), (16, 24)):
                try:
                    if core.read(address + length_offset, 4) != b"\x30\x00\x00\x00":
                        continue
                    value = core.read(address + secret_offset, SECRET_BYTES)
                except ValueError:
                    continue
                matches += 1
                row = _candidate(value, {"marker": hex(address),
                                         "data": hex(address + secret_offset),
                                         "published_alternative": 1 if length_offset == 12 else 2})
                if row["id"] in result:
                    result[row["id"]]["locations"].extend(row["locations"])
                else:
                    result[row["id"]] = row
                    if len(result) == limit:
                        cap_reached = True
                        break
            if cap_reached:
                break
    except TimeoutError:
        timed_out = True
    return list(result.values()), {"pattern_matches": matches,
                                   "unique_candidates": len(result),
                                   "search_exhausted": not (timed_out or cap_reached),
                                   "search_timed_out": timed_out,
                                   "candidate_cap_reached": cap_reached}


def xray_full_snapshot_entropy(core, limit=MAX_ENUMERATED):
    """Adapt X-Ray-TLS's *baseline* full-snapshot entropy count to candidates.

    The source baseline scans 48-byte windows at 8-byte steps within pages
    and scores entropy of their 96 hexadecimal characters at threshold 3.6.
    Its source only counts candidates; we retain the best `limit` values so
    that our common assignment stage can test them. This is not X-Ray-TLS's
    live memory-difference method or its patched TShark implementation.
    """
    if not 1 <= limit <= MAX_ENUMERATED:
        raise ValueError("Candidate limit must be between 1 and 10000")
    selected = {}
    heap = []
    windows = 0
    zero_pages = 0
    qualifying = 0
    timed_out = False
    cap_reached = False
    try:
        for base, size, offset, flags in core.segments:
            if not flags & 2:  # The X-Ray snapshot reads writable mappings.
                continue
            for page_start in range(0, size, 4096):
                page = core.data[offset + page_start:offset + min(size, page_start + 4096)]
                if not any(page):
                    zero_pages += 1
                    continue
                # The source baseline's range excludes the final possible
                # window in each page; retain that boundary for fidelity.
                for position in range(0, len(page) - SECRET_BYTES, 8):
                    value = page[position:position + SECRET_BYTES]
                    digits = value.hex()
                    counts = Counter(digits)
                    score = -sum((count / len(digits)) * math.log2(count / len(digits))
                                 for count in counts.values())
                    windows += 1
                    if score < 3.6:
                        continue
                    qualifying += 1
                    row = _candidate(value, {"data": hex(base + page_start + position)})
                    identity = row["id"]
                    if identity in selected:
                        selected[identity][1]["locations"].extend(row["locations"])
                        continue
                    priority = (score, identity)
                    if len(heap) < limit:
                        heapq.heappush(heap, priority)
                        selected[identity] = (score, row)
                    else:
                        cap_reached = True
                        if priority > heap[0]:
                            _, removed = heapq.heapreplace(heap, priority)
                            del selected[removed]
                            selected[identity] = (score, row)
    except TimeoutError:
        timed_out = True
    rows = [row for _, row in selected.values()]
    rows.sort(key=lambda row: (-selected[row["id"]][0], row["id"]))
    return rows, {"windows_scanned": windows, "zero_pages_skipped": zero_pages,
                  "qualifying_windows": qualifying, "unique_candidates": len(rows),
                  "search_exhausted": not timed_out, "search_timed_out": timed_out,
                  "candidate_cap_reached": cap_reached,
                  "entropy_unit": "bits_per_hex_character",
                  "writable_segments_only": True}
