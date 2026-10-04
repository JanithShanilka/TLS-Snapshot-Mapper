"""Controller-owned cryptographic commitments; recovery never sees the key."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat


INPUT_NAMES = ("memory.core", "traffic.pcap", "target.json")
OUTPUT_NAMES = ("candidates.private.json", "decisions.json", "seal.json")
TOOL_NAMES = {
    "blind_tls13": ("blind_server.py", "capture_blind.py", "capture_decoy.py",
                    "record_auth.py", "recover.py", "evaluate.py", "run_study.py",
                    "summarize.py"),
    "offline_memory": ("capture_firefox.py", "core_memory.py", "rank_tls13.py",
                       "rank_core.py", "tls13_packets.py"),
}


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_hashes(folder: Path, names):
    hashes = {}
    for name in names:
        path = folder / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"Unexpected evidence file type or hardlink: {name}")
        hashes[name] = {"sha256": sha256(path), "bytes": info.st_size}
    return hashes


def tool_hashes(tools: Path):
    result = {}
    for directory, names in TOOL_NAMES.items():
        for name, evidence in file_hashes(tools / directory, names).items():
            result[f"{directory}/{name}"] = evidence
    return result


def key_at(path: Path):
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise ValueError("Controller key permissions are too open")
        value = path.read_bytes()
        if len(value) != 32:
            raise ValueError("Invalid controller key")
        return value
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    value = os.urandom(32)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def seal_record(key: bytes, record: dict):
    return {"record": record, "hmac_sha256": hmac.new(key, canonical(record), hashlib.sha256).hexdigest()}


def verify_record(key: bytes, envelope: dict):
    expected = hmac.new(key, canonical(envelope["record"]), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["hmac_sha256"]):
        raise ValueError("Controller seal signature mismatch")
    return envelope["record"]


def verify_evidence(key: bytes, envelope_path: Path, inputs: Path, result: Path, tools: Path):
    record = verify_record(key, json.loads(envelope_path.read_text()))
    if record["inputs"] != file_hashes(inputs, INPUT_NAMES):
        raise ValueError("Sealed input changed")
    if record["outputs"] != file_hashes(result, OUTPUT_NAMES):
        raise ValueError("Sealed output changed")
    if record["tools"] != tool_hashes(tools):
        raise ValueError("Frozen software changed")
    return record
