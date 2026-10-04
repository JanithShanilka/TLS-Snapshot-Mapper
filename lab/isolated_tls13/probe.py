"""Run inside the sandbox; exit nonzero if isolation fails."""

import json
import os
from pathlib import Path
import socket
import sys


def main():
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        raise RuntimeError("Controller did not supply a network probe port")
    port = int(sys.argv[1])
    allowed = [Path("/input/memory.core"), Path("/input/traffic.pcap"), Path("/input/target.json")]
    if {path.name for path in Path("/input").iterdir()} != {path.name for path in allowed}:
        raise RuntimeError("Recovery input directory contains undeclared files")
    for path in allowed:
        with path.open("rb") as stream:
            if not stream.read(1):
                raise RuntimeError(f"Required input unavailable: {path}")
        try:
            descriptor = os.open(path, os.O_WRONLY)
        except OSError:
            pass
        else:
            os.close(descriptor)
            raise RuntimeError(f"Recovery input is writable: {path}")
    if not Path("/app/blind_tls13/recover.py").is_file():
        raise RuntimeError("Frozen recovery software unavailable")
    marker = Path("/out/probe-marker")
    marker.write_text("sandbox write works\n")
    marker.unlink()
    forbidden = [
        "/root/tlkh-blind-reference", "/home/researcher/research",
        "/mnt/HC_Volume_106994092", "/input/../results",
        "/out/../other-method", "/home/researcher/.ssh", "/etc/shadow",
    ]
    visible = [path for path in forbidden if Path(path).exists()]
    if visible:
        raise RuntimeError(f"Forbidden paths visible: {visible}")
    for target in ("/root", "/mnt", "/home"):
        link = Path("/out/escape")
        link.symlink_to(target)
        try:
            if any(link.iterdir()):
                raise RuntimeError(f"Symlink escaped sandbox: {target}")
        except FileNotFoundError:
            pass
        finally:
            link.unlink()
    if os.getuid() != 1000 or os.getgid() != 1000 or os.getgroups():
        raise RuntimeError("Recovery retained privileged identity or groups")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        try:
            connection.settimeout(2)
            connection.connect(("127.0.0.1", port))
        except OSError:
            pass
        else:
            raise RuntimeError("Recovery can connect to loopback")
    print(json.dumps({"isolation_probe": "passed", "uid": os.getuid(),
                      "visible_forbidden_paths": visible, "network": "denied"}))


if __name__ == "__main__":
    main()
