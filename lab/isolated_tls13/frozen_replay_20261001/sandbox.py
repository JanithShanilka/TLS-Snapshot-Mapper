"""Construct the recovery process's restricted Linux filesystem and namespaces."""

from pathlib import Path


def recovery_command(tools: Path, inputs: Path, output: Path, method: str):
    """Return argv for the frozen recover.py, with no study paths visible inside."""
    if method not in {"structured", "entropy"}:
        raise ValueError("Unknown frozen method")
    for folder in (tools, inputs, output):
        if not folder.is_dir() or folder.is_symlink():
            raise ValueError(f"Unsafe sandbox directory: {folder}")
    if list(output.iterdir()):
        raise ValueError("Output directory must be empty")
    for name in ("memory.core", "traffic.pcap", "target.json"):
        path = inputs / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Missing or unsafe recovery input: {name}")
    if not (tools / "blind_tls13/recover.py").is_file():
        raise ValueError("Frozen recovery script is missing")
    return [
        "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
        "--no-new-privs", "bwrap",
        "--unshare-all", "--unshare-user", "--uid", "1000", "--gid", "1000",
        "--disable-userns",
        "--die-with-parent", "--new-session",
        "--clearenv", "--setenv", "HOME", "/out", "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--setenv", "LC_ALL", "C",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/sbin", "/sbin",
        "--ro-bind", str(tools), "/app", "--ro-bind", str(inputs), "/input",
        "--bind", str(output), "/out", "--dir", "/tmp", "--proc", "/proc",
        "--dev", "/dev", "--chdir", "/out", "--",
        "/usr/bin/python3", "/app/blind_tls13/recover.py",
        "--core", "/input/memory.core", "--pcap", "/input/traffic.pcap",
        "--metadata", "/input/target.json", "--method", method,
        "--output", "/out/result",
    ]


def probe_command(tools: Path, inputs: Path, output: Path, controller: Path, port: int):
    if not 0 < port < 65536:
        raise ValueError("Invalid loopback probe port")
    argv = recovery_command(tools, inputs, output, "structured")
    argv[argv.index("--chdir"):argv.index("--chdir")] = [
        "--ro-bind", str(controller), "/controller"]
    separator = argv.index("--", argv.index("bwrap") + 1)
    return argv[:separator + 1] + ["/usr/bin/python3", "/controller/probe.py", str(port)]
