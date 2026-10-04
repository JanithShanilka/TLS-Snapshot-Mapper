"""Construct the recovery process's restricted Linux filesystem and namespaces."""

from pathlib import Path
import stat


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
    if controller.is_symlink() or not controller.is_dir() or \
            stat.S_IMODE(controller.stat().st_mode) & 0o005 != 0o005:
        raise ValueError("Controller probe mount is not readable by the recovery identity")
    script = controller / "probe.py"
    if script.is_symlink() or not script.is_file() or \
            not stat.S_IMODE(script.stat().st_mode) & 0o004:
        raise ValueError("Sandbox access probe is not readable by the recovery identity")
    argv = recovery_command(tools, inputs, output, "structured")
    argv[argv.index("--chdir"):argv.index("--chdir")] = [
        "--ro-bind", str(controller), "/controller"]
    separator = argv.index("--", argv.index("bwrap") + 1)
    return argv[:separator + 1] + ["/usr/bin/python3", "/controller/probe.py", str(port)]


def comparison_command(tools: Path, comparison: Path, inputs: Path, output: Path,
                       method: str, search_seconds: int, candidate_limit: int):
    if method not in {"structure_only", "anderson_nss_adjacent", "xray_full_snapshot_entropy"}:
        raise ValueError("Unknown comparison method")
    if search_seconds not in {30, 180, 600} or candidate_limit not in {25, 100, 1000}:
        raise ValueError("Comparison budget is not in the predeclared grid")
    if comparison.is_symlink() or not (comparison / "compare_recovery.py").is_file():
        raise ValueError("Comparison software is missing")
    argv = recovery_command(tools, inputs, output, "structured")
    argv[argv.index("--chdir"):argv.index("--chdir")] = [
        "--ro-bind", str(comparison), "/comparison"]
    separator = argv.index("--", argv.index("bwrap") + 1)
    return argv[:separator + 1] + [
        "/usr/bin/python3", "/comparison/compare_recovery.py",
        "--core", "/input/memory.core", "--pcap", "/input/traffic.pcap",
        "--metadata", "/input/target.json", "--tools", "/app",
        "--method", method, "--search-seconds", str(search_seconds),
        "--candidate-limit", str(candidate_limit), "--output", "/out/result"]


def budget_command(tools: Path, controller: Path, inputs: Path, output: Path,
                   method: str, search_seconds: int, candidate_limit: int):
    """Run unchanged historical functions through a budget-only adapter."""
    if method not in {"structured", "entropy"}:
        raise ValueError("Unknown historical method")
    if search_seconds not in {30, 180, 600} or candidate_limit not in {25, 100, 1000}:
        raise ValueError("Budget is outside the predeclared grid")
    if controller.is_symlink() or not (controller / "budget_recovery.py").is_file():
        raise ValueError("Budget adapter is missing")
    argv = recovery_command(tools, inputs, output, "structured")
    argv[argv.index("--chdir"):argv.index("--chdir")] = [
        "--ro-bind", str(controller), "/controller"]
    separator = argv.index("--", argv.index("bwrap") + 1)
    return argv[:separator + 1] + [
        "/usr/bin/python3", "/controller/budget_recovery.py",
        "--core", "/input/memory.core", "--pcap", "/input/traffic.pcap",
        "--metadata", "/input/target.json", "--tools", "/app",
        "--method", method, "--search-seconds", str(search_seconds),
        "--candidate-limit", str(candidate_limit), "--output", "/out/result"]
