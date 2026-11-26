#!/usr/bin/env python3
"""AgentShield: Zero-dependency security & prompt-injection auditor for AI agent configs and MCP setups."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List

__version__ = "0.1.0"

TARGET_FILENAMES = {
    "mcp.json",
    "claude_desktop_config.json",
    "claude.md",
    "agents.md",
    "skill.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
}

TARGET_DIR_HINTS = {".cursor", ".claude", ".vscode", ".github", "skills"}

SECRET_PATTERNS = [
    ("openai-key", "HIGH", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("anthropic-key", "HIGH", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("github-token", "HIGH", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("google-api-key", "HIGH", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("aws-access-key", "HIGH", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack-token", "HIGH", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
]

INJECTION_PATTERNS = [
    (
        "hidden-unicode-bidi",
        "HIGH",
        re.compile(r"[\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]"),
        "Zero-width or bidirectional override character detected (possible hidden prompt injection).",
    ),
    (
        "prompt-override-phrase",
        "MEDIUM",
        re.compile(
            r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+system\s+prompt|"
            r"exfiltrate\s+(?:secrets|env|keys)|send\s+.*\.env\s+to)"
        ),
        "Suspicious instruction-override or data-exfiltration phrase detected.",
    ),
]

EXECUTION_PATTERNS = [
    (
        "pipe-to-shell",
        "HIGH",
        re.compile(r"(?i)(?:curl|wget)\s+[^|\n]+\|\s*(?:ba)?sh\b"),
        "Remote script piped directly to shell.",
    ),
    (
        "destructive-rm",
        "MEDIUM",
        re.compile(r"\brm\s+-[rf]{1,2}\s+(?:/|~|\$HOME)\b"),
        "Potentially destructive recursive delete command targeting root or home directory.",
    ),
    (
        "encoded-shell-exec",
        "MEDIUM",
        re.compile(r"(?i)base64\s+(?:-d|--decode)\s*\|\s*(?:ba)?sh\b"),
        "Base64-decoded payload piped to shell.",
    ),
]

RISKY_MCP_COMMANDS = {"bash", "sh", "zsh", "cmd", "powershell", "pwsh", "curl", "wget"}


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str


def is_target_file(path: Path) -> bool:
    name_lower = path.name.lower()
    if name_lower in TARGET_FILENAMES:
        return True
    if name_lower.endswith(".mcp.json") or name_lower.endswith(".mdc"):
        return True
    parts_lower = {p.lower() for p in path.parts}
    if parts_lower & TARGET_DIR_HINTS and path.suffix.lower() in {".md", ".json", ".yaml", ".yml"}:
        return True
    return False


def iter_target_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for item in root.rglob("*"):
        if any(part in skip_dirs for part in item.parts):
            continue
        if item.is_file() and is_target_file(item):
            yield item


def scan_text_lines(file_path: Path, text: str) -> List[Finding]:
    findings: List[Finding] = []
    rel_path = str(file_path)
    for idx, line in enumerate(text.splitlines(), start=1):
        for rule_id, severity, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        file=rel_path,
                        line=idx,
                        message=f"Potential hardcoded credential ({rule_id}) found.",
                    )
                )
        for rule_id, severity, pattern, msg in INJECTION_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(rule_id=rule_id, severity=severity, file=rel_path, line=idx, message=msg))
        for rule_id, severity, pattern, msg in EXECUTION_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(rule_id=rule_id, severity=severity, file=rel_path, line=idx, message=msg))
    return findings


def scan_mcp_json(file_path: Path, text: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return findings

    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", "")).strip()
        cmd_base = Path(cmd).name.lower() if cmd else ""
        args = cfg.get("args", [])
        args_str = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)

        if cmd_base in RISKY_MCP_COMMANDS:
            findings.append(
                Finding(
                    rule_id="mcp-raw-shell-command",
                    severity="MEDIUM",
                    file=str(file_path),
                    line=1,
                    message=f"MCP server '{name}' invokes raw shell/downloader '{cmd_base}'. Verify args: {args_str[:80]}",
                )
            )
        if "-y" in args_str and "npx" in cmd_base and "@" not in args_str:
            findings.append(
                Finding(
                    rule_id="mcp-unpinned-npx",
                    severity="LOW",
                    file=str(file_path),
                    line=1,
                    message=f"MCP server '{name}' uses 'npx -y' without a pinned version.",
                )
            )
        env = cfg.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                val = str(v)
                if val and not val.startswith("$") and any(t in k.upper() for t in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
                    findings.append(
                        Finding(
                            rule_id="mcp-plaintext-env-secret",
                            severity="HIGH",
                            file=str(file_path),
                            line=1,
                            message=f"MCP server '{name}' may contain a plaintext secret in env var '{k}'. Use env references instead.",
                        )
                    )
    return findings


def scan_path(root: Path) -> List[Finding]:
    all_findings: List[Finding] = []
    for file_path in sorted(iter_target_files(root)):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        all_findings.extend(scan_text_lines(file_path, text))
        if file_path.suffix.lower() == ".json":
            all_findings.extend(scan_mcp_json(file_path, text))
    return all_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Read-only security & prompt-injection auditor for AI coding agents and MCP configs.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output findings as JSON")
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default="high",
        help="Minimum severity that causes a non-zero exit code (default: high)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.path)
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2

    findings = scan_path(target)

    if args.as_json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print(f"[OK] No issues detected in {target.resolve()}")
        else:
            for f in findings:
                print(f"[{f.severity}] {f.file}:{f.line} ({f.rule_id}) - {f.message}")
            print(f"\nTotal findings: {len(findings)}")

    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    threshold = {"none": 99, "low": 1, "medium": 2, "high": 3}[args.fail_on]
    if any(sev_rank.get(f.severity, 0) >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
