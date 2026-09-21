"""Bounded command inspection for built-in exec rule precision; never executes input."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import PurePosixPath
from typing import Any

SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
PERSISTENCE = re.compile(r"authorized_keys|(?:^|/)cron(?:tab|\.[^/]*)?(?:/|$)|/etc/systemd/system(?:/|$)|(?:^|/)(?:\.?profile|\.?bashrc|rc\.local)$", re.I)


def command_argv(value: Any) -> list[str]:
    """Accept argv arrays, their JSON encoding, and shell command strings."""
    if isinstance(value, list):
        return [str(part) for part in value]
    text = str(value or "")
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(part) for part in parsed]
    except (ValueError, TypeError):
        pass
    try:
        return shlex.split(text)
    except ValueError:
        return [text]


def command_segments(value: Any, depth: int = 0) -> list[list[str]]:
    """Unwrap at most four shell levels and split shell control operators.

    This is not a shell interpreter. Unsupported/malformed syntax stays opaque
    and does not qualify for the known-read-only exclusions below. An argv
    argument containing shell punctuation is only parsed for a shell -c body.
    """
    argv = command_argv(value)
    if not argv or depth >= 4:
        return [argv] if argv else []
    start = 1 if PurePosixPath(argv[0]).name == "sudo" else 0
    if len(argv) > start and PurePosixPath(argv[start]).name in SHELLS:
        for i in range(start + 1, len(argv) - 1):
            if argv[i].startswith("-") and "c" in argv[i][1:]:
                return command_segments(argv[i + 1], depth + 1)
    # Native argv must retain argument boundaries, including quoted filenames.
    if isinstance(value, list) or str(value).lstrip().startswith("["):
        return [argv]
    try:
        lexer = shlex.shlex(str(value), posix=True, punctuation_chars=";&|<>\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return [argv]
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token and all(c in ";&|\n" for c in token):
            segments.append([])
        else:
            segments[-1].append(token)
    result = []
    for segment in segments:
        if segment:
            result.extend(command_segments(segment, depth + 1))
    return result


def _persistence_write(argv: list[str]) -> bool:
    """Distinguish known reads/backup sources from writes to persistence paths."""
    if not argv:
        return False
    if argv[0] == "sudo":
        argv = argv[1:]
    if not argv:
        return False
    name = PurePosixPath(argv[0]).name
    for i, token in enumerate(argv[:-1]):
        if token in {">", ">>", "&>", "&>>"} and PERSISTENCE.search(argv[i + 1]):
            return True
    if name in {"useradd", "adduser", "chpasswd"}:
        return True
    if name == "systemctl":
        return "enable" in argv[1:]
    if name == "crontab":
        return not any(arg in {"-l", "--list", "--help", "-h"} for arg in argv[1:])
    if not any(PERSISTENCE.search(arg) for arg in argv[1:]):
        return False
    if any("$(" in arg or "`" in arg for arg in argv):
        return True  # Unresolved substitutions can write even inside a read command.
    if name == "find" and any(arg in {"-exec", "-execdir", "-delete", "-ok", "-okdir"} for arg in argv):
        return True
    if name == "tar":
        # Creating/listing a local backup reads source paths; extraction may write.
        return not any(arg in {"--create", "--list"} or
                       (arg.startswith("-") and any(flag in arg[1:] for flag in "ct") and not arg.startswith("--"))
                       for arg in argv[1:])
    if name in {"ls", "cat", "grep", "egrep", "fgrep", "head", "tail", "stat", "find", "test", "[", "sha256sum", "diff", "echo", "printf"}:
        return False
    if name in {"cp", "install"}:
        # cp/install sources can be persistence files during a local backup.
        for i, arg in enumerate(argv[:-1]):
            if arg in {"-t", "--target-directory"}:
                return bool(PERSISTENCE.search(argv[i + 1]))
        target = next((arg.split("=", 1)[1] for arg in argv if arg.startswith("--target-directory=")), argv[-1])
        return bool(PERSISTENCE.search(target))
    if name == "sed":
        return any(arg.startswith("-i") or arg.startswith("--in-place") for arg in argv[1:])
    # Unknown editors/interpreters keep the candidate; this is not an allowlist.
    return True


def rule_semantics_match(rule_id: str, value: Any) -> bool:
    """Refine built-in candidates while retaining other independent detections."""
    if rule_id == "download_and_execute":
        return _download_execution(value)
    if rule_id == "persistence_modify":
        return any(_persistence_write(argv) for argv in command_segments(value))
    if rule_id == "network_exfil_tools":
        segments = command_segments(value)
        receivers = []
        for argv in segments:
            name = PurePosixPath(argv[0]).name
            receiver = name == "sftp-server" or (
                name == "scp" and any(arg.startswith("-") and not arg.startswith("--") and "t" in arg[1:] for arg in argv[1:]))
            receivers.append(receiver)
        # Suppress only a pure inbound receiver, never a mixed shell sequence.
        return not receivers or not all(receivers)
    return True


def _download_execution(value: Any) -> bool:
    """Require an interpreter pipe/substitution or execution of a saved download.

    Plain HTTP probes and checksum pipes do not prove execution. This handles
    visible shell syntax only; runtime-expanded scripts require correlated data.
    """
    argv = command_argv(value)
    text = " ".join(argv)
    interpreter = r"(?:sudo\s+)?(?:/[\w./-]+/)?(?:sh|bash|dash|zsh|python[\d.]*|php|perl)\b"
    if re.search(r"\b(?:curl|wget|fetch)\b[^;\n]*\|\s*" + interpreter, text):
        return True
    if re.search(interpreter + r"\s+(?:[\w-]+\s+)?[<$]\(\s*(?:curl|wget|fetch)\b", text):
        return True
    downloaded: set[str] = set()
    for segment in command_segments(value):
        name = PurePosixPath(segment[0]).name
        if name in {"curl", "wget", "fetch"}:
            options = {"-o", "--output"} if name == "curl" else {"-O", "--output-document", "-o"}
            for i, arg in enumerate(segment[1:], 1):
                if arg in options and i + 1 < len(segment):
                    downloaded.add(segment[i + 1])
                elif any(arg.startswith(option + "=") for option in options if option.startswith("--")):
                    downloaded.add(arg.split("=", 1)[1])
        elif segment[0] in downloaded or (name in SHELLS | {"python", "python3", "php", "perl"} and any(arg in downloaded for arg in segment[1:])):
            return True
    return False
