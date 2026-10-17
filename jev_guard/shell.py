"""Conservative shell parsing for the guard's code-side rules.

This is not a shell. It splits a command into simple commands well enough to find
catastrophic patterns and write targets. Anything it can't understand is reported as
`parsed=False` or `complex=True`, and callers treat that as "send to Jev", never as safe.
"""

import os
import re
import shlex
from dataclasses import dataclass, field

SEPARATORS = {";", "&&", "||", "|", "&", "|&", ";;", "(", ")", "$", "{", "}"}
REDIRECTS = {">", ">>", ">|", "<", "<<", "<<<", "&>", "&>>", ">&", "<&", "<>"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", "<>"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
NON_FILE_TARGETS = {"-", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}

# Wrappers that run the command that follows them. Value: options that take an argument.
WRAPPERS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S"},
    "command": set(),
    "builtin": set(),
    "exec": {"-a"},
    "nohup": set(),
    "time": set(),
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-a", "-E", "-s"},
}

ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
MAX_DEPTH = 3


@dataclass
class SimpleCommand:
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)
    sudo: bool = False
    piped_from: "SimpleCommand | None" = None

    @property
    def name(self) -> str:
        return os.path.basename(self.argv[0]).lstrip("\\") if self.argv else ""

    @property
    def args(self) -> list[str]:
        return self.argv[1:]

    def operands(self) -> list[str]:
        """Arguments that aren't options (everything after a bare `--` counts)."""
        out, only_operands = [], False
        for arg in self.args:
            if not only_operands and arg == "--":
                only_operands = True
            elif only_operands or not arg.startswith("-") or arg == "-":
                out.append(arg)
        return out

    def short_flags(self) -> set[str]:
        flags: set[str] = set()
        for arg in self.args:
            if arg == "--":
                break
            if arg.startswith("--"):
                flags.add(arg)
            elif arg.startswith("-") and len(arg) > 1:
                flags.update(f"-{c}" for c in arg[1:])
        return flags


@dataclass
class ParsedCommand:
    raw: str
    commands: list[SimpleCommand]
    parsed: bool = True
    # Command substitution, process substitution, backticks or eval: the parse may miss things.
    complex: bool = False


def _strip_heredocs(text: str) -> str:
    """Drop heredoc bodies so their lines aren't mistaken for commands."""
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        delimiters = [m.group(2) for m in HEREDOC.finditer(line)]
        i += 1
        for delimiter in delimiters:
            while i < len(lines) and lines[i].strip() != delimiter:
                i += 1
            i += 1  # skip the delimiter line
    return "\n".join(out)


def _tokens(text: str) -> list[str]:
    text = _strip_heredocs(text.replace("\\\n", " "))
    # Whole-line comments are dropped. shlex's own comment handling is off because it also
    # cuts at a `#` inside a word (`http://x/#frag`), which could hide the rest of a line;
    # an inline `# comment` is kept as words instead, which can only over-detect.
    text = "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))
    # Newlines and backticks separate commands; inside quotes the substitution only changes
    # the quoted token's text, which keeps it one token.
    text = text.replace("\n", " ; ").replace("`", " ; ")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _unwrap(argv: list[str]) -> tuple[list[str], bool]:
    """Remove leading assignments and wrappers like sudo/env; report whether sudo was used."""
    sudo, i = False, 0
    while i < len(argv):
        word = argv[i]
        name = os.path.basename(word)
        if ASSIGNMENT.match(word):
            i += 1
        elif word in {"{", "}", "!"}:
            i += 1
        elif name in WRAPPERS:
            sudo = sudo or name in {"sudo", "doas"}
            takes_arg = WRAPPERS[name]
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or ASSIGNMENT.match(argv[i])):
                i += 2 if argv[i] in takes_arg else 1
            if name == "timeout" and i < len(argv):
                i += 1  # the duration
            if name == "nice" and i < len(argv) and argv[i].lstrip("-").isdigit():
                i += 1
        else:
            break
    return argv[i:], sudo


def parse(command: str, depth: int = 0) -> ParsedCommand:
    complex_ = any(marker in command for marker in ("$(", "`", "<(", ">(")) or depth > 0
    try:
        tokens = _tokens(command)
    except ValueError:
        return ParsedCommand(command, [], parsed=False, complex=True)

    commands: list[SimpleCommand] = []
    words: list[str] = []
    redirects: list[tuple[str, str]] = []
    pipe_source: SimpleCommand | None = None

    def flush(operator: str | None) -> None:
        nonlocal words, redirects, pipe_source
        argv, sudo = _unwrap(words)
        current = None
        if argv:
            current = SimpleCommand(argv, redirects, sudo, piped_from=pipe_source)
            commands.append(current)
        elif redirects:  # bare redirection such as `> file`
            commands.append(SimpleCommand([":"], redirects, sudo, piped_from=pipe_source))
        pipe_source = current if operator in {"|", "|&"} else None
        words, redirects = [], []

    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in SEPARATORS:
            flush(token)
        elif token in REDIRECTS:
            if words and words[-1].isdigit():
                words.pop()  # fd number such as the 2 in 2>file
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            redirects.append((token, target))
            i += 1
        else:
            words.append(token)
        i += 1
    flush(None)

    # Look inside `bash -c "..."` and `eval ...` so wrapping a command doesn't hide it.
    if depth < MAX_DEPTH:
        for cmd in list(commands):
            inner = None
            if cmd.name in SHELLS and "-c" in cmd.args:
                idx = cmd.args.index("-c")
                inner = cmd.args[idx + 1] if idx + 1 < len(cmd.args) else None
            elif cmd.name == "eval":
                inner = " ".join(cmd.args)
            if inner:
                complex_ = True
                nested = parse(inner, depth + 1)
                for sub in nested.commands:
                    sub.sudo = sub.sudo or cmd.sudo
                commands.extend(nested.commands)
                if not nested.parsed:
                    return ParsedCommand(command, commands, parsed=False, complex=True)

    return ParsedCommand(command, commands, parsed=True, complex=complex_)


def write_targets(cmd: SimpleCommand) -> list[str]:
    """Paths this command would create, modify, move or delete (best effort)."""
    targets = [t for op, t in cmd.redirects if op in WRITE_REDIRECTS and t and not t.isdigit()]
    name, operands = cmd.name, cmd.operands()

    if name in {"rm", "rmdir", "unlink", "shred", "touch", "mkdir", "truncate", "tee",
                "chmod", "chown", "chgrp", "mv"}:
        targets += operands
    elif name in {"cp", "install", "ln", "rsync", "scp"} and operands:
        targets.append(operands[-1])
    elif name == "sed" and any(a.startswith("-i") or a.startswith("--in-place") for a in cmd.args):
        files, script_given, skip = [], False, False
        for arg in cmd.args:
            if skip:
                skip = False
            elif arg in {"-e", "-f", "--expression", "--file"}:
                script_given = skip = True
            elif arg.startswith(("--expression=", "--file=")):
                script_given = True
            elif not arg.startswith("-"):
                files.append(arg)
        targets += files if script_given else files[1:]
    elif name == "dd":
        targets += [a[3:] for a in cmd.args if a.startswith("of=")]
    elif name in {"curl", "wget"}:
        flags = {"curl": ("-o", "--output"), "wget": ("-O", "--output-document")}[name]
        for i, arg in enumerate(cmd.args):
            if arg in flags and i + 1 < len(cmd.args):
                targets.append(cmd.args[i + 1])
            elif arg.startswith(flags[1] + "="):
                targets.append(arg.split("=", 1)[1])

    return [t for t in targets if t not in NON_FILE_TARGETS]
