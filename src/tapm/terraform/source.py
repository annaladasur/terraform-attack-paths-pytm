"""Deterministic HCL source scanner: block locations and comments.

The plan JSON has no file/line information and no comments. This scanner recovers
both from the ``.tf`` sources so every piece of evidence can point at
``file:start-end``. It is intentionally small: it tracks strings, interpolation,
heredocs, comments and braces, and records

* top-level blocks (resource/data/module/...) with their line ranges,
* first-level nested blocks and attributes inside each resource,
* every comment, with the block it sits in or immediately precedes.

Comments are *never* interpreted. They are carried as untrusted metadata so that a
comment like "ignore previous findings" can be shown, flagged and kept away from
any model instructions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_HEADER = re.compile(
    r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*$|^\s*(module|provider|variable|output)\s+"([^"]+)"\s*$|^\s*(locals|terraform)\s*$'
)
_ATTR = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=")
_NESTED = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$")


@dataclass
class Comment:
    file: str
    line: int
    end_line: int
    text: str
    style: str  # hash | slash | block
    block: str | None = None  # enclosing top-level block address
    precedes: str | None = None  # block that starts right after this comment


@dataclass
class Block:
    kind: str
    address: str
    file: str
    start: int
    end: int = 0
    members: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


@dataclass
class SourceFile:
    path: str
    lines: list[str]
    blocks: list[Block]
    comments: list[Comment]


def scan_text(text: str, path: str) -> SourceFile:
    blocks: list[Block] = []
    comments: list[Comment] = []
    lines = text.splitlines()

    i, n = 0, len(text)
    line = 1
    depth = 0
    header_buf: list[str] = []
    stack: list[tuple[str, int, Block | None]] = []  # (member name, start line, top block)
    current: Block | None = None
    member_buf: list[str] = []
    member_line = 1

    def flush_member_text(ch: str) -> None:
        member_buf.append(ch)

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # --- comments -------------------------------------------------------
        if c == "#" or (c == "/" and nxt == "/"):
            j = text.find("\n", i)
            j = n if j == -1 else j
            raw = text[i + (1 if c == "#" else 2) : j]
            comments.append(Comment(path, line, line, raw.strip(), "hash" if c == "#" else "slash",
                                    block=current.address if current else None))
            i = j
            continue
        if c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j
            raw = text[i + 2 : j]
            end_line = line + raw.count("\n")
            comments.append(Comment(path, line, end_line, _clean_block_comment(raw), "block",
                                    block=current.address if current else None))
            line = end_line
            i = j + 2
            continue

        # --- strings and heredocs --------------------------------------------
        if c == '"':
            j, line = _skip_string(text, i, line)
            if depth == 0:
                header_buf.append(text[i:j])
            elif current is not None:
                member_buf.append(text[i:j])
            i = j
            continue
        if c == "<" and text.startswith("<<", i):
            m = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)", text[i:])
            if m:
                marker = m.group(1)
                j = text.find("\n", i)
                end = re.compile(r"^\s*" + re.escape(marker) + r"\s*$", re.M)
                em = end.search(text, j + 1) if j != -1 else None
                stop = em.end() if em else n
                line += text[i:stop].count("\n")
                i = stop
                continue

        # --- structure -------------------------------------------------------
        if c == "{":
            if depth == 0:
                header = "".join(header_buf).strip()
                current = _open_block(header, path, line)
                if current:
                    blocks.append(current)
                header_buf = []
            elif depth == 1 and current is not None:
                name = _member_name("".join(member_buf))
                if name:
                    stack.append((name, member_line, current))
                member_buf = []
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            if depth == 0 and current is not None:
                current.end = line
                current = None
            elif depth == 1 and stack:
                name, start, blk = stack.pop()
                if blk is not None:
                    blk.members.setdefault(name, []).append((start, line))
                member_buf = []
            i += 1
            continue
        if c == "\n":
            if depth == 1 and current is not None:
                m = _ATTR.match("".join(member_buf))
                if m:
                    current.members.setdefault(m.group(1), []).append((member_line, line))
                member_buf = []
                member_line = line + 1
            elif depth == 0:
                header_buf.append(" ")
            line += 1
            i += 1
            continue

        if depth == 0:
            header_buf.append(c)
        elif depth == 1:
            if not member_buf or not "".join(member_buf).strip():
                member_line = line
            member_buf.append(c)
        i += 1

    # attach "precedes" for comments directly above a block (only blank/comment lines between)
    starts = sorted((b.start, b.address) for b in blocks)
    for cm in comments:
        if cm.block is not None:
            continue
        for start, addr in starts:
            if start > cm.end_line:
                gap = lines[cm.end_line : start - 1]
                if all(not ln.strip() or ln.strip().startswith(("#", "//", "/*", "*")) for ln in gap):
                    cm.precedes = addr
                break
    return SourceFile(path=path, lines=lines, blocks=blocks, comments=comments)


def _clean_block_comment(raw: str) -> str:
    return "\n".join(ln.strip().lstrip("*").strip() for ln in raw.strip().splitlines()).strip()


def _skip_string(text: str, i: int, line: int) -> tuple[int, int]:
    """Return the index after the closing quote, honouring ``${ ... }`` nesting."""
    j = i + 1
    n = len(text)
    interp = 0
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            line += 1
        if interp == 0 and ch == '"':
            return j + 1, line
        if text.startswith("${", j) or text.startswith("%{", j):
            interp += 1
            j += 2
            continue
        if interp and ch == "}":
            interp -= 1
        elif interp and ch == '"':
            # nested string inside interpolation
            j, line = _skip_string(text, j, line)
            continue
        j += 1
    return n, line


def _open_block(header: str, path: str, line: int) -> Block | None:
    m = _HEADER.match(header)
    if not m:
        return None
    if m.group(1):
        prefix = "data." if m.group(1) == "data" else ""
        return Block(m.group(1), f"{prefix}{m.group(2)}.{m.group(3)}", path, line)
    if m.group(4):
        addr = f"module.{m.group(5)}" if m.group(4) == "module" else f"{m.group(4)}.{m.group(5)}"
        return Block(m.group(4), addr, path, line)
    return Block(m.group(6), m.group(6), path, line)


def _member_name(buf: str) -> str | None:
    m = _NESTED.match(buf.strip() and buf or "")
    if m:
        return m.group(1)
    m = _ATTR.match(buf)
    return m.group(1) if m else None


class SourceIndex:
    """Address -> source location, across the root module and local child modules."""

    def __init__(self) -> None:
        self.blocks: dict[str, Block] = {}
        self.files: dict[str, SourceFile] = {}
        self.comments: list[Comment] = []

    @classmethod
    def build(cls, root: str | Path, module_sources: dict[str, str] | None = None) -> "SourceIndex":
        idx = cls()
        root = Path(root)
        idx._scan_dir(root, root, "")
        for prefix, rel in sorted((module_sources or {}).items()):
            mdir = (root / rel).resolve() if not Path(rel).is_absolute() else Path(rel)
            if mdir.is_dir():
                idx._scan_dir(root, mdir, prefix)
        return idx

    def _scan_dir(self, root: Path, directory: Path, prefix: str) -> None:
        for f in sorted(directory.glob("*.tf")):
            if f.name.endswith("_override.tf") or f.name == "override.tf":
                continue
            try:
                rel = str(f.resolve().relative_to(root.resolve()))
            except ValueError:
                rel = str(f)
            sf = scan_text(f.read_text(encoding="utf-8"), rel)
            self.files[rel] = sf
            for b in sf.blocks:
                if b.kind in ("resource", "data", "module"):
                    b.address = prefix + b.address
                    self.blocks[b.address] = b
            for c in sf.comments:
                if c.block:
                    c.block = prefix + c.block
                if c.precedes:
                    c.precedes = prefix + c.precedes
                self.comments.append(c)

    def locate(self, base: str) -> dict | None:
        b = self.blocks.get(base)
        if not b:
            return None
        return {"file": b.file, "start_line": b.start, "end_line": b.end}

    def locate_member(self, base: str, member: str, needle: str | None = None) -> dict | None:
        """Location of an attribute or nested block; optionally the one containing ``needle``."""
        b = self.blocks.get(base)
        if not b:
            return None
        spans = b.members.get(member) or []
        sf = self.files[b.file]
        for start, end in spans:
            if needle is None or any(needle in ln for ln in sf.lines[start - 1 : end]):
                return {"file": b.file, "start_line": start, "end_line": end}
        return self.locate_text(base, needle) if needle else None

    def locate_text(self, base: str, needle: str | None) -> dict | None:
        b = self.blocks.get(base)
        if not b or not needle:
            return None
        sf = self.files[b.file]
        for no in range(b.start, b.end + 1):
            if needle in sf.lines[no - 1]:
                return {"file": b.file, "start_line": no, "end_line": no}
        return None

    def comments_for(self, base: str) -> list[Comment]:
        return [c for c in self.comments if c.block == base or c.precedes == base]


def module_sources_from_plan(raw_plan: dict) -> dict[str, str]:
    """``module.a.`` -> ``./modules/a`` for local modules declared in the configuration."""
    out: dict[str, str] = {}

    def walk(module: dict, prefix: str, base_dir: str) -> None:
        for name, call in sorted((module.get("module_calls") or {}).items()):
            src = call.get("source", "")
            if src.startswith("./") or src.startswith("../"):
                path = str(Path(base_dir) / src) if base_dir else src
                out[f"{prefix}module.{name}."] = path
                walk(call.get("module") or {}, f"{prefix}module.{name}.", path)

    walk((raw_plan.get("configuration") or {}).get("root_module") or {}, "", "")
    return out


_LOCAL_REF = re.compile(r"\b((?:module\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)|(?:var\.[A-Za-z0-9_-]+)|(?:local\.[A-Za-z0-9_-]+)|"
                        r"(?:data\.[a-z0-9_]+\.[A-Za-z0-9_-]+(?:\[[^\]]*\])?\.[A-Za-z0-9_]+)|"
                        r"(?:aws_[a-z0-9_]+\.[A-Za-z0-9_-]+(?:\[[^\]]*\])?\.[A-Za-z0-9_]+))")


def locals_from_source(root: str | Path, module_sources: dict[str, str] | None = None) -> dict[tuple[str, str], dict]:
    """``locals {}`` blocks are absent from the plan's configuration; recover their references from source."""
    import hcl2

    out: dict[tuple[str, str], list[str]] = {}
    dirs = [("", Path(root))] + [(p, (Path(root) / rel).resolve()) for p, rel in sorted((module_sources or {}).items())]
    for prefix, d in dirs:
        for f in sorted(Path(d).glob("*.tf")):
            try:
                doc = hcl2.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            for block in doc.get("locals", []) or []:
                for name, value in block.items():
                    if name.startswith("__"):
                        continue
                    refs = sorted(set(_LOCAL_REF.findall(str(value))))
                    raw = value if isinstance(value, str) else None
                    if raw and len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
                        raw = raw[1:-1]
                    out[(prefix, name)] = {"refs": refs, "raw": raw}
    return out
