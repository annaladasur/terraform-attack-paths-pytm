#!/usr/bin/env python3
"""Record the live demo for the fallback clips (Task W5.2), then cut and render them.

    python3 scripts/record_demo_live.py record   # needs the live local stack; one real take
    python3 scripts/record_demo_live.py render   # offline: cut, pace, render, manifest, README table
    python3 scripts/record_demo_live.py check    # offline: re-render every clip and compare with manifest.json
    python3 scripts/record_demo_live.py record-slide11   # live stack: a new take of beats 5-7 for the Slide 11 clip

`record` runs `make demo-live AUTO=1 LLM=ollama` under asciinema on the live stack (Gitea, TAPM service, runner,
Ollama) and writes talk/recordings/demo.cast. The demo PRs must be closed first, so the take opens fresh ones and
the runner and service run CI again. The runbook prints a typed line for beat 10 (its fixture is
missing), so beat 10 is recorded on its own with the real benchmark command. Nothing here writes terminal
output: if a service is down, `record` stops.

`render` cuts demo.cast at the runbook's own "BEAT n/10" headers. Event text is never changed: an event that
straddles a cut is split at a line start, and times are rebased to the cut. Those casts stay real time. Where a
command prints more than a screen at once, rows would scroll off before anyone could read them, so render writes a
paced copy (`*.paced.cast`) that delays the rest of the output until every row has been on the 110x30 screen for
PAGE_HOLD_S; the text is unchanged. Each clip is rendered to a 1920x1080 H.264 MP4 (idle-time limit off) from its
paced copy, or from the real-time cast when no row needed holding, and manifest.json lists every hold.

`render` also makes `slide-11-short.mp4` (owner decision D7): beats 5-7 with each model wait cut to SHORT_WAIT_KEPT_S
and every full screen held as long as Slide 11's budget allows (up to SHORT_SCREEN_HOLD_MAX_S). Text is unchanged;
the cut waits and holds are in manifest.json. It is never real time. When `record-slide11` has made
`slide-11-take.cast` (the runbook from beat 5 on, after a runbook change), the clip is cut from that take instead.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RECORDINGS = PROJECT_ROOT.parent / "talk" / "recordings"
LOCAL_STACK = PROJECT_ROOT / "examples" / "local-stack"
DEMO_LIVE = PROJECT_ROOT / "demo" / "demo-live.sh"

COLS, ROWS = 110, 30
FONT_SIZE = 28  # px; 110 columns fill 1888 of 1920 px
LINE_HEIGHT = 1.2
BACKGROUND = "0x282a36"  # agg's default theme background, so the padding matches
LAST_FRAME_S = 2.0
IDLE_LIMIT_OFF = 1_000_000  # seconds; agg compresses pauses longer than this, so never
PAGE_HOLD_S = 2.0  # every row stays on screen at least this long before it scrolls off (CC-2 finding F11)
SHORT_WAIT_OVER_S = 5.0  # Slide 11 short clip: a gap between outputs longer than this is a model wait...
SHORT_WAIT_KEPT_S = 3.0  # ...and is cut to this
SHORT_SCREEN_HOLD_MAX_S = 14  # each full screen, and the last one, is held the longest whole number of seconds up to
SHORT_BUDGET_S = 75.0         # this that keeps the clip within Slide 11's budget

# LLM=ollama: the Makefile defaults LLM to simulated, which would skip the local model. No RESET=1: its re-seed
# force-push is rejected by the stack's branch protection (critic/W5.2.md); the branches are already canonical.
MAIN_COMMAND = "make demo-live AUTO=1 LLM=ollama"
SLIDE11_COMMAND = "bash demo/demo-live.sh --auto --from-beat 5 --llm ollama"  # cut at the beat 8 header
BEAT10_COMMANDS = [
    ".venv/bin/tapm tier2 iam-vulnerable --llm off > artifacts/tier2-iam-vulnerable.log",
    "head -1 artifacts/tier2-iam-vulnerable.log",
]

# (beat, clip name, slide) in runbook order; slides from demo/demo-live.sh print_beat_header calls.
BEATS = [
    (1, "beat-01-pr-diff", 3),
    (2, "beat-02-scanners", 3),
    (3, "beat-03-path", 8),
    (4, "beat-04-model-story-ask", 8),
    (5, "beat-05-explain", 11),
    (6, "beat-06-tamper", 11),
    (7, "beat-07-inject", 11),
    (8, "beat-08-gate", 13),
    (9, "beat-09-remediate", 13),
    (10, "beat-10-scalability", 14),
]

GITEA = os.environ.get("GITEA_URL", "http://localhost:3000")
SERVICE = os.environ.get("SERVICE_URL", "http://localhost:8080")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434")
REPO_API = f"{GITEA}/api/v1/repos/demo-org/infra-demo"
# The commit SHAs and issue number demo/demo-live.sh reads back (beats 3, 8, 9).
RUNBOOK_READS = {
    "issue_comments": 1,
    "status_shas": ["dd5ab75ab915fc948c148718629cd86f5750de09", "1bd7f18f921eb915b1bb24de2d69ef757caa7702"],
}


def utc(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd: list[str], **kw) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout.strip()


def get_json(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def pinned_model() -> str:
    m = re.search(r'^MODEL_NAME="([^"]+)"', DEMO_LIVE.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit(f"cannot read MODEL_NAME from {DEMO_LIVE}")
    return m.group(1)


def tool_versions() -> dict:
    return {
        "asciinema": run(["asciinema", "--version"]),
        "agg": run(["agg", "--version"]),
        "ffmpeg": run(["ffmpeg", "-version"]).splitlines()[0],
    }


# ---------------------------------------------------------------------------------------------- record


def preflight() -> dict:
    """Every service the runbook uses must answer; otherwise stop. Returns what was checked."""
    model = pinned_model()
    checks: dict = {}
    problems = []
    try:
        checks["gitea_version"] = get_json(f"{GITEA}/api/v1/version")["version"]
    except Exception as e:  # noqa: BLE001 - reported, then we stop
        problems.append(f"Gitea {GITEA}: {e}")
    try:
        checks["service_health"] = get_json(f"{SERVICE}/health")["status"]
        if checks["service_health"] != "ok":
            problems.append(f"TAPM service health is {checks['service_health']!r}")
    except Exception as e:  # noqa: BLE001
        problems.append(f"TAPM service {SERVICE}: {e}")
    try:
        names = [m["name"] for m in get_json(f"{OLLAMA}/api/tags")["models"]]
        checks["pinned_model_installed"] = model in names
        if model not in names:
            problems.append("Ollama is up but the model pinned in demo/demo-live.sh is not installed")
        loaded = [m["name"] for m in get_json(f"{OLLAMA}/api/ps").get("models", [])]
        checks["pinned_model_loaded_before"] = model in loaded
    except Exception as e:  # noqa: BLE001
        problems.append(f"Ollama {OLLAMA}: {e}")
    ps = run(["docker", "compose", "-f", str(LOCAL_STACK / "compose.yaml"), "ps", "--format", "json"])
    rows = json.loads(ps) if ps.startswith("[") else [json.loads(x) for x in ps.splitlines() if x.strip()]
    states = {c["Service"]: c["State"] for c in rows}
    checks["compose_services"] = states
    for svc in ("gitea", "runner", "analysis-service"):
        if states.get(svc) != "running":
            problems.append(f"compose service {svc} is {states.get(svc)!r}")
    img = run(["docker", "image", "inspect", "terraform-attack-paths-pytm:latest", "--format", "{{.Id}} {{.Created}}"])
    checks["service_image"], checks["service_image_created"] = img.split(" ", 1)
    if problems:
        sys.exit("stack not ready, nothing recorded:\n  " + "\n  ".join(problems))
    return checks


def gitea_readback(since: str) -> dict:
    """created_at of every Gitea object the runbook reads back, so the README can say which run produced it."""
    prs = get_json(f"{REPO_API}/pulls?state=all&limit=50")
    comments = get_json(f"{REPO_API}/issues/{RUNBOOK_READS['issue_comments']}/comments")
    out = {
        "pulls": [
            {"number": p["number"], "state": p["state"], "head": p["head"]["ref"], "head_sha": p["head"]["sha"],
             "created_at": p["created_at"], "closed_at": p.get("closed_at")}
            for p in prs
        ],
        "runbook_issue": RUNBOOK_READS["issue_comments"],
        "runbook_issue_last_comment_created_at": comments[-1]["created_at"] if comments else None,
        "statuses": {},
        "new_pull_comments": {},
    }
    for sha in RUNBOOK_READS["status_shas"]:
        out["statuses"][sha] = [
            {"context": s["context"], "status": s["status"], "created_at": s["created_at"], "description": s["description"]}
            for s in get_json(f"{REPO_API}/commits/{sha}/statuses")
        ]
    for p in out["pulls"]:
        if p["created_at"] >= since:
            out["new_pull_comments"][str(p["number"])] = [
                c["created_at"] for c in get_json(f"{REPO_API}/issues/{p['number']}/comments")
            ]
    return out


def asciinema(command: str, out: Path) -> int:
    env = {**os.environ, "TERM": "xterm-256color"}
    env.pop("NO_COLOR", None)
    rc = subprocess.run(
        ["asciinema", "rec", "-q", "--headless", "--return", "-f", "asciicast-v2", "--window-size",
         f"{COLS}x{ROWS}", "--capture-env", "SHELL,TERM", "--overwrite", "-c", command, str(out)],
        cwd=PROJECT_ROOT, env=env,
    ).returncode
    return rc


def shown(commands: list[str]) -> str:
    """A bash command line that prints each command after a `$ ` prompt and then runs it."""
    steps = [f"printf '\\033[1m$ %s\\033[0m\\n' {shlex.quote(c)}; {c}" for c in commands]
    return "bash -c " + shlex.quote("set -e; " + "; ".join(steps))


def cmd_record(_a) -> None:
    if run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT):
        sys.exit("working tree not clean; commit or stash before recording")
    if any(p["state"] == "open" for p in get_json(f"{REPO_API}/pulls?state=open")):
        sys.exit("demo PRs are still open; close them so the take opens fresh ones and CI runs again")
    checks = preflight()
    RECORDINGS.mkdir(parents=True, exist_ok=True)
    session = {
        "task": "W5.2",
        "code_sha": run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT),
        "stack_before": checks,
        "tools": tool_versions(),
    }
    model = pinned_model()

    start = dt.datetime.now(dt.timezone.utc).timestamp()
    rc = asciinema(MAIN_COMMAND, RECORDINGS / "demo.cast")
    end = dt.datetime.now(dt.timezone.utc).timestamp()
    session["main"] = {"command": MAIN_COMMAND, "cast": "demo.cast", "exit_code": rc,
                       "wall_start_utc": utc(start), "wall_end_utc": utc(end)}
    timings = PROJECT_ROOT / "artifacts" / "006-public-workload-iam-sensitive-bucket" / "rehearsal-timings.json"
    if timings.exists() and timings.stat().st_mtime >= start:  # written by this take, not an earlier one
        session["main"]["runbook_beat_timer_s"] = json.loads(timings.read_text())["beats"]
    session["gitea_readback"] = gitea_readback(utc(start))
    loaded = [m["name"] for m in get_json(f"{OLLAMA}/api/ps").get("models", [])]
    session["pinned_model_loaded_after_main"] = model in loaded

    b10 = RECORDINGS / "beat-10-scalability.cast"
    start10 = dt.datetime.now(dt.timezone.utc).timestamp()
    rc10 = asciinema(shown(BEAT10_COMMANDS), b10)
    session["beat10"] = {"commands": BEAT10_COMMANDS, "cast": b10.name, "exit_code": rc10,
                         "wall_start_utc": utc(start10)}
    session["tree_dirty_after"] = [x for x in run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT).splitlines()
                                   if "talk/recordings/" not in x]
    (RECORDINGS / "session.json").write_text(json.dumps(session, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: session[k] for k in ("main", "beat10")}, indent=2))
    if rc or rc10:
        sys.exit(f"a recorded command failed (main exit {rc}, beat 10 exit {rc10}); the casts are kept for review")


def cmd_record_slide11(a) -> None:
    """A new take of beats 5-7 (the runbook from beat 5 on) for the Slide 11 short clip.

    --runbook-ref REF runs the take with demo/demo-live.sh as it is at REF (a runbook fix not yet merged here). The
    file is checked out for the take only, its blob is recorded, and HEAD's copy is restored afterwards.
    """
    if run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT):
        sys.exit("working tree not clean; commit or stash before recording")
    checks = preflight()
    session = {"task": "W5.2 (Slide 11 clip, D7)", "code_sha": run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT),
               "stack_before": checks, "tools": tool_versions()}
    runbook = str(DEMO_LIVE.relative_to(PROJECT_ROOT))
    if a.runbook_ref:
        session["runbook"] = {"path": runbook, "ref": a.runbook_ref,
                              "commit": run(["git", "rev-parse", f"{a.runbook_ref}^{{commit}}"], cwd=PROJECT_ROOT),
                              "blob": run(["git", "rev-parse", f"{a.runbook_ref}:./{runbook}"], cwd=PROJECT_ROOT),
                              "head_blob": run(["git", "rev-parse", f"HEAD:./{runbook}"], cwd=PROJECT_ROOT)}
        run(["git", "checkout", a.runbook_ref, "--", runbook], cwd=PROJECT_ROOT)
    model = pinned_model()
    try:
        start = dt.datetime.now(dt.timezone.utc).timestamp()
        rc = asciinema(SLIDE11_COMMAND, RECORDINGS / "slide-11-take.cast")
        end = dt.datetime.now(dt.timezone.utc).timestamp()
    finally:
        if a.runbook_ref:
            run(["git", "checkout", "HEAD", "--", runbook], cwd=PROJECT_ROOT)
    session["take"] = {"command": SLIDE11_COMMAND, "cast": "slide-11-take.cast", "exit_code": rc,
                       "wall_start_utc": utc(start), "wall_end_utc": utc(end)}
    timings = PROJECT_ROOT / "artifacts" / "006-public-workload-iam-sensitive-bucket" / "rehearsal-timings.json"
    if timings.exists() and timings.stat().st_mtime >= start:
        session["take"]["runbook_beat_timer_s"] = json.loads(timings.read_text())["beats"]
    session["gitea_readback"] = gitea_readback(utc(start))
    loaded = [m["name"] for m in get_json(f"{OLLAMA}/api/ps").get("models", [])]
    session["pinned_model_loaded_after"] = model in loaded
    session["tree_dirty_after"] = [x for x in run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT).splitlines()
                                   if "talk/recordings/" not in x]
    (RECORDINGS / "slide-11-session.json").write_text(json.dumps(session, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(session["take"], indent=2))
    if rc:
        sys.exit(f"the recorded command exited {rc}; the cast is kept for review")


# ---------------------------------------------------------------------------------------------- render


def read_cast(path: Path) -> tuple[dict, list[list]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    if header.get("version") != 2:
        sys.exit(f"{path}: expected asciicast v2")
    return header, [json.loads(x) for x in lines[1:] if x.strip()]


def write_cast(path: Path, header: dict, events: list[list]) -> None:
    body = [json.dumps(header, ensure_ascii=False)] + [json.dumps(e, ensure_ascii=False) for e in events]
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


def find_cuts(events: list[list], numbers: list[int] | None = None) -> dict[int, tuple[int, int]]:
    """For each beat n, (event index, char offset) of the start of the line that opens its header box."""
    cuts: dict[int, tuple[int, int]] = {}
    i0 = 0
    for n in numbers or [b[0] for b in BEATS]:
        marker = f"BEAT {n}/10"
        i = next((k for k in range(i0, len(events)) if events[k][1] == "o" and marker in events[k][2]), None)
        if i is None:
            sys.exit(f"demo.cast: no '{marker}' header")
        # walk back from the marker to the box's top line (╔), then to that line's start
        j, pos = i, events[i][2].index(marker)
        while True:
            top = events[j][2].rfind("╔", 0, pos)
            if top >= 0:
                break
            j, pos = j - 1, len(events[j - 1][2])
        nl = events[j][2].rfind("\n", 0, top)
        cuts[n] = (j, nl + 1)
        i0 = i
    return cuts


def slice_events(events: list[list], a: tuple[int, int], b: tuple[int, int] | None) -> list[list]:
    """Events from cut a up to cut b (exclusive), with times rebased so cut a is t=0. Text is not changed."""
    (ia, ca), t0 = a, events[a[0]][0]
    out = []
    last = len(events) - 1 if b is None else b[0]
    for k in range(ia, last + 1):
        t, kind, data = events[k]
        lo = ca if k == ia else 0
        hi = b[1] if (b is not None and k == b[0]) else len(data)
        if b is not None and k == b[0] and hi == 0:
            break
        piece = data[lo:hi]
        if piece:
            out.append([round(t - t0, 6), kind, piece])
    return out


CSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def cell_width(ch: str) -> int:
    if unicodedata.combining(ch) or ch in "\u200d\ufe0e\ufe0f":
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def pace(events: list[list], cols: int = COLS, rows: int = ROWS, hold: float = PAGE_HOLD_S):
    """Delay output so no row leaves the screen less than `hold` s after its last character was written.

    Models the terminal the casts use (printable text, SGR colour codes, CR, LF, wrap at `cols`). When a line feed
    or a wrap at the bottom row would scroll off a row too early, the event is split at that character and the rest
    of the cast is shifted later. Returns (events, holds); joined text is identical to the input.
    """
    last_write: list[float | None] = [None] * rows  # per screen row, top first
    row, col, pending_wrap, shift = 0, 0, False, 0.0
    out: list[list] = []
    holds: list[dict] = []

    def down(t: float) -> float:
        nonlocal row, shift
        if row < rows - 1:
            row += 1
            return t
        top = last_write.pop(0)
        last_write.append(None)
        if top is not None and t < top + hold:
            delay = top + hold - t
            holds.append({"source_t_s": round(t - shift, 6), "added_s": round(delay, 6)})
            shift += delay
            t += delay
        return t

    for t_src, kind, data in events:
        t = t_src + shift
        start = 0
        pos = 0
        while pos < len(data):
            m = CSI.match(data, pos)
            if m:
                pos = m.end()
                continue
            ch = data[pos]
            before = t
            if ch == "\n":
                pending_wrap = False
                t = down(t)
            elif ch == "\r":
                col, pending_wrap = 0, False
            elif ch >= " ":
                w = cell_width(ch)
                if w and pending_wrap:
                    t = down(t)
                    col, pending_wrap = 0, False
                if w:
                    last_write[row] = t
                    col += w
                    if col >= cols:
                        col, pending_wrap = cols, True
            if t != before:  # a hold: emit what came before it at the old time, the rest later
                if pos > start:
                    out.append([round(before, 6), kind, data[start:pos]])
                start = pos
            pos += 1
        if start < len(data):
            out.append([round(t, 6), kind, data[start:]])
    return out, holds


def cut_waits(events: list[list], over: float = SHORT_WAIT_OVER_S, kept: float = SHORT_WAIT_KEPT_S):
    """Shorten every gap longer than `over` between two events to `kept`. Text is unchanged."""
    out, waits, shift = [], [], 0.0
    for i, (t, kind, data) in enumerate(events):
        if i and t - events[i - 1][0] > over:
            gap = t - events[i - 1][0]
            before = CSI.sub("", "".join(e[2] for e in events[:i])).replace("\r", "").strip().splitlines()
            waits.append({"after_t_s": round(events[i - 1][0], 6), "real_s": round(gap, 6), "kept_s": kept,
                          "after_line": before[-1].strip() if before else ""})
            shift += gap - kept
        out.append([round(t - shift, 6), kind, data])
    return out, waits


def short_clip(events: list[list]):
    """Slide 11 short clip from the real-time beats 5-7 events: model waits cut, then screens held.

    Each screen is held the longest whole number of seconds (at most SHORT_SCREEN_HOLD_MAX_S) for which the clip,
    last screen included, stays within SHORT_BUDGET_S. Returns (events, waits, holds, hold_s).
    """
    cut, waits = cut_waits(events)
    for hold in range(SHORT_SCREEN_HOLD_MAX_S, 0, -1):
        paced, holds = pace(cut, hold=float(hold))
        if paced[-1][0] + hold <= SHORT_BUDGET_S:
            return paced, waits, holds, float(hold)
    sys.exit("the Slide 11 clip does not fit its budget even at 1 s per screen")


def mp4_info(path: Path) -> dict:
    out = run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
               "stream=codec_name,width,height,pix_fmt,avg_frame_rate:format=duration", "-of", "json", str(path)])
    d = json.loads(out)
    s = d["streams"][0]
    return {"codec": s["codec_name"], "width": s["width"], "height": s["height"], "pix_fmt": s["pix_fmt"],
            "fps": s["avg_frame_rate"], "duration_s": round(float(d["format"]["duration"]), 3)}


def render_mp4(cast: Path, mp4: Path, tmp: Path, last_frame: float = LAST_FRAME_S) -> None:
    gif = tmp / (cast.stem + ".gif")
    subprocess.run(["agg", "-q", "--font-size", str(FONT_SIZE), "--line-height", str(LINE_HEIGHT),
                    "--idle-time-limit", str(IDLE_LIMIT_OFF), "--last-frame-duration", str(last_frame),
                    "--no-loop", "--fps-cap", "30", str(cast), str(gif)], check=True)
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(gif), "-vf",
                    f"pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color={BACKGROUND},fps=30,format=yuv420p",
                    "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-movflags", "+faststart", str(mp4)],
                   check=True)


def cmd_render(_a) -> None:
    session = json.loads((RECORDINGS / "session.json").read_text(encoding="utf-8"))
    src = RECORDINGS / "demo.cast"
    header, events = read_cast(src)
    cuts = find_cuts(events)

    clips = []
    for idx, (n, name, slide) in enumerate(BEATS[:-1]):  # beats 1-9 come from demo.cast
        nxt = cuts[BEATS[idx + 1][0]]
        ev = slice_events(events, cuts[n], nxt)
        t_cut = events[cuts[n][0]][0]
        h = {**header, "timestamp": int(header["timestamp"] + t_cut),
             "title": f"demo.cast beat {n}, from source event {cuts[n][0]} char {cuts[n][1]} (t={t_cut:.3f} s)"}
        write_cast(RECORDINGS / f"{name}.cast", h, ev)
        clips.append({"file": f"{name}.mp4", "cast": f"{name}.cast", "beat": n, "slide": slide, "source": "demo.cast",
                      "cut_start": {"event": cuts[n][0], "char": cuts[n][1], "t_s": t_cut},
                      "cut_end": {"event": nxt[0], "char": nxt[1], "t_s": events[nxt[0]][0]},
                      "start_utc": utc(header["timestamp"] + t_cut), "duration_cast_s": ev[-1][0]})
    full = slice_events(events, (0, 0), cuts[10])
    write_cast(RECORDINGS / "demo-full.cast", {**header, "title": "demo.cast up to the beat 10 header"}, full)
    clips.append({"file": "demo-full.mp4", "cast": "demo-full.cast", "beat": "1-9", "slide": "3, 8, 11, 13",
                  "source": "demo.cast", "cut_start": {"event": 0, "char": 0, "t_s": 0.0},
                  "cut_end": {"event": cuts[10][0], "char": cuts[10][1], "t_s": events[cuts[10][0]][0]},
                  "start_utc": utc(header["timestamp"]), "duration_cast_s": full[-1][0]})
    h10, ev10 = read_cast(RECORDINGS / "beat-10-scalability.cast")
    clips.append({"file": "beat-10-scalability.mp4", "cast": "beat-10-scalability.cast", "beat": 10, "slide": 14,
                  "source": "beat-10-scalability.cast (own take; see README)", "commands": BEAT10_COMMANDS,
                  "start_utc": utc(h10["timestamp"]), "duration_cast_s": ev10[-1][0]})

    for c in clips:
        c.update(pace_clip(c["cast"]))

    take = RECORDINGS / "slide-11-take.cast"  # a later take of beats 5-7, when record-slide11 has made one
    s11_name, (s11_header, s11_events) = (take.name, read_cast(take)) if take.exists() else ("demo.cast", (header, events))
    s11_cuts = cuts if s11_name == "demo.cast" else find_cuts(s11_events, [5, 6, 7, 8])
    seg = slice_events(s11_events, s11_cuts[5], s11_cuts[8])
    t5 = s11_events[s11_cuts[5][0]][0]
    write_cast(RECORDINGS / "slide-11.cast", {**s11_header, "timestamp": int(s11_header["timestamp"] + t5),
                                              "title": f"{s11_name} beats 5-7 (Slide 11), real time"}, seg)
    short, waits, holds, hold_s = short_clip(seg)
    write_cast(RECORDINGS / "slide-11-short.cast", {**s11_header, "timestamp": int(s11_header["timestamp"] + t5),
               "title": f"slide-11.cast with model waits cut to {SHORT_WAIT_KEPT_S} s and screens held "
                        f"{hold_s} s; not real time"}, short)
    clips.append({"file": "slide-11-short.mp4", "cast": "slide-11.cast", "beat": "5-7", "slide": 11,
                  "source": s11_name, "command": s11_header.get("command"),
                  "cut_start": {"event": s11_cuts[5][0], "char": s11_cuts[5][1], "t_s": t5},
                  "cut_end": {"event": s11_cuts[8][0], "char": s11_cuts[8][1], "t_s": s11_events[s11_cuts[8][0]][0]},
                  "start_utc": utc(s11_header["timestamp"] + t5), "duration_cast_s": seg[-1][0],
                  "rendered_from": "slide-11-short.cast",
                  "sha256_rendered_from": sha256(RECORDINGS / "slide-11-short.cast"),
                  "real_time": False, "last_frame_s": hold_s, "waits_cut": waits,
                  "paced": {"hold_s": hold_s, "added_s": round(sum(h["added_s"] for h in holds), 3),
                            "holds": holds},
                  "duration_rendered_s": short[-1][0]})
    if s11_name != "demo.cast" and (RECORDINGS / "slide-11-session.json").exists():
        s11_session = json.loads((RECORDINGS / "slide-11-session.json").read_text(encoding="utf-8"))
        clips[-1]["runbook"] = s11_session.get("runbook")

    with tempfile.TemporaryDirectory() as tmp:
        for c in clips:
            mp4 = RECORDINGS / c["file"]
            render_mp4(RECORDINGS / c["rendered_from"], mp4, Path(tmp), c.get("last_frame_s", LAST_FRAME_S))
            c.update(mp4=mp4_info(mp4), sha256_mp4=sha256(mp4), sha256_cast=sha256(RECORDINGS / c["cast"]))
            print(f"{c['file']:28} real {c['duration_cast_s']:8.2f} s  paced +{c['paced']['added_s']:5.2f} s"
                  f"  mp4 {c['mp4']['duration_s']:8.2f} s")

    manifest = {
        "task": "W5.2",
        "generated_by": "scripts/record_demo_live.py render",
        "source": {"file": "demo.cast", "sha256": sha256(src), "command": header.get("command"),
                   "start_utc": utc(header["timestamp"]), "duration_s": events[-1][0], "events": len(events),
                   "cols": header["width"], "rows": header["height"]},
        "session": {k: session[k] for k in ("code_sha", "stack_before", "main", "beat10", "gitea_readback",
                                            "pinned_model_loaded_after_main", "tree_dirty_after")},
        "render": {"font_size_px": FONT_SIZE, "line_height": LINE_HEIGHT, "theme": "agg default",
                   "padding_color": BACKGROUND, "idle_time_limit_s": IDLE_LIMIT_OFF,
                   "last_frame_duration_s": LAST_FRAME_S, "page_hold_s": PAGE_HOLD_S, "screen": f"{COLS}x{ROWS}",
                   "short_clip": {"wait_over_s": SHORT_WAIT_OVER_S, "wait_kept_s": SHORT_WAIT_KEPT_S,
                                  "screen_hold_max_s": SHORT_SCREEN_HOLD_MAX_S, "budget_s": SHORT_BUDGET_S},
                   "tools": {**session["tools"], **tool_versions()}},
        "clips": clips,
    }
    if (RECORDINGS / "slide-11-session.json").exists():
        manifest["slide11_session"] = json.loads((RECORDINGS / "slide-11-session.json").read_text(encoding="utf-8"))
    (RECORDINGS / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                                              encoding="utf-8")
    write_readme_table(manifest)


def pace_clip(cast_name: str) -> dict:
    """Write `<name>.paced.cast` when the cast needs holds (remove a stale one when it doesn't)."""
    header, events = read_cast(RECORDINGS / cast_name)
    paced, holds = pace(events)
    paced_name = cast_name.replace(".cast", ".paced.cast")
    if not holds:
        (RECORDINGS / paced_name).unlink(missing_ok=True)
        return {"rendered_from": cast_name, "paced": {"added_s": 0.0, "holds": []},
                "duration_rendered_s": events[-1][0]}
    title = f"{header.get('title') or cast_name}; paced: rows held {PAGE_HOLD_S} s on a {COLS}x{ROWS} screen"
    write_cast(RECORDINGS / paced_name, {**header, "title": title}, paced)
    return {"rendered_from": paced_name, "sha256_rendered_from": sha256(RECORDINGS / paced_name),
            "paced": {"added_s": round(sum(h["added_s"] for h in holds), 3), "holds": holds},
            "duration_rendered_s": paced[-1][0]}


def cmd_check(_a) -> None:
    """Re-pace and re-render every clip into a temporary folder; compare sha256 with manifest.json."""
    manifest = json.loads((RECORDINGS / "manifest.json").read_text(encoding="utf-8"))
    bad = []
    with tempfile.TemporaryDirectory() as tmp:
        for c in manifest["clips"]:
            header, events = read_cast(RECORDINGS / c["cast"])
            src = RECORDINGS / c["cast"]
            if c["file"] == "slide-11-short.mp4":
                short, _, _, _ = short_clip(events)
                src = Path(tmp) / c["rendered_from"]
                short_header = json.loads((RECORDINGS / c["rendered_from"]).read_text(encoding="utf-8").splitlines()[0])
                write_cast(src, short_header, short)
            else:
                paced, holds = pace(events)
                if holds:
                    src = Path(tmp) / c["rendered_from"]
                    title = f"{header.get('title') or c['cast']}; paced: rows held {PAGE_HOLD_S} s on a {COLS}x{ROWS} screen"
                    write_cast(src, {**header, "title": title}, paced)
            if src.parent != RECORDINGS and sha256(src) != c.get("sha256_rendered_from"):
                bad.append(f"{c['rendered_from']}: re-made cast differs")
            mp4 = Path(tmp) / c["file"]
            render_mp4(src, mp4, Path(tmp), c.get("last_frame_s", LAST_FRAME_S))
            ok = sha256(mp4) == c["sha256_mp4"]
            print(f"{c['file']:28} {'same' if ok else 'DIFFERENT'}")
            if not ok:
                bad.append(f"{c['file']}: re-render differs from manifest sha256")
    if bad:
        sys.exit("\n".join(bad))


def write_readme_table(manifest: dict) -> None:
    readme = RECORDINGS / "README.md"
    if not readme.exists():
        return
    def mmss(secs: float) -> str:
        return f"{int(secs // 60)}:{secs % 60:04.1f}"

    rows = ["| File | Beat | Slide | Starts (UTC) | Run time | Clip length | Paced stretches | What ran |",
            "|---|---|---|---|---|---|---|---|"]
    for c in manifest["clips"]:
        if "commands" in c:
            what = " then ".join(f"`{x}`" for x in c["commands"])
        else:
            what = "`" + (c.get("command") or manifest["source"]["command"]) + "`"
        holds = c["paced"]["holds"]
        if c.get("waits_cut"):
            cut = "; ".join(f"wait at {mmss(w['after_t_s'])} cut from {w['real_s']:.1f} s to {w['kept_s']:.0f} s"
                            for w in c["waits_cut"])
            paced = f"NOT real time: {cut}; each full screen and the last held {c['paced']['hold_s']:.0f} s"
        elif holds:
            at = sorted({mmss(h["source_t_s"]) for h in holds})
            paced = f"{len(holds)} hold{'s' if len(holds) != 1 else ''}, +{c['paced']['added_s']:.1f} s, at run time {', '.join(at)}"
        else:
            paced = "none (real time)"
        rows.append(f"| `{c['file']}` | {c['beat']} | {c['slide']} | {c['start_utc']} | {mmss(c['duration_cast_s'])} | "
                    f"{mmss(c['mp4']['duration_s'])} | {paced} | {what} |")
    text = readme.read_text(encoding="utf-8")
    for begin, end, body in (
        ("<!-- clips:begin (generated by scripts/record_demo_live.py render) -->", "<!-- clips:end -->", rows),
        ("<!-- slide11:begin (generated by scripts/record_demo_live.py render) -->", "<!-- slide11:end -->",
         slide11_lines(next(c for c in manifest["clips"] if c["file"] == "slide-11-short.mp4"))),
    ):
        if begin in text and end in text:
            text = text[: text.index(begin) + len(begin)] + "\n" + "\n".join(body) + "\n" + text[text.index(end):]
    readme.write_text(text, encoding="utf-8")


def slide11_lines(c: dict) -> list[str]:
    """README bullets for the Slide 11 short clip, every number from manifest.json."""
    real, clip = c["duration_cast_s"], c["mp4"]["duration_s"]
    start = dt.datetime.fromisoformat(c["start_utc"].replace("Z", "+00:00"))
    local = start.astimezone(ZoneInfo("America/Chicago"))
    day = local.day
    ordinal = f"{day}{'th' if 10 <= day % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')}"
    take = "the main take" if c["source"] == "demo.cast" else f"a separate take, `{c['command']}`"
    if c.get("runbook"):
        rb = c["runbook"]
        take += f",\n  with `{rb['path']}` from `{rb['ref'].replace('refs/heads/', '')}` @ `{rb['commit'][:7]}`"
    waits = [f"  - {w['real_s']:.1f} s after `{w['after_line']}`" + (";" if i < len(c["waits_cut"]) - 1 else ".")
             for i, w in enumerate(c["waits_cut"])]
    minutes, seconds = divmod(round(real), 60)
    return [
        f"- **What it is.** Beats 5, 6 and 7 of {take}.",
        f"  Cut from `{c['source']}` at the runbook's beat 5 and beat 8 headers (`slide-11.cast`, real time).",
        f"  The segment starts at {c['start_utc']} ({local:%b} {day}, {local:%H:%M %Z}) and really took {real:.1f} s.",
        f"- **What was cut.** The {len(c['waits_cut'])} model waits, each shortened to {c['waits_cut'][0]['kept_s']:.0f} s:",
        *waits,
        f"- **What was held.** Each full screen is held {c['paced']['hold_s']:.0f} s, and so is the last one, so the"
        " speaker can talk over it.",
        f"- **Result.** The clip lasts {clip:.1f} s against the slide's 75 s budget. No text is added, removed or changed.",
        "  `slide-11-short.cast` is the edited timeline, and `manifest.json` lists every cut and hold.",
        "- **Say:**",
        "",
        f"  > \"Here's the same demo, recorded on this laptop on {local:%B} {ordinal}. I've cut out the model's thinking",
        f"  > time: the real run took {minutes} minutes {seconds} seconds.\"",
        "",
        "  Then use the beat 5 and beat 7 lines above. Never call it live or real time.",
    ]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("record", help="one real take on the live stack").set_defaults(fn=cmd_record)
    sub.add_parser("render", help="cut, pace, render and write manifest.json (offline)").set_defaults(fn=cmd_render)
    sub.add_parser("check", help="re-render every clip and compare with manifest.json").set_defaults(fn=cmd_check)
    s11 = sub.add_parser("record-slide11", help="live stack: a new take of beats 5-7 for the Slide 11 clip (D7)")
    s11.add_argument("--runbook-ref", help="run the take with demo/demo-live.sh from this git ref (restored after)")
    s11.set_defaults(fn=cmd_record_slide11)
    a = ap.parse_args()
    for tool in ("asciinema", "agg", "ffmpeg", "ffprobe"):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found (brew install asciinema agg ffmpeg)")
    a.fn(a)


if __name__ == "__main__":
    main()
