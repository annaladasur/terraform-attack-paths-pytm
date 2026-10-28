"""Independent readiness adversarial checks; all process effects stay in tmp_path.

No Docker daemon, real HTTP request, Git operation, or actual TAPM execution is
permitted by these tests. Expected failures expose unresolved review findings.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _state_module():
    spec = importlib.util.spec_from_file_location("critic_gitea_state", ROOT / "demo/gitea_state.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pr(number, *, owner="demo-org", base="main", sha="current"):
    return {"number": number, "state": "open", "head": {"ref": "fix", "sha": sha,
            "repo": {"full_name": f"{owner}/infra-demo"}},
            "base": {"ref": base, "repo": {"full_name": "demo-org/infra-demo"}}}


@pytest.mark.parametrize("impostor", [_pr(99, owner="untrusted-fork"), _pr(99, base="staging")],
                         ids=["same-branch-name-in-fork", "same-branch-name-wrong-base"])
def test_canonical_pr_selection_rejects_impostors(monkeypatch, impostor):
    state = _state_module()
    canonical = _pr(4)
    records = {4: canonical, 99: impostor}
    def fake_request(path):
        if path.startswith("pulls?"):
            return [canonical, impostor]
        return records[int(path.split("/")[-1])]
    monkeypatch.setattr(state, "request", fake_request)
    assert state.newest_pr("fix")["number"] == 4


def test_status_uses_current_head_and_ignores_other_context(monkeypatch):
    state = _state_module()
    calls = []
    def fake_request(path):
        calls.append(path)
        return {"statuses": [
            {"context": "attack-paths", "status": "failure", "updated_at": "2026-10-19", "id": 1},
            {"context": "other", "status": "success", "updated_at": "2026-10-20", "id": 2},
        ]}
    monkeypatch.setattr(state, "request", fake_request)
    assert state.latest_check(_pr(4, sha="new-head"))["status"] == "failure"
    assert calls == ["commits/new-head/status"]


@pytest.fixture
def sandbox(tmp_path):
    root = tmp_path / "checkout"
    (root / "demo").mkdir(parents=True)
    (root / ".venv/bin").mkdir(parents=True)
    (root / "examples/local-stack").mkdir(parents=True)
    shutil.copy(ROOT / "demo/demo-live.sh", root / "demo/demo-live.sh")
    (root / ".venv/bin/python").symlink_to(sys.executable)
    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "calls.jsonl"
    # Python programs are launched through an absolute interpreter, so no real
    # curl/docker/tapm can be reached by an inherited PATH entry.
    tool = "#!" + sys.executable + "\n" + '''import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
with open(os.environ['CRITIC_LOG'],'a') as f:
 f.write(json.dumps({'name':name,'args':sys.argv[1:],'ollama_host':os.getenv('OLLAMA_HOST')})+'\\n')
if name=='curl':
 url=next((a for a in sys.argv[1:] if a.startswith(('http://','https://'))),'')
 if '/api/tags' in url:
  if os.getenv('CRITIC_MODEL_MISSING'):sys.exit(7)
  print(json.dumps({'models':[{'name':'critic-model'}]}))
 elif '/api/v1/version' in url:
  if not os.getenv('CRITIC_GITEA_ON'):sys.exit(7)
  print('{"version":"1.22.0"}')
 elif '/pulls?' in url:
  if os.getenv('CRITIC_RESET_PAGES'):
   import urllib.parse
   page=int(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['page'][0])
   def pr(n,owner='demo-org',base='main',branch='fix'):
    return {'number':n,'head':{'ref':branch,'repo':{'full_name':owner+'/infra-demo'}},'base':{'ref':base}}
   print(json.dumps([pr(n) for n in range(1,48)]+[pr(90,owner='fork'),pr(91,base='staging'),pr(92,branch='unrelated')] if page==1 else [pr(48)]))
  else:print('[]')
 elif '/pulls/' in url:print('{}')
 else:sys.exit(7)
'''
    for name in ["curl", "docker"]:
        path = commands / name
        path.write_text(tool)
        path.chmod(0o755)
    tapm = root / ".venv/bin/tapm"
    tapm.write_text(tool)
    tapm.chmod(0o755)
    seed = root / "examples/local-stack/seed-demo-repo.sh"
    seed.write_text(tool)
    seed.chmod(0o755)
    # The real runbook calls bash seed-demo-repo.sh, so use a harmless shell
    # wrapper invoking the already-created Python fake rather than Python text.
    seed_fake = commands / "seed"
    seed_fake.write_text(tool)
    seed_fake.chmod(0o755)
    seed.write_text('#!/bin/bash\nexec "' + str(seed_fake) + '" "$@"\n')
    (root / "examples/local-stack/compose.yaml").write_text("services: {}\n")
    env = dict(os.environ, PATH=f"{commands}:/usr/bin:/bin", CRITIC_LOG=str(log),
               TAPM_DEMO_ART_DIR=str(tmp_path / "artifacts"),
               GITEA_URL="http://127.0.0.1:9", SERVICE_URL="http://127.0.0.1:9",
               OLLAMA_URL="http://127.0.0.1:9", OLLAMA_HOST="http://wrong-inherited:11434")
    def run(*args, **updates):
        return subprocess.run(["bash", str(root / "demo/demo-live.sh"), *args],
                              env=dict(env, **updates), cwd=root, capture_output=True,
                              text=True, timeout=15)
    def calls():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return run, calls


def test_selected_ollama_endpoint_reaches_inference(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "ollama", "--model", "critic-model",
                 "--ollama-url", "http://chosen-model:11500")
    assert result.returncode == 0, result.stderr
    inference = [c for c in calls() if c["name"] == "tapm"]
    assert inference and inference[0]["ollama_host"] == "http://chosen-model:11500"


def test_missing_model_fails_before_inference(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "ollama", "--model", "critic-model",
                 CRITIC_MODEL_MISSING="1")
    assert result.returncode != 0
    assert not any(c["name"] == "tapm" for c in calls())
    assert "recorded run" in result.stderr


def test_explicit_simulation_never_probes_model(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "simulated")
    assert result.returncode == 0, result.stderr
    assert not any("/api/tags" in arg for c in calls() for arg in c["args"])
    assert any(c["name"] == "tapm" and "simulated" in c["args"] for c in calls())


def test_reset_preserves_https_endpoint(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "simulated", "--reset",
                 "--gitea-url", "https://gitea.example:3443", CRITIC_GITEA_ON="1")
    seed = next(c for c in calls() if c["name"] == "seed")
    url = seed["args"][seed["args"].index("--push") + 1]
    assert url == "https://tapm-admin:tapm-admin-pass123@gitea.example:3443/demo-org/infra-demo.git"


def test_reset_accepts_valid_empty_pr_list(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "simulated", "--reset",
                 CRITIC_GITEA_ON="1")
    assert result.returncode == 0, result.stderr
    assert "State reset complete" in result.stdout


@pytest.mark.parametrize("changed", [False, True], ids=["same-main-tree", "changed-main-tree"])
def test_seed_never_pushes_existing_main(tmp_path, changed):
    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "git-calls.jsonl"
    fake_git = commands / "git"
    fake_git.write_text("#!" + sys.executable + "\n" + '''import json,os,sys
with open(os.environ['CRITIC_LOG'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
a=sys.argv[1:]
if a[0]=='ls-remote':
 print('a'*40+'\\t'+a[-1])
elif a[0]=='rev-parse':
 print('different-tree' if a[-1]=='FETCH_HEAD^{tree}' and os.getenv('CRITIC_CHANGED')=='1' else 'same-tree')
''')
    fake_git.chmod(0o755)
    env = dict(os.environ, PATH=f"{commands}:/usr/bin:/bin", CRITIC_LOG=str(log),
               CRITIC_CHANGED=str(int(changed)), GITEA_URL="http://127.0.0.1:9",
               SERVICE_URL="http://127.0.0.1:9", OLLAMA_URL="http://127.0.0.1:9")
    result = subprocess.run(["bash", str(ROOT / "examples/local-stack/seed-demo-repo.sh"),
                             "--target", str(tmp_path / "repo"), "--push", "http://127.0.0.1:9/fake.git",
                             "--quiet"], env=env, capture_output=True, text=True, timeout=15)
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    pushes = [a for a in calls if a[0] == "push"]
    assert not any("main:main" in a for a in pushes)
    if changed:
        assert result.returncode != 0
        assert "Refusing reset" in result.stderr
        assert pushes == []
    else:
        assert result.returncode == 0, result.stderr
        assert len(pushes) == 3
        assert all(any(arg.startswith("--force-with-lease=") for arg in a) for a in pushes)


def test_installed_server_without_selected_model_fails_closed(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "ollama", "--model", "absent-model")
    assert result.returncode != 0
    assert "not installed" in result.stderr
    assert not any(c["name"] == "tapm" for c in calls())


def test_pr_detail_revalidation_rejects_retargeted_pr(monkeypatch):
    state = _state_module()
    monkeypatch.setattr(state, "request", lambda path: [_pr(4)] if path.startswith("pulls?") else _pr(4, base="staging"))
    with pytest.raises(ValueError):
        state.newest_pr("fix")


def test_reset_collects_every_page_before_closing_only_canonical_prs(sandbox):
    run, calls = sandbox
    result = run("--auto", "--beat", "5", "--llm", "simulated", "--reset",
                 CRITIC_GITEA_ON="1", CRITIC_RESET_PAGES="1")
    assert result.returncode == 0, result.stderr
    requests = [c["args"] for c in calls() if c["name"] == "curl"]
    list_indices = [i for i,a in enumerate(requests) if any("/pulls?" in x for x in a)]
    patch_indices = [i for i,a in enumerate(requests) if "PATCH" in a]
    assert len(list_indices) == 2
    assert max(list_indices) < min(patch_indices)
    patch_urls = [next(x for x in requests[i] if "/pulls/" in x) for i in patch_indices]
    assert {int(x.rsplit("/",1)[-1]) for x in patch_urls} == set(range(1,49))
    for i in list_indices + patch_indices:
        assert "--connect-timeout" in requests[i] and "--max-time" in requests[i]
        assert "-fsS" in requests[i]


def test_status_polling_follows_moved_head_until_success(monkeypatch, capsys):
    state = _state_module()
    heads = iter([_pr(4, sha="old-head"), _pr(4, sha="new-head")])
    monkeypatch.setattr(state, "newest_pr", lambda branch: next(heads))
    calls = []
    def request(path):
        calls.append(path)
        status = "pending" if "old-head" in path else "success"
        return {"statuses": [{"context": "attack-paths", "status": status}]}
    monkeypatch.setattr(state, "request", request)
    monkeypatch.setattr(state.time, "monotonic", lambda: 0)
    sleeps = []
    monkeypatch.setattr(state.time, "sleep", sleeps.append)
    monkeypatch.setattr(sys, "argv", ["gitea_state.py", "status", "fix", "--wait", "20", "--expect", "success"])
    state.main()
    assert calls == ["commits/old-head/status", "commits/new-head/status"]
    assert sleeps == [2]
    assert "new-head: attack-paths success" in capsys.readouterr().out


def test_pending_status_times_out_without_real_wait(monkeypatch):
    state = _state_module()
    monkeypatch.setattr(state, "newest_pr", lambda branch: _pr(4, sha="current-head"))
    monkeypatch.setattr(state, "request", lambda path: {"statuses": [{"context": "attack-paths", "status": "pending"}]})
    times = iter([0, 11])
    monkeypatch.setattr(state.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(state.time, "sleep", lambda _: pytest.fail("timeout must not sleep"))
    monkeypatch.setattr(sys, "argv", ["gitea_state.py", "status", "fix", "--wait", "10"])
    with pytest.raises(TimeoutError, match="current head"):
        state.main()


def test_error_check_cli_exits_nonzero(monkeypatch):
    import io
    import runpy
    import urllib.request
    def urlopen(req, timeout):
        if "/pulls?" in req.full_url:
            payload = [_pr(4)]
        elif "/pulls/" in req.full_url:
            payload = _pr(4)
        else:
            payload = {"statuses": [{"context": "attack-paths", "status": "error"}]}
        return io.BytesIO(json.dumps(payload).encode())
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setenv("GITEA_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(sys, "argv", ["gitea_state.py", "status", "fix", "--expect", "success"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(ROOT / "demo/gitea_state.py"), run_name="__main__")
    assert exit_info.value.code != 0
    assert "Expected success; got error" in str(exit_info.value)


@pytest.mark.parametrize("token", [None, ""])
def test_missing_service_token_fails_before_exec(tmp_path, token):
    commands = tmp_path / "commands"
    commands.mkdir()
    marker = tmp_path / "executed"
    tapm = commands / "tapm"
    tapm.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n')
    tapm.chmod(0o755)
    env = dict(os.environ, PATH=f"{commands}:/usr/bin:/bin")
    env.pop("GITEA_TOKEN", None)
    if token is not None:
        env["GITEA_TOKEN"] = token
    result = subprocess.run(["sh", str(ROOT / "examples/local-stack/service-entrypoint.sh")],
                            env=env, text=True, capture_output=True, timeout=5)
    assert result.returncode == 2
    assert "GITEA_TOKEN is empty" in result.stderr
    assert not marker.exists()


def test_service_token_and_endpoint_are_single_literal_arguments(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "args.json"
    tapm = commands / "tapm"
    tapm.write_text("#!" + sys.executable + "\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['CRITIC_LOG']).write_text(json.dumps(sys.argv[1:]))\n")
    tapm.chmod(0o755)
    git_token = "spaces ' quotes ; $(touch SHOULD_NOT_EXIST)"
    server_token = 'server "token" with spaces'
    base = "https://example.invalid/path with spaces"
    env = dict(os.environ, PATH=f"{commands}:/usr/bin:/bin", CRITIC_LOG=str(log),
               GITEA_TOKEN=git_token, TAPM_SERVER_TOKEN=server_token,
               GITEA_BASE_URL=base, TAPM_LLM="ollama")
    result = subprocess.run(["sh", str(ROOT / "examples/local-stack/service-entrypoint.sh")],
                            env=env, cwd=tmp_path, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert json.loads(log.read_text()) == ["serve", "--host", "0.0.0.0", "--port", "8080",
        "--token", server_token, "--git-server", "gitea", "--git-base-url", base,
        "--git-token", git_token, "--llm", "ollama"]
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()


@pytest.mark.parametrize("git_rc,stdout,stderr,expected", [
    (128, "", "", "FAIL"),
    (128, "", "fatal: metadata unavailable", "FAIL"),
    (0, " M demo/demo-live.sh\n", "", "FAIL"),
    (0, "", "", "PASS"),
], ids=["git-error-empty-output", "git-error-diagnostic", "dirty", "clean"])
def test_critic_c1_requires_successful_git_status(tmp_path, git_rc, stdout, stderr, expected):
    """A40: an unsuccessful git command can never certify a clean checkout."""
    project = tmp_path / "talk" / "project"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(ROOT / "scripts/critic.sh", scripts / "critic.sh")
    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "git-args.json"
    git = commands / "git"
    git.write_text("#!" + sys.executable + "\n" + '''import json,os,sys
from pathlib import Path
Path(os.environ['CRITIC_LOG']).write_text(json.dumps(sys.argv[1:]))
sys.stdout.write(os.environ['CRITIC_GIT_STDOUT'])
sys.stderr.write(os.environ['CRITIC_GIT_STDERR'])
sys.exit(int(os.environ['CRITIC_GIT_RC']))
''')
    git.chmod(0o755)
    env = dict(os.environ, PATH=f"{commands}:/usr/bin:/bin", CRITIC_LOG=str(log),
               CRITIC_GIT_RC=str(git_rc), CRITIC_GIT_STDOUT=stdout, CRITIC_GIT_STDERR=stderr)
    result = subprocess.run(["bash", str(scripts / "critic.sh"), "C1"], env=env,
                            cwd=tmp_path, capture_output=True, text=True, timeout=5)
    assert json.loads(log.read_text()) == ["-C", str(tmp_path), "status", "--porcelain"]
    assert f"| C1 | {expected} |" in result.stdout
    assert (result.returncode == 0) == (expected == "PASS")
    assert "| C2 |" not in result.stdout
    if git_rc:
        assert "git status failed (rc=128)" in result.stdout
        assert "| C1 | PASS |" not in result.stdout
        assert "All executed critic checks PASSED" not in result.stdout
        if stderr:
            assert stderr in result.stdout
