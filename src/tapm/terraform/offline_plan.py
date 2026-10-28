"""Produce ``terraform show -json`` output without cloud credentials.

How it stays offline and credential-free:

* the fixture is copied to a temp dir and an ``zz_offline_override.tf`` sets the AWS
  provider's ``skip_credentials_validation`` / ``skip_requesting_account_id`` /
  ``skip_metadata_api_check`` flags (the override never touches your source);
* fake static credentials are injected and any real ``AWS_*`` credentials in the
  environment are removed from the child process;
* fixtures avoid data sources that call AWS (``aws_caller_identity``, ``aws_ami``...),
  so ``terraform plan -refresh=false`` makes no API calls;
* with ``TAPM_PROVIDER_MIRROR`` set, providers come from a local filesystem mirror
  and no registry access is needed.

Plans are cached by a hash of the normalised sources (comments and formatting
whitespace removed, ``plan-cache/``), so editing a comment or re-formatting never
needs a re-plan, and pre-computed lab variants work on machines without Terraform.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..util import PROJECT_ROOT, sha256


CACHE_DIR = PROJECT_ROOT / "plan-cache"


def strip_comments(text: str) -> str:
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(c)
        i += 1
    text = "\n".join(re.sub(r"[ \t]+", " ", ln).rstrip() for ln in "".join(out).splitlines())
    return re.sub(r"\n\s*\n+", "\n", text).strip()


def normalize_source(text: str) -> str:
    """Comments removed, whitespace outside string literals dropped (except one space between
    two identifier characters, so token boundaries survive) and trailing commas removed:
    formatting-only edits (``terraform fmt``, re-indenting, one-line vs. multi-line lists)
    map to the same cache key."""
    t = strip_comments(text)
    out: list[str] = []
    i, n, in_str = 0, len(t), False
    word = lambda ch: ch.isalnum() or ch in "_-"
    while i < n:
        c = t[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(t[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c.isspace():
            j = i
            while j < n and t[j].isspace():
                j += 1
            if out and j < n and word(out[-1]) and word(t[j]):
                out.append(" ")
            i = j
            continue
        else:
            if c in "]})" and out and out[-1] == ",":
                out.pop()
            out.append(c)
        i += 1
    return "".join(out)


def source_key(tf_dir: str | Path) -> str:
    tf_dir = Path(tf_dir)
    parts = []
    for f in sorted(tf_dir.rglob("*.tf")):
        rel = f.relative_to(tf_dir)
        if any(p.startswith(".") for p in rel.parts) or f.name.endswith("_override.tf"):
            continue
        parts.append(f"{rel}\n{normalize_source(f.read_text(encoding='utf-8'))}")
    return sha256("\n\x00\n".join(parts))


PINNED_TERRAFORM = "1.16.4"


def terraform_bin() -> str | None:
    env = os.environ.get("TAPM_TERRAFORM")
    if env and Path(env).exists():
        return env
    default_tool = PROJECT_ROOT / ".tools/bin/terraform"
    if default_tool.exists():
        return str(default_tool)
    return shutil.which("terraform")


def get_pinned_terraform(require_pin: bool = True) -> str:
    """Return the pinned Terraform binary, asserting version == PINNED_TERRAFORM if require_pin is True."""
    exe = terraform_bin()
    if not exe:
        raise RuntimeError("Terraform binary not found. Set TAPM_TERRAFORM or run scripts/fetch-tools.sh")
    if require_pin:
        try:
            proc = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30)
            out = proc.stdout
        except (subprocess.SubprocessError, OSError) as e:
            raise RuntimeError(f"Failed to execute terraform version at '{exe}': {e}")
        match = re.search(r"Terraform\s+v?([0-9]+\.[0-9]+\.[0-9]+)", out)
        ver = match.group(1) if match else "unknown"
        if ver != PINNED_TERRAFORM:
            raise RuntimeError(
                f"Terraform version mismatch: '{exe}' reports {ver}, expected pinned {PINNED_TERRAFORM}. "
                f"Set TAPM_TERRAFORM to the pinned binary or run scripts/fetch-tools.sh."
            )
    return exe


MOCK_SERVICES = ("sts", "iam", "ec2", "s3", "lambda", "kms", "secretsmanager", "ssm", "rds", "dynamodb", "sns", "sqs")


def override_text(tf_dir: Path, mock_aws: str | None, legacy_provider: bool = False) -> str:
    """Provider override: skip credential checks; with ``mock_aws``, send API calls to a local mock (moto)."""
    aliases = sorted(set(re.findall(r'provider\s+"aws"\s*\{[^}]*?alias\s*=\s*"([^"]+)"', "\n".join(
        f.read_text(encoding="utf-8") for f in Path(tf_dir).rglob("*.tf")), re.S)))
    blocks = []
    for alias in [None] + aliases:
        lines = ['provider "aws" {']
        if alias:
            lines.append(f'  alias = "{alias}"')
        lines += ["  skip_credentials_validation = true", "  skip_requesting_account_id  = true",
                  "  skip_metadata_api_check     = true", "  skip_region_validation      = true"]
        if mock_aws:
            path_style = "s3_force_path_style" if legacy_provider else "s3_use_path_style"
            lines += ['  access_key = "mock"', '  secret_key = "mock"', f"  {path_style} = true", "  endpoints {"]
            lines += [f'    {svc} = "{mock_aws}"' for svc in MOCK_SERVICES]
            lines += ["  }"]
        lines.append("}")
        blocks.append("\n".join(lines))
    if has_remote_backend(tf_dir):
        # never touch a real state backend: plan against an empty local one
        blocks.append('terraform {\n  backend "local" {\n    path = "tapm-offline.tfstate"\n  }\n}')
    return "\n\n".join(blocks) + "\n"


def has_remote_backend(tf_dir: Path) -> bool:
    return any(re.search(r'^\s*backend\s+"(?!local")', f.read_text(encoding="utf-8"), re.M)
               for f in Path(tf_dir).glob("*.tf") if not f.name.startswith("zz_offline"))


def plan_fixture(tf_dir: str | Path, out_plan: str | Path, *, use_cache: bool = True, write_cache: bool = True,
                 mock_aws: str | None = None, var_files: list[str] | None = None, variables: dict | None = None,
                 legacy_provider: bool = False, context_dir: str | Path | None = None) -> dict:
    """``context_dir``: copy this ancestor too, for configurations that read files via ``../`` paths."""
    tf_dir, out_plan = Path(tf_dir), Path(out_plan)
    key = source_key(tf_dir)
    cached = CACHE_DIR / f"{key}.json"
    if use_cache and cached.exists():
        shutil.copyfile(cached, out_plan)
        return {"source": "plan-cache", "key": key}
    if use_cache and cached.with_suffix(".json.gz").exists():
        out_plan.write_bytes(gzip.decompress(cached.with_suffix(".json.gz").read_bytes()))
        return {"source": "plan-cache", "key": key}
    tf = terraform_bin()
    if not tf:
        raise RuntimeError(
            "No cached plan for these sources and no terraform binary found.\n"
            "  - install Terraform (>= 1.6) or set TAPM_TERRAFORM, or\n"
            "  - use the Docker image (make docker-demo), or\n"
            "  - revert your edit to one of the pre-computed lab variants (see labs/README.md)."
        )
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update({"AWS_ACCESS_KEY_ID": "offline-plan-only", "AWS_SECRET_ACCESS_KEY": "offline-plan-only",
                "AWS_EC2_METADATA_DISABLED": "true", "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1"})
    with tempfile.TemporaryDirectory(prefix="tapm-plan-") as tmp:
        ignore = shutil.ignore_patterns(".terraform*", "*.tfstate*", "plan.json", "baselines", "gold.yaml", ".git")
        if context_dir:
            ctx = Path(tmp) / "ctx"
            shutil.copytree(Path(context_dir), ctx, ignore=ignore)
            work = ctx / Path(tf_dir).resolve().relative_to(Path(context_dir).resolve())
        else:
            work = Path(tmp) / "src"
            shutil.copytree(tf_dir, work, ignore=ignore)
        (work / "zz_offline_override.tf").write_text(override_text(work, mock_aws, legacy_provider), encoding="utf-8")
        if mock_aws:
            env["NO_PROXY"] = env["no_proxy"] = ",".join(filter(None, [env.get("NO_PROXY", ""), "127.0.0.1", "localhost"]))
        mirror = os.environ.get("TAPM_PROVIDER_MIRROR")
        if mirror:
            rc = Path(tmp) / "offline.tfrc"
            rc.write_text('provider_installation {\n  filesystem_mirror {\n    path = "%s"\n    include = ["registry.terraform.io/hashicorp/*"]\n  }\n}\n' % mirror)
            env["TF_CLI_CONFIG_FILE"] = str(rc)
        init = ["init", "-input=false", "-no-color"] + ([] if has_remote_backend(work) else ["-backend=false"])
        for args in (init,
                     ["plan", "-input=false", "-no-color", "-refresh=false", "-lock=false", "-out=tfplan",
                      *[f"-var-file={Path(v).resolve()}" for v in (var_files or [])],
                      *[f"-var={k}={v}" for k, v in sorted((variables or {}).items())]]):
            p = subprocess.run([tf, *args], cwd=work, env=env, capture_output=True, text=True, timeout=900)
            if p.returncode != 0:
                raise RuntimeError(f"terraform {args[0]} failed:\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
        show = subprocess.run([tf, "show", "-json", "-no-color", "tfplan"], cwd=work, env=env,
                              capture_output=True, text=True, timeout=300)
        if show.returncode != 0:
            raise RuntimeError(f"terraform show failed: {show.stderr[-2000:]}")
    data = json.loads(show.stdout)
    data.pop("timestamp", None)  # the only volatile field; dropped so committed plans are byte-stable
    text = json.dumps(data, sort_keys=True, indent=1) + "\n"
    out_plan.write_text(text, encoding="utf-8")
    if write_cache:
        CACHE_DIR.mkdir(exist_ok=True)
        cached.write_text(text, encoding="utf-8")
    return {"source": "terraform", "key": key, "terraform_version": data.get("terraform_version")}
