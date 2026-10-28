"""Generate plan.json.gz and baseline scanner files for the 5 real-world benign modules."""

import gzip
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from tapm.scanners.run import run_scanners
from tapm.terraform.offline_plan import PINNED_TERRAFORM, get_pinned_terraform
from tapm.util import PROJECT_ROOT

MOCK_URL = "http://127.0.0.1:5055"
SERVICES = [
    "sts", "iam", "ec2", "s3", "lambda", "kms", "secretsmanager", "ssm",
    "rds", "dynamodb", "sns", "sqs"
]

MODULES = [
    {
        "id": "realworld-vpc-complete",
        "repo_dir": PROJECT_ROOT / ".tools/realworld-repos/terraform-aws-modules/terraform-aws-vpc",
        "subpath": "examples/complete",
        "region": "eu-west-1",
        "has_alias_provider": False,
    },
    {
        "id": "realworld-security-group-complete",
        "repo_dir": PROJECT_ROOT / ".tools/realworld-repos/terraform-aws-modules/terraform-aws-security-group",
        "subpath": "examples/complete",
        "region": "eu-west-1",
        "has_alias_provider": False,
    },
    {
        "id": "realworld-s3-bucket-complete",
        "repo_dir": PROJECT_ROOT / ".tools/realworld-repos/terraform-aws-modules/terraform-aws-s3-bucket",
        "subpath": "examples/complete",
        "region": "eu-west-1",
        "has_alias_provider": False,
    },
    {
        "id": "realworld-rds-complete",
        "repo_dir": PROJECT_ROOT / ".tools/realworld-repos/terraform-aws-modules/terraform-aws-rds",
        "subpath": "examples/complete-postgres",
        "region": "eu-west-1",
        "has_alias_provider": True,
    },
    {
        "id": "realworld-iam-role",
        "repo_dir": PROJECT_ROOT / ".tools/realworld-repos/terraform-aws-modules/terraform-aws-iam",
        "subpath": "examples/iam-role",
        "region": "eu-west-1",
        "has_alias_provider": False,
    },
]


import sys


def write_gz(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        gz.write(text.encode("utf-8"))


def plan_and_scan(mod: dict, force: bool = False) -> None:
    case_id = mod["id"]
    repo_dir = mod["repo_dir"]
    subpath = mod["subpath"]
    region = mod["region"]
    has_alias = mod["has_alias_provider"]

    plan_out = PROJECT_ROOT / "evaluations/realworld/plans" / f"{case_id}.json.gz"
    base_dir = PROJECT_ROOT / "evaluations/realworld/baselines" / case_id
    src_dir = repo_dir / subpath

    if force or not plan_out.exists():
        tf_bin = get_pinned_terraform()
        endpoints_block = "\n".join(f'    {s} = "{MOCK_URL}"' for s in SERVICES)
        alias_block = f"""
provider "aws" {{
  alias = "region2"
  region = "eu-central-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  access_key = "mock"
  secret_key = "mock"
  s3_use_path_style = true
  endpoints {{
{endpoints_block}
  }}
}}
""" if has_alias else ""

        override = f"""
provider "aws" {{
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  access_key = "mock"
  secret_key = "mock"
  s3_use_path_style = true
  endpoints {{
{endpoints_block}
  }}
}}
{alias_block}
"""
        override_file = src_dir / "zz_offline_override.tf"
        override_file.write_text(override)

        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        env.update({
            "AWS_ACCESS_KEY_ID": "mock",
            "AWS_SECRET_ACCESS_KEY": "mock",
            "AWS_DEFAULT_REGION": region,
            "AWS_CONFIG_FILE": "/dev/null",
            "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
            "AWS_EC2_METADATA_DISABLED": "true",
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        mirror = os.environ.get("TAPM_PROVIDER_MIRROR") or str(PROJECT_ROOT / ".tools/mirror")
        if mirror and Path(mirror).exists():
            rc = src_dir / "offline.tfrc"
            rc.write_text(f'provider_installation {{\n  filesystem_mirror {{\n    path = "{mirror}"\n    include = ["registry.terraform.io/hashicorp/*"]\n  }}\n}}\n')
            env["TF_CLI_CONFIG_FILE"] = str(rc)

        lock_file = src_dir / ".terraform.lock.hcl"
        if lock_file.exists():
            lock_file.unlink()

        try:
            print(f"[{case_id}] Running terraform init...")
            p_init = subprocess.run([tf_bin, "init", "-backend=false", "-no-color", "-upgrade"], cwd=src_dir, env=env, capture_output=True, text=True)
            if p_init.returncode != 0:
                print(f"[{case_id}] terraform init stderr:\n{p_init.stderr}")
                p_init.check_returncode()

            print(f"[{case_id}] Running terraform plan...")
            p_plan = subprocess.run([tf_bin, "plan", "-input=false", "-no-color", "-refresh=false", "-lock=false", "-out=tfplan"],
                                    cwd=src_dir, env=env, capture_output=True, text=True)
            if p_plan.returncode != 0:
                print(f"[{case_id}] terraform plan stdout:\n{p_plan.stdout}\nstderr:\n{p_plan.stderr}")
                p_plan.check_returncode()

            print(f"[{case_id}] Running terraform show...")
            show = subprocess.run([tf_bin, "show", "-json", "-no-color", "tfplan"], cwd=src_dir, env=env, check=True, capture_output=True, text=True)

            data = json.loads(show.stdout)
            data.pop("timestamp", None)
            plan_json = json.dumps(data, sort_keys=True, indent=1) + "\n"

            write_gz(plan_out, plan_json)
            print(f"[{case_id}] Wrote plan: {plan_out} ({len(plan_json)} bytes raw)")

            meta_file = plan_out.parent / "run-metadata.json"
            meta = {}
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
            meta[case_id] = {
                "terraform_bin": tf_bin,
                "terraform_version": data.get("terraform_version") or PINNED_TERRAFORM,
                "pinned": PINNED_TERRAFORM,
            }
            meta_file.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        finally:
            if override_file.exists():
                override_file.unlink()
            tfrc_file = src_dir / "offline.tfrc"
            if tfrc_file.exists():
                tfrc_file.unlink()
            tfplan_file = src_dir / "tfplan"
            if tfplan_file.exists():
                tfplan_file.unlink()
    else:
        print(f"[{case_id}] Plan already exists: {plan_out}")

    # Baseline scanner findings
    if force or not (base_dir / "versions.json").exists():
        print(f"[{case_id}] Running scanners on clean source...")
        base_dir.mkdir(parents=True, exist_ok=True)
        run_scanners(src_dir, base_dir)
        print(f"[{case_id}] Wrote baselines: {base_dir}")
    else:
        print(f"[{case_id}] Baselines already exist: {base_dir}")


def main() -> None:
    force = "--force" in sys.argv
    for mod in MODULES:
        print(f"Processing {mod['id']}...")
        plan_and_scan(mod, force=force)
    print("All 5 real-world benign modules planned and scanned successfully!")


if __name__ == "__main__":
    main()
