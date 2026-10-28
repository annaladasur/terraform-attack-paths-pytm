"""Generate plan.json.gz and baseline scanner files for the 5 held-out CloudGoat scenarios."""

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
    "rds", "dynamodb", "sns", "sqs", "elasticbeanstalk", "codebuild"
]

SCENARIOS = [
    {
        "name": "beanstalk_secrets",
        "rel_path": "cloudgoat/scenarios/aws/beanstalk_secrets",
        "vars": {"cgid": "tapmcg", "profile": "default", "cg_whitelist": ["203.0.113.10/32"]},
        "context_parent": False,
    },
    {
        "name": "secrets_in_the_cloud",
        "rel_path": "cloudgoat/scenarios/aws/secrets_in_the_cloud",
        "vars": {"cgid": "tapmcg", "profile": "default", "cg_whitelist": ["203.0.113.10/32"]},
        "context_parent": False,
    },
    {
        "name": "vpc_peering_overexposed",
        "rel_path": "cloudgoat/scenarios/aws/vpc_peering_overexposed",
        "vars": {"cgid": "tapmcg", "profile": "default", "cg_whitelist": ["203.0.113.10/32"]},
        "context_parent": False,
    },
    {
        "name": "rds_snapshot",
        "rel_path": "cloudgoat/scenarios/aws/rds_snapshot",
        "vars": {"cgid": "tapmcg", "profile": "default", "cg_whitelist": ["203.0.113.10/32"]},
        "context_parent": True,
    },
    {
        "name": "codebuild_secrets",
        "rel_path": "cloudgoat/scenarios/aws/codebuild_secrets",
        "vars": {"cgid": "tapm", "profile": "default", "cg_whitelist": ["203.0.113.10/32"]},
        "context_parent": True,
    },
]

import sys

def write_gz(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        gz.write(text.encode("utf-8"))

def plan_and_scan(sc: dict, force: bool = False):
    name = sc["name"]
    rel_path = sc["rel_path"]
    vars_dict = sc["vars"]
    context_parent = sc["context_parent"]
    
    plan_out = PROJECT_ROOT / "evaluations/tier2/plans" / f"cloudgoat-{name}.json.gz"
    base_dir = PROJECT_ROOT / "evaluations/tier2/baselines" / f"cloudgoat-{name}"
    
    cg_root = PROJECT_ROOT / ".tools/tier2-repos/rhinosecuritylabs/cloudgoat"
    scenario_dir = cg_root / rel_path
    tf_dir = scenario_dir / "terraform"
    
    # Ensure dummy keys exist
    pub = PROJECT_ROOT / "evaluations/tier2/dummy-cloudgoat.pub"
    if pub.exists():
        shutil.copyfile(pub, scenario_dir / "cloudgoat.pub")
        (scenario_dir / "cloudgoat").write_text("dummy-private-key\n")
        
    if force or not plan_out.exists():
        tf_bin = get_pinned_terraform()
        with tempfile.TemporaryDirectory(prefix=f"tapm-plan-{name}-") as tmp:
            tmp_path = Path(tmp)
            if context_parent:
                ctx_dest = tmp_path / "scenario"
                shutil.copytree(scenario_dir, ctx_dest)
                work_dir = ctx_dest / "terraform"
            else:
                work_dir = tmp_path / "terraform"
                shutil.copytree(tf_dir, work_dir)
                
            # Strip profile = var.profile
            provider_file = work_dir / "provider.tf"
            if provider_file.exists():
                content = provider_file.read_text()
                content = content.replace("profile = var.profile", "")
                provider_file.write_text(content)
                
            # Write zz_offline_override.tf
            endpoints_block = "\n".join(f'    {s} = "{MOCK_URL}"' for s in SERVICES)
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
"""
            (work_dir / "zz_offline_override.tf").write_text(override)
            (work_dir / "terraform.tfvars.json").write_text(json.dumps(vars_dict, indent=2))
            
            env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
            env.update({
                "AWS_ACCESS_KEY_ID": "mock",
                "AWS_SECRET_ACCESS_KEY": "mock",
                "AWS_DEFAULT_REGION": vars_dict.get("region", "us-east-1"),
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
                rc = tmp_path / "offline.tfrc"
                rc.write_text(f'provider_installation {{\n  filesystem_mirror {{\n    path = "{mirror}"\n    include = ["registry.terraform.io/hashicorp/*"]\n  }}\n}}\n')
                env["TF_CLI_CONFIG_FILE"] = str(rc)
            
            # init
            p_init = subprocess.run([tf_bin, "init", "-backend=false", "-no-color"], cwd=work_dir, env=env, capture_output=True, text=True)
            if p_init.returncode != 0:
                print(f"[{name}] terraform init failed:\n{p_init.stderr}")
                p_init.check_returncode()
                
            # plan
            p_plan = subprocess.run([tf_bin, "plan", "-input=false", "-no-color", "-refresh=false", "-lock=false", "-out=tfplan", "-var-file=terraform.tfvars.json"],
                           cwd=work_dir, env=env, capture_output=True, text=True)
            if p_plan.returncode != 0:
                print(f"[{name}] terraform plan failed:\n{p_plan.stdout}\n{p_plan.stderr}")
                p_plan.check_returncode()
                
            # show
            show = subprocess.run([tf_bin, "show", "-json", "-no-color", "tfplan"], cwd=work_dir, env=env, check=True, capture_output=True, text=True)
            
            data = json.loads(show.stdout)
            data.pop("timestamp", None)
            plan_json = json.dumps(data, sort_keys=True, indent=1) + "\n"
            
            write_gz(plan_out, plan_json)
            print(f"[{name}] Wrote plan: {plan_out} ({len(plan_json)} bytes raw)")

            meta_file = plan_out.parent / "run-metadata.json"
            meta = {}
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
            meta[name] = {
                "terraform_bin": tf_bin,
                "terraform_version": data.get("terraform_version") or PINNED_TERRAFORM,
                "pinned": PINNED_TERRAFORM,
            }
            meta_file.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(f"[{name}] Plan already exists: {plan_out}")
        
    # Baselines
    if force or not (base_dir / "versions.json").exists():
        print(f"[{name}] Running scanners...")
        run_scanners(tf_dir, base_dir)
        print(f"[{name}] Wrote baselines: {base_dir}")
    else:
        print(f"[{name}] Baselines already exist: {base_dir}")

def main():
    force = "--force" in sys.argv
    for sc in SCENARIOS:
        print(f"Processing {sc['name']}...")
        plan_and_scan(sc, force=force)
    print("All 5 held-out scenarios planned and scanned successfully!")

if __name__ == "__main__":
    main()
