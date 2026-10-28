"""Build a moto AMI catalogue: moto's defaults plus stand-ins for the Ubuntu images CloudGoat queries.

The stand-ins are not real AMIs; they only let `data "aws_ami"` lookups resolve during an offline plan.
"""
import glob
import gzip
import json
import os
import sys

import moto

M = os.path.dirname(moto.__file__)
amis = json.loads(gzip.decompress(open(f"{M}/ec2/resources/amis.json.gz", "rb").read()))
for region in ("us-east-1", "us-west-2"):
    for sub in ("latest_amis", "ecs/optimized_amis"):
        for p in glob.glob(f"{M}/ec2/resources/{sub}/{region}.json*"):
            raw = open(p, "rb").read()
            amis += json.loads(gzip.decompress(raw) if p.endswith(".gz") else raw)
tmpl = dict(amis[0])
for owner in ("099720109477", "137112412989"):  # Canonical, Amazon
    for tag, name in (("focal", "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20260101"),  # KaiMonkey
                      ("jammy", "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20260101"),
                      ("noble", "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260101")):
        a = dict(tmpl)
        a.update({"ami_id": f"ami-0tapm{owner[:6]}{tag}", "name": name, "owner_id": owner, "architecture": "x86_64",
                  "virtualization_type": "hvm", "root_device_type": "ebs", "public": True, "state": "available",
                  "description": "tapm offline plan stand-in (not a real AMI)", "creation_date": "2026-01-01T00:00:00.000Z"})
        amis.append(a)
os.makedirs(os.path.dirname(os.path.abspath(sys.argv[1])), exist_ok=True)
json.dump(amis, open(sys.argv[1], "w"))
print(f"{len(amis)} AMIs -> {sys.argv[1]}")
