# Third-party notices

The project code is Apache-2.0. Upstream corpus material retains its original license.
Frozen Terraform sources, derived plans and scanner baselines are retained for reproducible research.
The corpus manifests record inputs, transformations and license identifiers. Full upstream license texts follow.

| Upstream | Frozen commit | License file |
|---|---|---|
| [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat/tree/abf1ba8f5e47d7ced750fdfa025d51c99f1a43ed) | `abf1ba8f5e47d7ced750fdfa025d51c99f1a43ed` | [LICENSE](third-party/RhinoSecurityLabs--cloudgoat--LICENSE) |
| [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat/tree/729f8da62c6a85ce4af5ad3d123de97776d954c4) | `729f8da62c6a85ce4af5ad3d123de97776d954c4` | [LICENSE](third-party/bridgecrewio--terragoat--LICENSE) |
| [BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable/tree/0f298666f9b7cfa01488b86912afdb211773188a) | `0f298666f9b7cfa01488b86912afdb211773188a` | [LICENSE](third-party/BishopFox--iam-vulnerable--LICENSE) |
| [tenable/KaiMonkey](https://github.com/tenable/KaiMonkey/tree/3feb0bf1a5ab81a79f225407a5ed16db3acd59a4) | `3feb0bf1a5ab81a79f225407a5ed16db3acd59a4` | [LICENSE](third-party/tenable--KaiMonkey--LICENSE) |
| [ine-labs/AWSGoat](https://github.com/ine-labs/AWSGoat/tree/b24869ad455ed8d1393d00ecdc15ee638d1c1332) | `b24869ad455ed8d1393d00ecdc15ee638d1c1332` | [LICENSE](third-party/ine-labs--AWSGoat--LICENSE) |
| [terraform-aws-modules/terraform-aws-vpc](https://github.com/terraform-aws-modules/terraform-aws-vpc/tree/b3abd6df2ecf052451a361ed55b8f06f8742a795) | `b3abd6df2ecf052451a361ed55b8f06f8742a795` | [LICENSE](third-party/terraform-aws-modules--terraform-aws-vpc--LICENSE) |
| [terraform-aws-modules/terraform-aws-security-group](https://github.com/terraform-aws-modules/terraform-aws-security-group/tree/b3c1b2e8beff9671960f874f5569d77c803b0127) | `b3c1b2e8beff9671960f874f5569d77c803b0127` | [LICENSE](third-party/terraform-aws-modules--terraform-aws-security-group--LICENSE) |
| [terraform-aws-modules/terraform-aws-s3-bucket](https://github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/8a0b697adfbc673e6135c70246cff7f8052ad95a) | `8a0b697adfbc673e6135c70246cff7f8052ad95a` | [LICENSE](third-party/terraform-aws-modules--terraform-aws-s3-bucket--LICENSE) |
| [terraform-aws-modules/terraform-aws-rds](https://github.com/terraform-aws-modules/terraform-aws-rds/tree/7c83995e3898fff639c74ce4cc7a72e61e7952c6) | `7c83995e3898fff639c74ce4cc7a72e61e7952c6` | [LICENSE](third-party/terraform-aws-modules--terraform-aws-rds--LICENSE) |
| [terraform-aws-modules/terraform-aws-iam](https://github.com/terraform-aws-modules/terraform-aws-iam/tree/da8e6a8673933ee651f0f0fe611d5ac6b9f9bcb9) | `da8e6a8673933ee651f0f0fe611d5ac6b9f9bcb9` | [LICENSE](third-party/terraform-aws-modules--terraform-aws-iam--LICENSE) |

Vendored source: `evaluations/tier2/sources/cloudgoat-*` comes from the pinned CloudGoat scenarios.
Other corpus provenance: `evaluations/tier2/manifest.yaml`, `evaluations/realworld/manifest.yaml`,
`evaluations/terrara/manifest.yaml`. Retrieval hashes and two corrected full-SHA references are in
[the upstream verification receipt](third-party/upstream-verification.json).

TerrARA has no redistributable license at the pinned revision. Its hand-crafted source and plans are excluded;
only our comparison metadata/results and references are included. Optional local reproduction is separate.

Python libraries and optional external tools are installed separately under their respective licenses; their
versions are recorded in `pyproject.toml`, `scripts/fetch-tools.sh` and evaluation manifests.
No model weights or third-party executable binaries are included in the source snapshot.
