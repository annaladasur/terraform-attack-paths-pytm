"""terraform-attack-paths-pytm: Terraform plan -> security graph -> PyTM -> attack paths.

Security truth is produced by deterministic code in this package. The ``tapm.ai``
subpackage may only *annotate* that truth, and every annotation must pass the
deterministic validator in ``tapm.ai.validator`` before it is reported.
"""

__version__ = "0.1.0"
SCHEMA_VERSION = "1"
PROMPT_VERSION = "v1"
SCOPE_STATEMENT = (
    "Terraform-visible identity, resource, trust and boundary policies; "
    "conditions are flagged, not evaluated; SCPs, RCPs and session policies are out of scope."
)
