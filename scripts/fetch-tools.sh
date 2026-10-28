#!/usr/bin/env bash
# Download the pinned toolchain into .tools/ and verify every artifact against the
# vendor's published SHA256SUMS. Needed only to regenerate plans or scanner
# baselines; the default demo replays committed artifacts and needs none of this.
#
# Scanners are supply chain too: Trivy's March 2026 compromise (CVE-2026-33634)
# shipped a malicious v0.69.4 and hijacked trivy-action tags. Pin exact versions,
# verify checksums, and pin GitHub Actions by commit SHA.
set -euo pipefail

TERRAFORM_VERSION=1.16.4
AWS_PROVIDER_VERSION=6.66.0
TFSEC_VERSION=1.28.14
TRIVY_VERSION=0.74.0
GITLEAKS_VERSION=8.30.0

root="$(cd "$(dirname "$0")/.." && pwd)"
tools="$root/.tools"
mkdir -p "$tools/bin" "$tools/mirror/registry.terraform.io/hashicorp/aws" "$tools/dl"
cd "$tools/dl"

case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac

sha_check() { # file sums-file
  if command -v sha256sum >/dev/null; then grep " $1\$" "$2" | sha256sum -c -; else grep " $1\$" "$2" | shasum -a 256 -c -; fi
}

provider() { # name version mirror-dir: fetch one provider into a filesystem mirror, checksum-verified
  local z="terraform-provider-${1}_${2}_${os}_${arch}.zip"
  mkdir -p "$3/registry.terraform.io/hashicorp/$1"
  curl -fsSLO "https://releases.hashicorp.com/terraform-provider-${1}/${2}/${z}"
  curl -fsSLO "https://releases.hashicorp.com/terraform-provider-${1}/${2}/terraform-provider-${1}_${2}_SHA256SUMS"
  sha_check "$z" "terraform-provider-${1}_${2}_SHA256SUMS"
  cp "$z" "$3/registry.terraform.io/hashicorp/$1/"
}

if [ "${1:-}" = "--terrara" ]; then
  # TerrARA benchmark (evaluations/terrara): samples pin hashicorp/aws ~> 3.x and ~> 5.24, and use a few
  # utility providers. Same Terraform as above; a separate mirror so the Tier 1 plans cannot change.
  m="$tools/terrara-mirror"
  for v in 3.76.1 5.24.0; do echo "== hashicorp/aws $v"; provider aws "$v" "$m"; done
  for pv in archive:2.8.1 null:3.3.2 random:3.9.1 local:2.9.1 tls:4.4.1 template:2.2.0; do
    echo "== hashicorp/${pv%%:*} ${pv#*:}"; provider "${pv%%:*}" "${pv#*:}" "$m"
  done
  echo "TerrARA mirror in $m (export TAPM_PROVIDER_MIRROR_TERRARA=$m)"
  exit 0
fi

echo "== terraform $TERRAFORM_VERSION"
tf="terraform_${TERRAFORM_VERSION}_${os}_${arch}.zip"
curl -fsSLO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/${tf}"
curl -fsSLO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS"
sha_check "$tf" "terraform_${TERRAFORM_VERSION}_SHA256SUMS"
unzip -oq "$tf" terraform -d "$tools/bin"

echo "== provider mirror (aws $AWS_PROVIDER_VERSION, archive 2.8.1, tls 4.4.1, local 2.9.1, null 3.3.2, random 3.9.1)"
provider aws "$AWS_PROVIDER_VERSION" "$tools/mirror"
provider archive "2.8.1" "$tools/mirror"
provider tls "4.4.1" "$tools/mirror"
provider local "2.9.1" "$tools/mirror"
provider null "3.3.2" "$tools/mirror"
provider random "3.9.1" "$tools/mirror"

echo "== tfsec v$TFSEC_VERSION (baseline; tfsec is now part of Trivy)"
ts="tfsec_${TFSEC_VERSION}_${os}_${arch}.tar.gz"
curl -fsSLO "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/${ts}"
curl -fsSLO "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec_${TFSEC_VERSION}_checksums.txt"
sha_check "$ts" "tfsec_${TFSEC_VERSION}_checksums.txt"
tar xzf "$ts" -C "$tools/bin" tfsec

echo "== trivy $TRIVY_VERSION"
tos=$([ "$os" = linux ] && echo Linux || echo macOS)
tar_arch=$([ "$arch" = amd64 ] && echo 64bit || echo ARM64)
tv="trivy_${TRIVY_VERSION}_${tos}-${tar_arch}.tar.gz"
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tv}"
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
sha_check "$tv" "trivy_${TRIVY_VERSION}_checksums.txt"
tar xzf "$tv" -C "$tools/bin" trivy

echo "== gitleaks v$GITLEAKS_VERSION"
gl_arch=$([ "$arch" = amd64 ] && echo x64 || echo arm64)
gl="gitleaks_${GITLEAKS_VERSION}_${os}_${gl_arch}.tar.gz"
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gl}"
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
sha_check "$gl" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"
tar xzf "$gl" -C "$tools/bin" gitleaks

echo
"$tools/bin/terraform" version | head -1
"$tools/bin/tfsec" --version 2>/dev/null | tail -1
"$tools/bin/trivy" --version | head -1
"$tools/bin/gitleaks" version | head -1
echo "tools installed in $tools (source scripts/toolenv.sh or use the Makefile targets)"
