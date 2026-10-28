# Conference / lab image: everything pre-installed so `make demo` works offline.
#   docker build -t terraform-attack-paths-pytm .
#   docker run --rm -it terraform-attack-paths-pytm make demo
#
# Pin the base image by digest before the conference (docker buildx imagetools inspect python:3.12-slim-bookworm).
FROM python:3.12-slim-bookworm

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TAPM_TERRAFORM=/app/.tools/bin/terraform TAPM_PROVIDER_MIRROR=/app/.tools/mirror \
    TAPM_TFSEC=/app/.tools/bin/tfsec TAPM_TRIVY=/app/.tools/bin/trivy TAPM_CHECKOV=/app/.venv-scanners/bin/checkov

RUN apt-get update \
 && apt-get install -y --no-install-recommends graphviz make curl unzip ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv .venv && .venv/bin/pip install -e '.[dev]' \
 && python -m venv .venv-scanners && .venv-scanners/bin/pip install 'checkov==3.3.20'

COPY scripts ./scripts
RUN bash scripts/fetch-tools.sh

COPY . .
RUN useradd --create-home lab && chown -R lab:lab /app
USER lab

# Offline by default: the demo replays committed plans and baselines; AI uses recorded or simulated output.
CMD ["make", "demo"]
