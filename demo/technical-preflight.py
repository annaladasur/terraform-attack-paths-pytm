#!/usr/bin/env python3
"""Read-only local stage checks; never starts services, edits PRs or substitutes AI."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request


def local_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname not in {'localhost', '127.0.0.1', '::1'}
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Preflight endpoints must be credential-free local HTTP URLs')
    return value.rstrip('/')


def fetch(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=120 if payload else 5) as response:
        return json.load(response)


def require(condition, message='Invalid preflight evidence'):
    if not condition:
        raise ValueError(message)


def configured_model():
    text = Path(__file__).with_name('demo-live.sh').read_text()
    return os.environ.get('TAPM_MODEL') or re.search(r'^MODEL_NAME="([^"]+)"$', text, re.M)[1]


def check_stage(gitea, service, runtime, model, generate=False, transport=fetch):
    gitea, service, runtime = map(local_url, (gitea, service, runtime))
    checks = []
    def check(name, action):
        try:
            evidence = action()
            checks.append({'check': name, 'passed': True, 'evidence': evidence})
        except Exception as error:
            # Do not include raw response bodies, credentials or model prompts.
            checks.append({'check': name, 'passed': False, 'error': type(error).__name__})
    def version():
        result = transport(gitea + '/api/v1/version')
        require(result.get('version'), 'missing version')
        return {'version': result['version']}
    def health():
        result = transport(service + '/health')
        require(result.get('status') == 'ok', 'service is not healthy')
        return {'status': 'ok'}
    def installed():
        matches = [x for x in transport(runtime + '/api/tags')['models'] if x['name'] == model]
        require(len(matches) == 1 and matches[0].get('digest'), 'configured model unavailable')
        return {'digest': matches[0]['digest'], 'installed': True}
    def pr_status(branch, expected):
        base = gitea + '/api/v1/repos/demo-org/infra-demo'
        page = 1
        candidates = []
        while True:
            batch = transport(base + f'/pulls?state=open&limit=50&page={page}')
            require(isinstance(batch, list))
            candidates.extend(x for x in batch if x['head']['ref'] == branch
                              and x['base']['ref'] == 'main'
                              and x['head'].get('repo', {}).get('full_name') == 'demo-org/infra-demo')
            if len(batch) < 50:
                break
            page += 1
        require(candidates, 'no canonical open PR')
        number = max(candidates, key=lambda x: x['number'])['number']
        pr = transport(base + f'/pulls/{number}')
        require(pr['head']['ref'] == branch and pr['base']['ref'] == 'main')
        require(pr['head'].get('repo', {}).get('full_name') == 'demo-org/infra-demo')
        sha = pr['head']['sha']
        statuses = transport(base + f'/commits/{urllib.parse.quote(sha, safe="")}/status')['statuses']
        relevant = [x for x in statuses if x.get('context') == 'attack-paths']
        latest = max(relevant, key=lambda x: (x.get('updated_at', ''), x.get('id', 0)))
        require(latest['status'] == expected, 'required check has wrong or pending status')
        # Re-read after status lookup: a moved head must never pass on an old check.
        require(transport(base + f'/pulls/{number}')['head']['sha'] == sha, 'PR head moved')
        return {'pr': number, 'head': sha, 'required_check': expected}
    check('gitea', version)
    check('analysis_service', health)
    check('configured_model_installed', installed)
    check('vulnerable_pr_blocked', lambda: pr_status('pr-42', 'failure'))
    check('fixed_pr_passed', lambda: pr_status('fix', 'success'))
    if generate:
        def generation():
            response = transport(runtime + '/api/chat', {
                'model': model, 'messages': [{'role': 'user', 'content': 'Reply with READY.'}],
                'stream': False, 'options': {'temperature': 0, 'num_ctx': 2048, 'num_predict': 16}})
            require(response.get('done') is True and response.get('message', {}).get('content', '').strip())
            return {'completed': True, 'output_tokens': response.get('eval_count')}
        check('local_generation', generation)
    return {'passed': all(x['passed'] for x in checks), 'checks': checks,
            'fresh_end_to_end_run': False, 'native_powerpoint_verified': False,
            'scope': 'Read-only service/model/current-head checks; not a rehearsal or a fresh pipeline run'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitea-url', default='http://localhost:3000')
    parser.add_argument('--service-url', default='http://localhost:8080')
    parser.add_argument('--runtime-url', default='http://localhost:11434')
    parser.add_argument('--model', default=None)
    parser.add_argument('--generate', action='store_true', help='Also request a short real local generation')
    args = parser.parse_args()
    result = check_stage(args.gitea_url, args.service_url, args.runtime_url,
                         args.model or configured_model(), args.generate)
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
