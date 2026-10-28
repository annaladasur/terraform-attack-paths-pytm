"""Stage preflight must reject stale heads, missing models and substituted checks."""
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('stage_preflight', Path(__file__).parents[1] / 'demo/technical-preflight.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def fake_transport(*, stale=False, missing=False, wrong=False):
    calls = []
    reads = {}
    def get(url, payload=None):
        calls.append((url, payload))
        if url.endswith('/version'): return {'version': 'fixture'}
        if url.endswith('/health'): return {'status': 'ok'}
        if url.endswith('/tags'): return {'models': [] if missing else [{'name': 'fixture-model', 'digest': 'fixture-digest'}]}
        if url.endswith('/chat'): return {'done': True, 'message': {'content': 'READY'}, 'eval_count': 1}
        def pr(n): return {'number': n, 'head': {'ref': 'pr-42' if n == 3 else 'fix', 'sha': f'head{n}', 'repo': {'full_name': 'demo-org/infra-demo'}}, 'base': {'ref': 'main'}}
        if '/pulls?' in url: return [pr(3), pr(4)]
        if '/pulls/' in url:
            n = int(url.rsplit('/', 1)[1]);reads[n] = reads.get(n, 0) + 1
            result = pr(n)
            if stale and reads[n] > 1: result['head']['sha'] = 'new-head'
            return result
        if '/commits/' in url:
            state = 'failure' if 'head3' in url else 'success'
            return {'statuses': [{'id': 1, 'context': 'unrelated' if wrong else 'attack-paths', 'status': state}]}
        raise AssertionError(url)
    return get, calls


def run(transport, generate=False):
    return preflight.check_stage('http://localhost:3000', 'http://localhost:8080', 'http://localhost:11434', 'fixture-model', generate, transport)


def test_current_heads_and_real_generation_are_explicit():
    transport, calls = fake_transport()
    result = run(transport, True)
    assert result['passed'] and len(result['checks']) == 6
    assert sum(payload is not None for _, payload in calls) == 1
    assert not result['fresh_end_to_end_run'] and not result['native_powerpoint_verified']


@pytest.mark.parametrize('fault', ['stale', 'missing', 'wrong'])
def test_no_stale_or_substituted_success(fault):
    transport, _ = fake_transport(**{fault: True})
    assert not run(transport)['passed']


def test_unavailable_runtime_is_a_failed_check_not_a_fallback():
    transport, _ = fake_transport()
    def unavailable(url, payload=None):
        if url.endswith('/tags'): raise ConnectionRefusedError()
        return transport(url, payload)
    result = run(unavailable)
    check = next(x for x in result['checks'] if x['check'] == 'configured_model_installed')
    assert not result['passed'] and check['error'] == 'ConnectionRefusedError'


@pytest.mark.parametrize('url', ['https://example.com', 'http://example.com', 'http://secret@localhost:3000', 'http://localhost:3000?token=secret'])
def test_no_remote_or_credential_endpoints(url):
    with pytest.raises(ValueError): preflight.local_url(url)


def test_optimized_python_cannot_disable_readiness_checks():
    import subprocess
    import sys
    code = f"import runpy; m=runpy.run_path({str(Path('demo/technical-preflight.py').resolve())!r}); m['require'](False)"
    result = subprocess.run([sys.executable, '-O', '-c', code], capture_output=True, text=True)
    assert result.returncode != 0 and 'ValueError' in result.stderr
