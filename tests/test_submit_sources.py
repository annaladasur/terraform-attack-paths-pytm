"""Verify CI source traceability from explicit collection through the real service."""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from tapm.service.client import SubmitClient
from tapm.report.developer import render_developer_report
from tapm.service.server import create_server
from tapm.service.sources import collect_source_files
from tapm.util import PROJECT_ROOT


def test_collect_preserves_relative_names_and_line_bytes(tmp_path):
    text = '# source context\r\nresource "aws_s3_bucket" "sample" {\n}\n'
    (tmp_path / 'nested').mkdir()
    (tmp_path / 'nested/main.tf').write_bytes(text.encode('utf-8'))
    (tmp_path / 'secret.tfvars').write_text('value = "not-source"')
    (tmp_path / 'plan.json').write_text('{}')
    for name in ['.git', '.terraform']:
        (tmp_path / name).mkdir()
        (tmp_path / name / 'ignored.tf').write_text('must not be submitted')
    assert collect_source_files(tmp_path) == {'nested/main.tf': text}


def test_collection_does_not_follow_symlink_directory(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'private.tf').write_text('must not be read')
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'linked').symlink_to(outside, target_is_directory=True)
    assert collect_source_files(root) == {}


def test_collection_rejects_symlinked_terraform_file(tmp_path):
    (tmp_path / 'secret.txt').write_text('must not be read')
    (tmp_path / 'leak.tf').symlink_to(tmp_path / 'secret.txt')
    with pytest.raises(ValueError, match='regular file'):
        collect_source_files(tmp_path)


def test_explicit_invalid_root_does_not_submit_a_job(tmp_path):
    calls = []
    def transport(*args):
        calls.append(args)
        raise AssertionError('a source collection error must precede submission')
    client = SubmitClient(server_url='http://mock.test', transport=transport)
    result = client.run(plan={}, source_dir=tmp_path / 'missing', level='validate')
    assert result.status == 'error' and result.exit_code == 1
    assert result.job_id is None and 'Cannot collect Terraform source' in result.error
    assert calls == []


def test_real_service_has_source_locations_and_same_modeled_path(tmp_path):
    server = create_server(host='127.0.0.1', port=0, token='source-test-token',
                           data_dir=tmp_path / 'service', workers=1,
                           default_llm='simulated', default_jev='local')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = SubmitClient(server_url=f'http://127.0.0.1:{server.server_address[1]}',
                          token='source-test-token', poll_interval=0.05, timeout=60)
    fixture = PROJECT_ROOT / 'fixtures/006-public-workload-iam-sensitive-bucket'
    plan = json.loads((fixture / 'plan.json').read_text())
    try:
        with_sources = client.run(plan=plan, source_dir=fixture, repo='local/source-test', pr=1,
                                  sha='a' * 40, level='validate', auto_enrich=False,
                                  render_dfd=False, out_dir=tmp_path / 'located')
        # Accepting a reported route cannot clear unresolved plan-only IAM policy.
        import datetime as dt
        expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        exceptions = f"""exceptions:
  - id: ACCEPTED-PLAN-ONLY
    entry: internet
    target: aws_s3_bucket.customer_data
    owner: test-team
    reason: accepted route does not establish policy completeness
    expires: {expiry}
"""
        plan_only = client.run(plan=plan, repo='local/source-test', pr=2, sha='b' * 40,
                               exceptions_yaml=exceptions,
                               level='validate', auto_enrich=False,
                               render_dfd=False, out_dir=tmp_path / 'plan-only')
        assert with_sources.status == plan_only.status == 'completed'
        assert with_sources.exit_code == plan_only.exit_code == 3
        located_job = server.job_queue.get_job(with_sources.job_id)
        original_job = server.job_queue.get_job(plan_only.job_id)
        report = render_developer_report(located_job.artifacts_dir)
        for location in ['alb.tf:3', 'network.tf:72-78', 'network.tf:94-100',
                         'iam.tf:4-13', 'app.tf:10-13', 'iam.tf:25-35']:
            assert location in report
        assert 'location unavailable' not in report
        assert 'location unavailable' in render_developer_report(original_job.artifacts_dir)
        located_paths = json.loads((tmp_path / 'located/attack-paths.json').read_text())['paths']
        original_paths = json.loads((tmp_path / 'plan-only/attack-paths.json').read_text())['paths']
        assert len(located_paths) == len(original_paths) == 1
        assert located_paths[0]['key'] == original_paths[0]['key']
        assert located_paths[0]['preconditions'] == ['workload_ssrf']
        assert original_paths[0]['preconditions'] == ['workload_ssrf', 'condition_satisfied']
        assert located_paths[0]['status'] == 'plausible' and located_paths[0]['priority'] == 'high'
        assert original_paths[0]['status'] == 'review' and original_paths[0]['priority'] == 'medium'
        assert original_paths[0]['hops'][-1]['status'] == 'ASSUMPTION'
        located_analysis = json.loads((tmp_path / 'located/attack-paths.json').read_text())['analysis']
        original_analysis = json.loads((tmp_path / 'plan-only/attack-paths.json').read_text())['analysis']
        assert located_analysis['complete'] and located_analysis['policy_complete']
        assert not original_analysis['complete'] and not original_analysis['policy_complete']
        assert original_analysis['policy_uncertainties']
        plan_only_gate = json.loads((original_job.artifacts_dir / 'gate.json').read_text())
        assert plan_only_gate['decision'] == 'fail' and plan_only_gate['analysis_complete'] is False
        assert any(e['id'] == 'ACCEPTED-PLAN-ONLY' and e['state'] == 'valid' for e in plan_only_gate['exceptions'])
        assert any('unresolved IAM' in reason for reason in plan_only_gate['problems'])
        for job_id in [with_sources.job_id, plan_only.job_id]:
            job = server.job_queue.get_job(job_id)
            assert job.plan_deleted and not job.temp_dir.exists()
    finally:
        server.job_queue.shutdown()
        server.shutdown()
        server.server_close()


def test_cli_source_dir_is_explicit_and_forwarded(tmp_path, monkeypatch, capsys):
    from tapm.cli import main
    from tapm.service.client import SubmitResult

    received = {}
    def run(self, **kwargs):
        received.update(kwargs)
        return SubmitResult(job_id='cli-source', level='validate', status='completed',
                            verdict='pass', exit_code=0)
    monkeypatch.setattr(SubmitClient, 'run', run)
    plan = tmp_path / 'plan.json'
    plan.write_text('{}')
    with pytest.raises(SystemExit) as result:
        main(['submit', str(plan), '--source-dir', str(tmp_path), '--level', 'validate', '--json'])
    assert result.value.code == 0
    assert received['source_dir'] == str(tmp_path)
    assert json.loads(capsys.readouterr().out)['job_id'] == 'cli-source'


@pytest.mark.parametrize('workflow', [
    'examples/local-stack/.gitea/workflows/attack-paths.yml',
    'examples/local-stack/demo-repo/.gitea/workflows/attack-paths.yml',
    'examples/local-cluster/.gitea/workflows/attack-paths.yml',
])
def test_native_and_rest_workflow_collectors_match(workflow, tmp_path, monkeypatch):
    import subprocess
    import textwrap
    import yaml

    content = yaml.safe_load((PROJECT_ROOT / workflow).read_text())
    script = next(step['run'] for step in content['jobs']['attack-paths']['steps']
                  if step.get('name') == 'Submit plan to TAPM analysis service')
    assert '--source-dir .' in script and '--download-artifacts' not in script
    syntax = subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    start = script.index('from pathlib import Path')
    marker = 'payload = json.dumps({' if 'payload = json.dumps({' in script else 'with open("/tmp/tapm-run/plan.json"'
    end = script.index(marker, start)
    # Dedent using the actual indentation of the embedded Python collector.
    lines = script[start:end].splitlines()
    code = lines[0] + '\n' + textwrap.dedent('\n'.join(lines[1:]))
    (tmp_path / 'main.tf').write_bytes(b'# exact CRLF\r\nresource "aws_s3_bucket" "x" {}\r\n')
    (tmp_path / 'ignore.tfvars').write_text('private = "not source"')
    (tmp_path / '.terraform').mkdir()
    (tmp_path / '.terraform/ignored.tf').write_text('excluded dependency cache')
    monkeypatch.chdir(tmp_path)
    namespace = {'os': __import__('os')}
    exec(compile(code, workflow, 'exec'), namespace)
    assert namespace['source_files'] == collect_source_files(tmp_path)


def test_unreadable_source_directory_is_not_silently_omitted(tmp_path, monkeypatch):
    def denied(*args, onerror=None, **kwargs):
        assert onerror is not None
        onerror(PermissionError('unreadable source directory'))
        return iter(())
    monkeypatch.setattr('tapm.service.sources.os.walk', denied)
    with pytest.raises(PermissionError, match='unreadable source'):
        collect_source_files(tmp_path)
