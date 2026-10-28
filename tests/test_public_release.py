"""Snapshot export must preserve exact bytes and reject unsafe/unreviewed material."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name.replace('_', '-') + '.py'))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def repo(tmp_path):
    p = tmp_path / 'source'; p.mkdir()
    subprocess.run(['git', 'init', '-q', str(p)], check=True)
    subprocess.run(['git', '-C', str(p), 'config', 'user.name', 'Snapshot test'], check=True)
    subprocess.run(['git', '-C', str(p), 'config', 'user.email', 'test@example.invalid'], check=True)
    for name in ['README.md', 'LICENSE', 'PUBLIC-RELEASE.md', 'src/tapm/__init__.py', 'fixtures/demo/gold.yaml']:
        f=p/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(name+'\n')
    return p


def commit(p):
    subprocess.run(['git','-C',str(p),'add','-A'],check=True)
    subprocess.run(['git','-C',str(p),'-c','commit.gpgsign=false','commit','-qm','Fixture snapshot'],check=True)


def test_export_reads_committed_bytes_and_no_private_history(tmp_path):
    p=repo(tmp_path);commit(p)
    (p/'README.md').write_text('uncommitted, not reviewed')
    (p/'.env').write_text('not-exported')
    out=tmp_path/'snapshot';m=module('export_public').export(p,'HEAD','.',out)
    assert (out/'README.md').read_text()=='README.md\n'
    assert not (out/'.git').exists() and not (out/'.env').exists()
    assert m['private_history_included'] is False
    assert module('verify_public').verify(out)==5


@pytest.mark.parametrize('kind',['extra','missing','changed','symlink','mode'])
def test_inventory_rejects_tamper(tmp_path,kind):
    p=repo(tmp_path);commit(p);out=tmp_path/'snapshot';module('export_public').export(p,'HEAD','.',out)
    if kind=='extra': (out/'extra.env').write_text('unexpected')
    if kind=='missing': (out/'LICENSE').unlink()
    if kind=='changed': (out/'README.md').write_text('different')
    if kind=='symlink':
        (out/'LICENSE').unlink();(out/'LICENSE').symlink_to(p/'LICENSE')
    if kind=='mode': (out/'README.md').chmod(0o755)
    with pytest.raises(ValueError): module('verify_public').verify(out)


@pytest.mark.parametrize('name',['.env','artifacts/runtime.txt','state.tfstate','private.pem','.venv-scanners/pkg.py','.terraform/provider.txt','labs/workspace/plan.json','node_modules/pkg.js'])
def test_export_rejects_tracked_runtime(tmp_path,name):
    p=repo(tmp_path);f=p/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('do not export');commit(p)
    with pytest.raises(ValueError): module('export_public').export(p,'HEAD','.',tmp_path/'snapshot')


def test_export_refuses_symlink_or_existing_destination(tmp_path):
    p=repo(tmp_path);(p/'link').symlink_to('README.md');commit(p)
    with pytest.raises(ValueError): module('export_public').export(p,'HEAD','.',tmp_path/'snapshot')
    with pytest.raises(ValueError): module('export_public').export(p,'HEAD','.',p)


def test_manifest_path_traversal_rejected(tmp_path):
    p=repo(tmp_path);commit(p);out=tmp_path/'snapshot';module('export_public').export(p,'HEAD','.',out)
    f=out/'release-manifest.json';m=json.loads(f.read_text());m['files']['../outside']={'sha256':'x','mode':'0o644'};f.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='Unsafe manifest path'): module('verify_public').verify(out)


def test_frozen_mode_detects_modified_label(tmp_path):
    p=repo(tmp_path);commit(p);out=tmp_path/'snapshot';module('export_public').export(p,'HEAD','.',out)
    assert module('verify_public').verify(out,frozen=True)==1
    (out/'fixtures/demo/gold.yaml').write_text('modified')
    with pytest.raises(ValueError,match='Hash mismatch'): module('verify_public').verify(out,frozen=True)


def test_upstream_license_receipts_match_and_errata_preserve_sources():
    receipt=json.loads((ROOT/'third-party/upstream-verification.json').read_text())
    assert len(receipt['licenses'])==10
    for item in receipt['licenses']:
        assert hashlib.sha256((ROOT/item['local_path']).read_bytes()).hexdigest()==item['sha256']
    assert len(receipt['reference_corrections'])==2
    for correction in receipt['reference_corrections']:
        assert correction['original_unresolvable_full_revision']!=correction['verified_revision']
        assert len(correction['files'])==4
        for item in correction['files']:
            assert hashlib.sha256((ROOT/item['vendored_path']).read_bytes()).hexdigest()==item['sha256']
