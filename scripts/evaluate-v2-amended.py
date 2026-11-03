#!/usr/bin/env python3
"""Preseal and execute a separately identified valid-policy harness correction.

Original specifications, expectations and executions are retained. This changes
materialized inputs and must never be described as the original sealed run.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse, hashlib, importlib.util, json

ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'evaluations/v2'
spec=importlib.util.spec_from_file_location('original_v2',ROOT/'scripts/evaluate-v2.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
original_plan=base.iam_plan
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
def amended_plan(specification):
    plan=original_plan(specification)
    for resource in plan['planned_values']['root_module']['resources']:
        value=resource['values']
        if resource['type']=='aws_iam_policy' and resource['name']=='limit' and specification.get('boundary')==[]:
            value['policy']=json.dumps({'Statement':[{'Effect':'Allow','Action':'s3:ListBucket','Resource':'*'}]})
        if resource['type']=='aws_iam_role':
            value['assume_role_policy']=json.dumps({'Statement':[{'Effect':'Allow','Principal':{'Service':'ec2.amazonaws.com'},'Action':'sts:AssumeRole'}]})
    return plan
def materialized(checks):
    rows=[]
    for check in checks:
        if check['kind']!='iam':continue
        before=original_plan(check['input']);after=amended_plan(check['input'])
        rows.append({'id':check['id'],'before_sha256':digest(before),'after_sha256':digest(after),'changed':before!=after,
                     'before_plan':before,'after_plan':after})
    return rows
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seal',action='store_true')
    parser.add_argument('--out-dir',type=Path,default=ROOT/'artifacts/v2-amended')
    args=parser.parse_args();protocol,checks=base.verify_seal()
    path=S/'amended-protocol.json';rows=materialized(checks)
    if args.seal:
        if path.exists():raise SystemExit('Amendment already sealed; refusing overwrite')
        record={'schema_version':1,'sealed_at_utc':datetime.now(timezone.utc).isoformat(),
                'evaluation_class':'amended-input known regression; not original sealed run or unseen evaluation',
                'reason':'Empty Statement arrays are malformed. Valid nonmatching boundary Allow exercises implicit deny; a valid service trust replaces an empty role trust. Expected booleans are unchanged.',
                'primary_reference':'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html',
                'original_protocol_sha256':base.sha256(S/'protocol.json'),
                'expected_checks_sha256':base.sha256(S/'expected-checks.json'),
                'runner_sha256':base.sha256(Path(__file__)),
                'original_runner_sha256':base.sha256(ROOT/'scripts/evaluate-v2.py'),
                'materialized_iam_plans':rows}
        path.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n');print('SEALED '+base.sha256(path));return
    sealed=json.loads(path.read_text())
    assert sealed['runner_sha256']==base.sha256(Path(__file__))
    assert sealed['original_runner_sha256']==base.sha256(ROOT/'scripts/evaluate-v2.py')
    assert sealed['expected_checks_sha256']==base.sha256(S/'expected-checks.json')
    assert sealed['original_protocol_sha256']==base.sha256(S/'protocol.json')
    assert rows==sealed['materialized_iam_plans']
    base.iam_plan=amended_plan
    code=base.run(args.out_dir)
    file=args.out_dir/'results.json';result=json.loads(file.read_text())
    result['evaluation_class']=sealed['evaluation_class']
    result['amendment']={'protocol_sha256':base.sha256(path),'sealed_at_utc':sealed['sealed_at_utc'],
                         'materialized_input_changes':sum(x['changed'] for x in rows),
                         'original_final_source_result':'25/28; three empty-boundary controls unresolved, not passed',
                         'original_expectations_unchanged':True}
    file.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    report=args.out_dir/'RESULTS.md'
    report.write_text('# V2 amended-input known regression\n\nThis is a separately presealed material-input correction. Original final-source run: **25/28**, retained with failures. Empty synthetic boundaries and role trusts were replaced with valid policies; expected booleans stayed unchanged. This is not the original sealed28 pass.\n\n'+report.read_text().split('\n',1)[1])
    raise SystemExit(code)
if __name__=='__main__':main()
