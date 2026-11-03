#!/usr/bin/env python3
"""Offline, pinned-source V2 replay with complete pair accounting and no gold writes.

Requires the already cached public source checkouts identified in the previous
corpus artifact. It refuses fetch, plan and scanner execution. Outputs retain
earlier runs as execution history; they never replace historical benchmark gold.
"""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import copy, hashlib, json, os, subprocess

ROOT=Path(__file__).resolve().parents[1];S=ROOT/'evaluations/v2'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def source_hashes():return {str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'src/tapm').rglob('*.py'))}
def main():
    import tapm.eval.tier2 as tier2
    from tapm.eval.stats import wilson_interval as wilson
    prior=json.loads((S/'corpus-results.json').read_text())
    cache=Path(os.environ.get('TAPM_TIER2_REPOS',prior['execution']['cached_source_root']))
    os.environ['TAPM_TIER2_REPOS']=str(cache)
    for path,digest in prior['input_sha256'].items():assert sha(ROOT/path)==digest,path
    for path,digest in prior['integrity']['frozen_file_sha256'].items():assert sha(ROOT/path)==digest,path
    actual_sources={};source_inventories={}
    for url,record in prior['pinned_external_sources'].items():
        repo=tier2.repo_dir(url)
        commit=record.get('commit') or record.get('head')
        head=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        if commit:assert head==commit,(url,head,commit)
        for case,files in record['case_source_tf_sha256'].items():
            prior_case=next(c for run in prior['runs'] for c in run['cases'] if c['id']==case)
            prior_repo=Path(prior['execution']['cached_source_root']).joinpath(*(p.lower()for p in url.rstrip('/').split('/')[-2:]))
            relative=Path(prior_case['source_directory']).relative_to(prior_repo)
            source=repo/relative;assert source.exists(),('missing actual pinned source',case,source)
            actual_sources[case]=source.resolve()
            source_inventories[case]=files
            for path,digest in files.items():assert sha(source/path)==digest,(case,path)
    def verify_sources():
        for case,source in actual_sources.items():
            files={str(p.relative_to(source)):sha(p)for p in source.rglob('*.tf')if not any(x in {'.git','.terraform'}for x in p.relative_to(source).parts)}
            assert files==source_inventories[case],('actual source inventory or bytes changed',case)
    verify_sources()
    def prohibited(*args,**kwargs):raise RuntimeError('V2 offline replay forbids fetching, planning and scanning')
    tier2.ensure_repo=tier2.plan_fixture=tier2.run_scanners=prohibited
    original=tier2.run_deterministic;captured={}
    def capture(cfg):
        assert Path(cfg.tf_dir).resolve()==actual_sources[cfg.name],('unverified actual source directory',cfg.name,cfg.tf_dir)
        result=original(cfg)
        captured[cfg.name]={'path_analysis':result.path_analysis,'displayed_paths':[p.to_json() for p in result.paths],
            'source_directory':str(cfg.tf_dir),'notes':result.build.notes,
            'assumption_counts':dict(Counter(a for p in result.paths for a in p.preconditions)),
            'options':{'user_entries':cfg.user_entries,'heuristic_sensitivity':cfg.heuristic_sensitivity,'extra_targets':list(cfg.extra_targets)}}
        return result
    tier2.run_deterministic=capture
    started=datetime.now(timezone.utc).isoformat();before=source_hashes();runs=[]
    for manifest,tag in [('manifest.yaml','v2-current'),('manifest-heldout.yaml','v2-current-familiar-heldout')]:
        run=tier2.run_tier2(manifest_name=manifest,tag=tag,out_dir=ROOT/'artifacts/v2-corpus',write_results=False,
                          command='PYTHONPATH=src python scripts/evaluate-v2-corpus.py (offline cached plans/baselines/sources)')
        for case in run['cases']:
            assert 'error'not in case,case
            case.update(captured[case['id']])
        runs.append(run)
    assert before==source_hashes(),'Engine changed during replay'
    verify_sources()
    output=copy.deepcopy(prior);history=output.pop('execution_history',[])
    previous=copy.deepcopy(prior);previous.pop('execution_history',None)
    history.append({'original_artifact_sha256':sha(S/'corpus-results.json'),'result':previous})
    output.update(started_at_utc=started,finished_at_utc=datetime.now(timezone.utc).isoformat(),source_sha256=before,runs=runs,execution_history=history)
    cases=[c for run in runs for c in run['cases']];counts={k:sum(c['score'][k] for c in cases)for k in ['tp','fn','fp','tn','out_of_scope','out_of_scope_found']}
    accounting=[c['score']['prediction_accounting'] for c in cases];coverage={k:sum(a['coverage_score'][k]for a in accounting)for k in ['tp','fn','fp']}
    summary=output['summary'];summary.update(cases=len(cases),case_errors=0,displayed_routes=sum(c['paths']for c in cases),legacy_gold_row_counts=counts,
        unique_predicted_entry_target_pairs=sum(a['unique_predicted_pairs']for a in accounting),duplicate_displayed_routes=sum(a['duplicate_routes']for a in accounting),
        undisplayed_reachable_pairs=sum(a['undisplayed_reachable_pairs']for a in accounting),verification_unknown_pairs=sum(a['verification_unknown_pairs']for a in accounting),
        prediction_labels={label:sum(a['by_label'][label]for a in accounting)for label in ['VALID','INVALID','OUT_OF_SCOPE','UNKNOWN','UNLABELED']},
        completeness={'overall_complete':sum(c['path_analysis']['complete']for c in cases),'overall_incomplete':sum(not c['path_analysis']['complete']for c in cases),
                      'policy_complete':sum(c['path_analysis']['policy_complete']for c in cases),'policy_incomplete':sum(not c['path_analysis']['policy_complete']for c in cases),
                      'enumeration_complete':sum(c['path_analysis']['enumeration']['complete']for c in cases),'enumeration_incomplete':sum(not c['path_analysis']['enumeration']['complete']for c in cases),
                      'verification_complete':sum(c['path_analysis']['reachability']['complete']for c in cases)})
    for label,den in [('precision',counts['tp']+counts['fp']),('recall',counts['tp']+counts['fn'])]:
        summary['legacy_'+label+'_numerator']=counts['tp'];summary['legacy_'+label+'_denominator']=den
        summary['legacy_'+label]=counts['tp']/den if den else None
        summary['legacy_'+label+'_wilson_95']=list(wilson(counts['tp'],den))if den else None
    verified=summary['verified_pair_label_limited_coverage'];verified.update(coverage)
    for label,den in [('precision',coverage['tp']+coverage['fp']),('recall',coverage['tp']+coverage['fn'])]:
        verified[label+'_numerator']=coverage['tp'];verified[label+'_denominator']=den
        verified[label+'_wilson_95']=list(wilson(coverage['tp'],den))if den else None
    unlabeled=[{'case':c['id'],**p}for c in cases for p in c['score']['prediction_accounting']['inventory']if p['label']=='UNLABELED']
    output['unlabeled_predictions']=unlabeled
    current={(p['case'],p['entry'],p['target'])for p in unlabeled}
    reviewed={(p['case'],p['entry'],p['target'])for p in output['post_hoc_candidate_review']['decisions_for_current_unlabeled_pairs']}
    assert current==reviewed,'New candidate set requires independent review'
    assert all(sha(ROOT/path)==digest for path,digest in prior['integrity']['frozen_file_sha256'].items())
    output['execution']['method']='scripts/evaluate-v2-corpus.py: pinned source hashes, cached plan/baselines, all external work forbidden'
    output['execution']['cached_source_root']=str(cache)
    output['assumptions_and_limits']=[s.replace('all novel emitted pairs are inventoried separately and await independent adjudication.','all novel emitted pairs are inventoried separately; post-hoc dispositions remain outside frozen scores.')for s in output['assumptions_and_limits']]
    (S/'corpus-results.json').write_text(json.dumps(output,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
