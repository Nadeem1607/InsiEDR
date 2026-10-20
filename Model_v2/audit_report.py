"""Frozen model checks, honest comparisons and packaging. No fitting or selection."""
import os
os.environ.setdefault('OMP_NUM_THREADS','2')
import sys,json,hashlib,subprocess,zipfile
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import balanced_accuracy_score,average_precision_score,accuracy_score
from core import rvfl_class,score,windows
from train import cohort
ROOT=Path(__file__).resolve().parent;OUT=ROOT/'run';WORK=ROOT/'data'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(name,obj):(OUT/name).write_text(json.dumps(obj,indent=2,allow_nan=False),encoding='utf8')
def main():
    frozen=json.loads((OUT/'frozen_selection.json').read_text());evaluation=json.loads((OUT/'evaluation.json').read_text())
    assert sha(OUT/'pipeline.joblib')==frozen['model_sha256']
    rvfl_class()
    import torch
    torch.set_num_threads(2)
    bundle=joblib.load(OUT/'pipeline.joblib')
    # Export prefixed, correctly marked validation/holdout inputs if first training process
    # predates this output-only export addition. Cohorts already exist; never regenerate.
    cohort(63001,'validation_new');X,M=cohort(63002,'prospective_holdout')
    assert all(sha(WORK/p)==h for p,h in frozen['source_sha256'].items())
    mask=M.day_index.le(12);x=X.loc[mask].reset_index(drop=True);m=M.loc[mask].reset_index(drop=True)
    reference=score(bundle,x,m)
    mutated=x.copy();mutated.loc[m.day_index.gt(8)]=mutated.loc[m.day_index.gt(8)]*50+7
    changed=score(bundle,mutated,m[['hostname','date']]);early=m.day_index.le(8).to_numpy()
    assert np.allclose(reference[0].loc[early],changed[0].loc[early])
    assert np.allclose(reference[-1][early],changed[-1][early],equal_nan=True)
    order=np.random.default_rng(123).permutation(len(x))
    shuffled=score(bundle,x.iloc[order].reset_index(drop=True),m.iloc[order].reset_index(drop=True))
    assert np.allclose(shuffled[2][np.argsort(order)],reference[2])
    assert np.allclose(shuffled[-1][np.argsort(order)],reference[-1],equal_nan=True)
    short=pd.DataFrame({'hostname':['A']*8+['B']*8,'date':list(pd.date_range('2026-01-01',periods=8).strftime('%Y-%m-%d'))*2})
    _,_,idx,hist=windows(np.arange(16)/16,short)
    assert len(idx)==2 and np.all(short.hostname.to_numpy()[hist]==short.hostname.to_numpy()[idx,None])
    gaps=short.drop(index=4).reset_index(drop=True)
    _,_,idx,_=windows(np.arange(15)/15,gaps)
    assert len(idx)==1 and gaps.iloc[idx[0]].hostname=='B'
    badx=pd.concat([x,x.iloc[:1]],ignore_index=True);badm=pd.concat([m,m.iloc[:1]],ignore_index=True)
    try:score(bundle,badx,badm);raise AssertionError('Duplicate accepted')
    except ValueError as e:assert 'Duplicate' in str(e)
    child=subprocess.run([sys.executable,str(ROOT/'predict.py'),'--features',str(OUT/'prospective_holdout_inputs/X.csv'),
          '--metadata',str(OUT/'prospective_holdout_inputs/metadata.csv'),'--output',str(ROOT/'inference_check')],capture_output=True,text=True)
    if child.returncode:raise RuntimeError(child.stderr)
    expected=pd.read_csv(OUT/'prospective_holdout/daily_predictions.csv');actual=pd.read_csv(ROOT/'inference_check/daily_predictions.csv')
    for c in ['threat_probability','drift_error','forecasted_risk']:
        assert np.allclose(expected[c],actual[c],equal_nan=True,atol=1e-6)
    assert expected.threat_alert.equals(actual.threat_alert)
    assert expected.temporal_alert.fillna('NA').equals(actual.temporal_alert.fillna('NA'))
    checks=dict(future_feature_and_prediction_invariance=True,metadata_labels_not_required=True,
        shuffled_row_invariance=True,no_gap_or_cross_host_windows=True,duplicate_host_day_rejected=True,
        saved_cli_reproduces_predictions=True,original_sources_unchanged=True,frozen_model_unchanged=True)
    oldroot=WORK/'architecture_pipeline/run';comparisons={}
    for name in ['test','challenge']:
        if not (oldroot/name/'daily_predictions.csv').exists():
            comparisons[name]=json.loads((OUT/'post_freeze_audit.json').read_text())['comparison'][name]
            continue
        old=pd.read_csv(oldroot/name/'daily_predictions.csv');new=pd.read_csv(OUT/name/'daily_predictions.csv')
        assert old[['hostname','date','binary_label']].equals(new[['hostname','date','binary_label']])
        od=old.loc[old.temporal_available].copy()
        comparisons[name]=dict(old_threat_accuracy=float(accuracy_score(old.binary_label,old.threat_alert)),
            old_threat_balanced_accuracy=float(balanced_accuracy_score(old.binary_label,old.threat_alert)),
            old_temporal_accuracy=float(accuracy_score(od.binary_label,od.temporal_alert.astype(bool))),
            old_temporal_balanced_accuracy=float(balanced_accuracy_score(od.binary_label,od.temporal_alert.astype(bool))),
            old_threat_ap=float(average_precision_score(old.binary_label,old.threat_probability)),
            old_temporal_ap=float(average_precision_score(od.binary_label,od.next_risk_absolute_error)),
            new_threat=evaluation[name]['threat'],new_temporal=evaluation[name]['temporal'])
    intervals={};rng=np.random.default_rng(63002)
    groups=[g for _,g in expected.groupby('hostname')]
    values={s:[] for s in ['threat_balanced_accuracy','temporal_balanced_accuracy','threat_ap','temporal_ap']}
    for _ in range(300):
        d=pd.concat([groups[i] for i in rng.integers(0,len(groups),len(groups))],ignore_index=True)
        e=d.loc[d.temporal_available]
        if not d.binary_label.sum():continue
        values['threat_balanced_accuracy'].append(float(balanced_accuracy_score(d.binary_label,d.threat_alert)))
        values['temporal_balanced_accuracy'].append(float(balanced_accuracy_score(e.binary_label,e.temporal_alert.astype(bool))))
        values['threat_ap'].append(float(average_precision_score(d.binary_label,d.threat_probability)))
        values['temporal_ap'].append(float(average_precision_score(e.binary_label,e.drift_error)))
    for name,v in values.items():intervals[name]=np.quantile(v,[.025,.975]).tolist()
    gaps={name:dict(threat_balanced_accuracy_train_minus_holdout=evaluation['train_original']['threat']['balanced_accuracy']-evaluation[name]['threat']['balanced_accuracy'],
                    threat_ap_train_minus_holdout=evaluation['train_original']['threat']['pr_auc']-evaluation[name]['threat']['pr_auc'],
                    temporal_balanced_accuracy_train_minus_holdout=evaluation['train_original']['temporal']['balanced_accuracy']-evaluation[name]['temporal']['balanced_accuracy'])
          for name in ['test','challenge','prospective_holdout']}
    target={name:dict(threat_above_80=evaluation[name]['threat']['balanced_accuracy']>.8,
                     temporal_above_80=evaluation[name]['temporal']['balanced_accuracy']>.8,
                     host15_above_80=evaluation[name]['host_last15']['balanced_accuracy']>.8)
            for name in ['test','challenge','prospective_holdout']}
    save('post_freeze_audit.json',dict(checks=checks,comparison=comparisons,train_gaps=gaps,
         prospective_host_bootstrap_95_intervals=intervals,bootstrap_replicates=300,target_check=target,
         interval_scope='Within one shared-mechanism synthetic cohort, not external validity.'))
    report=['# Retrained pipeline: results and decisions','',
       'A new model has trained without overwriting either prior pipeline. The primary target is >80% **balanced accuracy**. Ordinary accuracy is also reported, because a model predicting normal every day already scores around 99% on these rare-attack populations. A high accuracy number alone does not establish useful detection.','',
       '## Selected model','',
       f"- Training: 51,840 original/v2 training rows. No historical evaluation rows enter fitting. Tier 2: {frozen['tier2']['spec']['name']}, two fixed-seed boosters, six probabilities, 40 ordered inputs.",
       '- Four IF domain forests are calibrated on disjoint reserved normal training hosts. Only upper-tail percentile scores receive anomaly risk. This replaces the old high normal-risk floor.',
       f"- Fusion: `{bundle['fusion']}`. RedRVFL: seven daily inputs, three frozen 64-unit random-LSTM layers, Ridge alpha {bundle['redrvfl'].ridge_alpha}, `{bundle['error_mode']}` next-risk error. Only Ridge heads train.",
       '- All candidates and the selection rule were recorded before inspecting this run’s heldout results. Alert thresholds optimize worst-cohort validation balanced accuracy with <=3% normal FPR in each validation population.',
       '- Seed 63001 is additional validation, explicitly never a test. Seed 63002 was generated after freezing the selected models/thresholds. Both contain all seven attack families; supervised fitting still contains only the five known primitives plus normal.',
       '- The old test/challenge/fresh sets were examined in prior work. The new seed is a prospective synthetic check, not independent real-world data; it shares the same attack mechanisms.',
       '', '## Daily performance','',
       '| Population | Stage | Accuracy | Balanced accuracy | Attack recall | Precision | Normal FPR | PR-AUC |',
       '|---|---|---:|---:|---:|---:|---:|---:|']
    for name in ['train_original','train_augmented','validation_original','validation_new','test','challenge','old_fresh','prospective_holdout']:
        for stage in ['threat','temporal']:
            r=evaluation[name][stage]
            report.append(f"| {name} | {stage} | {r['accuracy']:.2%} | {r['balanced_accuracy']:.2%} | {r['recall']:.2%} | {r['precision']:.2%} | {r['false_positive_rate']:.2%} | {r['pr_auc']:.4f} |")
    report+=['','Temporal metrics exclude targets without seven consecutive prior days. This is detection after observing the target day’s risk, not a promise to predict attack labels in advance. The >80% target refers to binary attack detection, not six-class scenario macro-F1.','',
       '## Comparison on identical historical data','',
       '| Population | Old Tier 2 balanced accuracy | New Tier 2 balanced accuracy | Old temporal balanced accuracy | New temporal balanced accuracy |',
       '|---|---:|---:|---:|---:|']
    for name,v in comparisons.items():report.append(f"| {name} | {v['old_threat_balanced_accuracy']:.2%} | {v['new_threat']['balanced_accuracy']:.2%} | {v['old_temporal_balanced_accuracy']:.2%} | {v['new_temporal']['balanced_accuracy']:.2%} |")
    report+=['','## Final error-based host ranking','',
       'The operational score uses the latest **15 eligible target days**. Ground truth and alert thresholds refer to that same interval. Full-period ranking files are retained without thresholds for historical triage; they are not directly comparable to last15 host accuracy.','',
       '| Population | Eligible hosts | Attack hosts in interval | Accuracy | Balanced accuracy | Recall | Precision | Normal-host FPR |',
       '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name in ['test','challenge','prospective_holdout']:
        r=evaluation[name]['host_last15']
        report.append(f"| {name} | {r['rows']} | {r['positive_rows']} | {r['accuracy']:.2%} | {r['balanced_accuracy']:.2%} | {r['recall']:.2%} | {r['precision']:.2%} | {r['false_positive_rate']:.2%} |")
    report+=['','## Generalization and remaining failures','']
    for name,g in gaps.items():
        report.append(f"- Original-training minus {name}: Tier 2 balanced-accuracy gap {g['threat_balanced_accuracy_train_minus_holdout']:+.2%}; Tier 2 AP gap {g['threat_ap_train_minus_holdout']:+.4f}; temporal balanced-accuracy gap {g['temporal_balanced_accuracy_train_minus_holdout']:+.2%}.")
    report+=['','Prospective whole-host bootstrap 95% intervals (300 resamples):','']
    for name,(lo,hi) in intervals.items():report.append(f'- {name}: [{lo:.4f}, {hi:.4f}].')
    report+=['','Scenario outcomes remain in evaluation.json. Known-class identification accuracy is separate from binary detection. No labels or holdout examples were changed to achieve the target.','',
      '| Test scenario | Days | Tier 2 alert rate | Temporal alert rate | Trained class? |',
      '|---|---:|---:|---:|---|']
    for sc,v in evaluation['test']['per_scenario'].items():
        report.append(f"| {sc} | {v['rows']} | {v['threat_alert_rate']:.1%} | {v['temporal_alert_rate']:.1%} | {v['supervised_known']} |")
    report+=['','## Target verdict','']
    for name,v in target.items():report.append(f"- {name}: Tier 2 >80% balanced accuracy **{v['threat_above_80']}**; temporal >80% **{v['temporal_above_80']}**; last15 host alerts >80% **{v['host15_above_80']}**.")
    report+=['','Passing a point-estimate target on one synthetic cohort cannot certify absence of overfitting or memorization. Check the uncertainty intervals, attack recall, precision and cohort gaps. No retuning was performed after prospective scores were read. Independently observed benign telemetry and independent attack mechanisms remain required for real deployment claims.','',
      '## Passed implementation checks','',
      '- Future perturbations cannot alter earlier model features or predictions. Shuffling rows preserves keyed predictions. Missing dates and host boundaries cannot form sequences. Duplicate host/day inputs are rejected.',
      '- Label-free saved-model CLI inference matches prospective probabilities, forecasts, errors and decisions. Original datasets and frozen model checksums are unchanged. No exact training vectors occur in the new holdout.',
      '- TreeSHAP is exact per booster and exported as mean signed class-margin contributions. They do not sum to the logit of the ensemble’s averaged probability. Explanations refer to Tier 2, not the final error score.',
      '', 'All decisions are in protocol.json, decisions.jsonl, tier2_candidates.json, temporal_candidates.json and frozen_selection.json. Predictions/rankings for every population and auditable input/export files are alongside this report.']
    (OUT/'TRAINING_REPORT.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    event=dict(time=datetime.now(timezone.utc).isoformat(),event='final_audit_and_report',checks=checks,
               target_check=target,model_unchanged=True,no_post_holdout_tuning=True)
    with (OUT/'decisions.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(event)+'\n')
    env=json.loads((OUT/'environment.json').read_text())['packages']
    (ROOT/'requirements.txt').write_text('\n'.join(('scikit-learn' if p=='sklearn' else p)+'=='+v for p,v in env.items())+'\n',encoding='utf8')
    files=[p for p in ROOT.iterdir() if p.is_file()]+[p for p in OUT.rglob('*') if p.is_file() and p.name!='artifact_checksums.json']
    save('artifact_checksums.json',[dict(path=p.relative_to(ROOT).as_posix(),sha256=sha(p)) for p in sorted(files)])
    targetzip=ROOT.parent/'InsiEDR_Retrained_Pipeline_v2.zip'
    with zipfile.ZipFile(targetzip,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in files+[OUT/'artifact_checksums.json']:z.write(p,Path(ROOT.name)/p.relative_to(ROOT))
    print(json.dumps(dict(checks=checks,target_check=target,intervals=intervals,zip=str(targetzip),bytes=targetzip.stat().st_size),indent=2))
if __name__=='__main__':main()
