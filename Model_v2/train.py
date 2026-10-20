"""Retrain on frozen training data; select with validation; freeze before new holdout.

All historical evaluations are retrospective. New seed is generated only after freeze.
"""
import os
os.environ.setdefault('OMP_NUM_THREADS','2')
from pathlib import Path
import sys,json,hashlib,time,platform
sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime,timezone
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (accuracy_score,balanced_accuracy_score,average_precision_score,
 precision_score,recall_score,f1_score,roc_auc_score,confusion_matrix)
from core import DomainStage,CLASSES,fit_booster,windows,rvfl_class,fuse,drift,score,host_rank

ROOT=Path(__file__).resolve().parent;WORK=ROOT/'data';OUT=ROOT/'run';OUT.mkdir(exist_ok=True)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(name,obj):(OUT/name).write_text(json.dumps(obj,indent=2,default=str,allow_nan=False),encoding='utf8')
def log(event,**data):
    row=dict(time=datetime.now(timezone.utc).isoformat(),event=event,**data)
    with (OUT/'decisions.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(row,default=str)+'\n')
    print(event,json.dumps(data,default=str)[:650],flush=True)
def pair(path,x='X.csv',m='metadata.csv'):
    return pd.read_csv(path/x),pd.read_csv(path/m)
def cohort(seed,purpose):
    folder=ROOT/'cohorts'/f'{purpose}_{seed}'
    if not folder.exists():
        from cohort_generator import build
        build(folder,seed,False)
    x,m=pair(folder/'development_90_days/daily_features')
    prefix=f'{purpose.upper()}{seed}-'
    m.hostname=prefix+m.hostname;m.agent_id='AGENT-'+m.hostname
    m.campaign_id=m.campaign_id.fillna('').map(lambda s:prefix+s if s else '')
    m['cohort']=purpose;m['split']=purpose
    export=OUT/(purpose+'_inputs');export.mkdir(exist_ok=True)
    x.to_csv(export/'X.csv',index=False,float_format='%.10g')
    m.to_csv(export/'metadata.csv',index=False)
    return x,m
def measures(y,s,t):
    y=np.asarray(y,int);s=np.asarray(s,float);valid=np.isfinite(s);y=y[valid];s=s[valid]
    if not len(y):return dict(rows=0)
    p=s>=t
    return dict(rows=len(y),positive_rows=int(y.sum()),accuracy=float(accuracy_score(y,p)),
        balanced_accuracy=float(balanced_accuracy_score(y,p)),
        pr_auc=float(average_precision_score(y,s)) if y.sum() else None,
        roc_auc=float(roc_auc_score(y,s)) if len(np.unique(y))==2 else None,
        precision=float(precision_score(y,p,zero_division=0)),recall=float(recall_score(y,p,zero_division=0)),
        f1=float(f1_score(y,p,zero_division=0)),false_positive_rate=float(p[y==0].mean()),
        confusion_matrix=confusion_matrix(y,p,labels=[0,1]).tolist())
def threshold(groups):
    """Maximin validation balanced accuracy with <=3% FPR in EACH validation cohort."""
    clean=[]
    for y,s in groups:
        y=np.asarray(y,int);s=np.asarray(s,float);ok=np.isfinite(s);clean.append((y[ok],s[ok]))
    vals=np.concatenate([s for _,s in clean])
    positives=np.concatenate([s[y==1] for y,s in clean])
    candidates=np.unique(np.r_[np.quantile(vals,np.linspace(0,1,301)),positives,np.nextafter(vals.max(),np.inf)])
    best=None
    for t in candidates:
        b=[];fps=[];precision=[]
        for y,s in clean:
            pred=s>=t;tp=(pred&(y==1)).sum();fp=(pred&(y==0)).sum()
            fpr=float(fp/(y==0).sum());recall=float(tp/(y==1).sum())
            b.append(.5*(recall+1-fpr));fps.append(fpr);precision.append(tp/max(tp+fp,1))
        if max(fps)>.03:continue
        key=(min(b),float(np.mean(b)),float(np.mean(precision)),float(t))
        if best is None or key>best[0]:best=(key,float(t))
    assert best is not None
    return best[1],dict(min_balanced_accuracy=best[0][0],mean_balanced_accuracy=best[0][1],
          populations=[measures(y,s,best[1]) for y,s in clean])

def run():
    start=time.time()
    if (OUT/'frozen_selection.json').exists():raise RuntimeError('Preserve this frozen run; refuse overwrite.')
    log('protocol',target='>80% BALANCED accuracy, not majority-class accuracy; precision/recall/AP/FPR retained.',
        training='Original 60-day training and existing v2 supplement only; no old heldout labels used to fit models.',
        validation='Original validation plus newly generated validation seed 63001 (all seven attack families).',
        prospective_test='Seed 63002 all-seven-family cohort generated only AFTER model and thresholds are frozen.',
        input_contract='Four IF domains, 32 behavior + 8 risk/context =40 inputs, six probabilities, seven daily risks -> RedRVFL.',
        restrictions='No test-based tuning, label alterations, duplicates, or preferentially easier holdouts.',
        probability_warning='Class-weighted scores sum to 1 but are not asserted to be empirical calibrated probabilities.',
        limitation='All synthetic cohorts share mechanisms. Historical test/challenge are consumed retrospective benchmarks.')
    protocol=dict(validation_seed=63001,prospective_seed=63002,
       representations=['level','hybrid','context'],
       specs=[dict(name='level_d2_cap5',rep='level',depth=2,trees=240,child=40,weight_cap=5),
              dict(name='level_d3_cap5',rep='level',depth=3,trees=240,child=40,weight_cap=5),
              dict(name='hybrid_d2_cap5',rep='hybrid',depth=2,trees=240,child=40,weight_cap=5),
              dict(name='hybrid_d3_cap5',rep='hybrid',depth=3,trees=240,child=40,weight_cap=5),
              dict(name='level_d2_cap20',rep='level',depth=2,trees=240,child=40,weight_cap=20),
              dict(name='context_d2_cap5',rep='context',depth=2,trees=240,child=40,weight_cap=5)],
       selection='0.45 new-val AP + 0.30 original-val AP + 0.25 grouped-forward AP - 0.1 positive train-minus-group AP gap',
       seeds=[20261021,20261022],fusion=['weighted15','weighted35','novelty','reference'],
       ridge_alpha=[10.,1000.,100000.],error_modes=['absolute','upward'],
       temporal_selection='max(min validation balanced accuracy + .05 min validation AP), subject to <=3% FPR per validation cohort',
       threshold='Maximize minimum balanced accuracy across the two validation cohorts, <=3% FPR each.',
       host_ranking='max error * mean error * sqrt(count), with exactly 15 eligible days for operational alerts.')
    dump('protocol.json',protocol)
    release=WORK/'InsiEDR_Synthetic_Release_v1'
    xd,md=pair(release/'development_90_days/daily_features');md['cohort']='original'
    xa,ma=pair(WORK/'anti_overfit_v2/augmentation','training_X.csv','training_metadata.csv')
    ma['cohort']=ma.cohort_seed.map(lambda s:f'augmentation_{s}')
    xv,mv=cohort(63001,'validation_new')
    X=pd.concat([xd,xa,xv],ignore_index=True);M=pd.concat([md,ma,mv],ignore_index=True)
    train=M.split.eq('train').to_numpy();v0=M.split.eq('validation').to_numpy();v1=M.split.eq('validation_new').to_numpy()
    assert train.sum()==51840 and not M.duplicated(['hostname','date']).any()
    assert M.loc[train,'scenario_label'].isin(CLASSES).all()
    assert set(M.loc[v1,'scenario_label'])-set(CLASSES)=={'HONEYTOKEN_TRIP','KILL_CHAIN_APT'}
    train_hash=pd.util.hash_pandas_object(X.loc[train],index=False)
    assert not train_hash.duplicated().any()
    assert not set(train_hash)&set(pd.util.hash_pandas_object(X.loc[v0|v1],index=False))
    sourcepaths=[release/'development_90_days/daily_features'/n for n in ['X.csv','metadata.csv']]
    sourcepaths += [WORK/'anti_overfit_v2/augmentation'/n for n in ['training_X.csv','training_metadata.csv']]
    sourcehash={p.relative_to(WORK).as_posix():sha(p) for p in sourcepaths}
    dump('training_validation_counts.json',{s:dict(rows=int(mask.sum()),classes=M.loc[mask,'scenario_label'].value_counts().to_dict()) for s,mask in [('training',train),('original_validation',v0),('new_validation',v1)]})
    # Group + time holdout entirely within training: one augmentation cohort, late dates.
    cvfit=train&~M.cohort.eq('augmentation_41003').to_numpy()&M.day_index.le(40).to_numpy()
    cvcheck=train&M.cohort.eq('augmentation_41003').to_numpy()&M.day_index.gt(40).to_numpy()
    assert not set(M.loc[cvfit,'hostname'])&set(M.loc[cvcheck,'hostname'])
    domain=DomainStage().fit(X,M,train);cvdomain=DomainStage().fit(X,M,cvfit)
    log('domain_fit',normal_forest_rows=domain.fit_rows,disjoint_host_normal_calibration_rows=domain.calibration_rows,
        calibration='Empirical anomaly percentiles from 20% reserved normal training hosts; upper decile maps to [0,1].',
        grouped_forward_rows=int(cvcheck.sum()))
    allfeatures={};cvfeatures={};candidates=[];models={}
    for rep in protocol['representations']:
        allfeatures[rep]=domain.transform(X,M,rep)[0]
        cvfeatures[rep]=cvdomain.transform(X,M,rep)[0]
    for spec in protocol['specs']:
        F=allfeatures[spec['rep']];CF=cvfeatures[spec['rep']]
        cvmodel=fit_booster(CF,M,cvfit,spec)
        cvap=float(average_precision_score(M.loc[cvcheck,'binary_label'],1-cvmodel.predict_proba(CF.loc[cvcheck])[:,0]))
        model=fit_booster(F,M,train,spec)
        p=1-model.predict_proba(F)[:,0]
        aptrain=float(average_precision_score(M.loc[train,'binary_label'],p[train]))
        ap0=float(average_precision_score(M.loc[v0,'binary_label'],p[v0]));ap1=float(average_precision_score(M.loc[v1,'binary_label'],p[v1]))
        utility=.45*ap1+.30*ap0+.25*cvap-.10*max(aptrain-cvap,0)
        row=dict(spec=spec,train_ap=aptrain,original_val_ap=ap0,new_val_ap=ap1,grouped_forward_ap=cvap,selection_score=utility)
        candidates.append(row);models[spec['name']]=model
        dump('tier2_candidates.json',candidates);log('tier2_candidate',**row)
    winner=max(candidates,key=lambda c:c['selection_score']);spec=winner['spec'];rep=spec['rep']
    boosters=[models[spec['name']],fit_booster(allfeatures[rep],M,train,spec,20261022)]
    F,risk,peak=domain.transform(X,M,rep)
    probs=np.mean([b.predict_proba(F) for b in boosters],axis=0);threat=1-probs[:,0]
    t_threat,threat_validation=threshold([(M.loc[v0,'binary_label'],threat[v0]),(M.loc[v1,'binary_label'],threat[v1])])
    log('tier2_selected',spec=spec,ensemble_seeds=protocol['seeds'],threshold=t_threat,validation=threat_validation)
    # Forward-only cross-fit upstream stages for RedRVFL. Each fold has its own IF calibration.
    oof_threat=np.full(len(M),np.nan);oof_risk=oof_threat.copy();oof_peak=oof_threat.copy()
    for lo,hi in [(20,35),(35,50),(50,60)]:
        fm=train&M.day_index.le(lo).to_numpy();target=train&M.day_index.gt(lo).to_numpy()&M.day_index.le(hi).to_numpy()
        dom=DomainStage().fit(X,M,fm);ff,rr,pk=dom.transform(X,M,rep)
        b=fit_booster(ff,M,fm,spec);tt=1-b.predict_proba(ff)[:,0]
        oof_threat[target]=tt[target];oof_risk[target]=rr[target];oof_peak[target]=pk[target]
        log('temporal_forward_fold',fit_end=lo,target_end=hi,fit_rows=int(fm.sum()),target_rows=int(target.sum()))
    pd.DataFrame(dict(hostname=M.hostname,date=M.date,split=M.split,forward_threat=oof_threat,forward_if=oof_risk,forward_if_peak=oof_peak)).to_csv(OUT/'forward_upstream_scores.csv',index=False)
    import torch
    torch.set_num_threads(2);RV=rvfl_class()
    temporal_candidates=[];temporal_models={}
    for fusion in protocol['fusion']:
        upstream=fuse(oof_threat,oof_risk,oof_peak,fusion)
        ss,yy,idx,hist=windows(upstream,M)
        clean=train[idx]&(M.binary_label.to_numpy()[idx]==0)&np.all(M.binary_label.to_numpy()[hist]==0,axis=1)&np.all(train[hist],axis=1)
        block=np.where(M.day_index.to_numpy()<=35,0,np.where(M.day_index.to_numpy()<=50,1,2))
        clean &= np.all(block[hist]==block[idx,None],axis=1)
        full_fused=fuse(threat,risk,peak,fusion);sq,yt,ri,_=windows(full_fused,M)
        for alpha in protocol['ridge_alpha']:
            rv=RV(input_features=1,hidden_size=64,num_layers=3,ridge_alpha=alpha,seed=20261021)
            rv.fit(ss[clean],yy[clean]);pred=np.full(len(M),np.nan);pred[ri]=np.clip(rv.predict(sq),0,1)
            for error_mode in protocol['error_modes']:
                error=drift(full_fused,pred,error_mode)
                tt,info=threshold([(M.loc[v0,'binary_label'],error[v0]),(M.loc[v1,'binary_label'],error[v1])])
                valap=min(r['pr_auc'] for r in info['populations']);utility=info['min_balanced_accuracy']+.05*valap
                name=f'{fusion}_alpha{alpha}_{error_mode}'
                row=dict(name=name,fusion=fusion,alpha=alpha,error_mode=error_mode,threshold=tt,
                    validation=info,selection_score=utility,clean_training_windows=int(clean.sum()))
                temporal_candidates.append(row);temporal_models[name]=rv
            log('temporal_candidate_pair',fusion=fusion,alpha=alpha,
                best_min_validation_balanced_accuracy=max(r['validation']['min_balanced_accuracy'] for r in temporal_candidates[-2:]))
    tw=max(temporal_candidates,key=lambda r:r['selection_score']);dump('temporal_candidates.json',temporal_candidates)
    bundle=dict(domain=domain,representation=rep,boosters=boosters,redrvfl=temporal_models[tw['name']],fusion=tw['fusion'],
                error_mode=tw['error_mode'],classes=CLASSES,thresholds=dict(threat=t_threat,drift=tw['threshold']),spec=spec)
    F,risk,probs,fused,pred,error=score(bundle,X,M)
    vranks=[host_rank(M.loc[mask].reset_index(drop=True),error[mask],last15=True) for mask in [v0,v1]]
    thost,host_validation=threshold([(r.binary_label,r.score) for r in vranks])
    bundle['thresholds']['host15']=thost
    joblib.dump(bundle,OUT/'pipeline.joblib')
    frozen=dict(model_sha256=sha(OUT/'pipeline.joblib'),timestamp=datetime.now(timezone.utc).isoformat(),
        tier2=winner,temporal=tw,thresholds=bundle['thresholds'],threat_validation=threat_validation,host_validation=host_validation,
        protocol_sha256=sha(OUT/'protocol.json'),source_sha256=sourcehash,
        holdout_63002_generated=False,known_limit='Historic benchmarks consumed previously; seed63002 shares synthetic mechanisms.')
    dump('frozen_selection.json',frozen);log('frozen',model_sha256=frozen['model_sha256'],selected=spec['name'],temporal=tw['name'],thresholds=bundle['thresholds'])
    # The prospective cohort is generated only here, after the freeze artifact exists.
    xp,mp=cohort(63002,'prospective_holdout')
    log('new_holdout_generated_after_freeze',seed=63002,rows=len(mp),attack_days=int(mp.binary_label.sum()),families=mp.scenario_label.value_counts().to_dict())
    evaluations={}
    def evaluate(name,xx,mm,ff,rr,pp,fu,pr,er):
        folder=OUT/name;folder.mkdir(exist_ok=True)
        prediction=mm.copy()
        for i,c in enumerate(CLASSES):prediction['prob_'+c]=pp[:,i]
        prediction['predicted_scenario']=np.asarray(CLASSES)[pp.argmax(axis=1)]
        prediction['if_risk']=rr;prediction['threat_probability']=1-pp[:,0];prediction['fused_risk']=fu
        prediction['forecasted_risk']=pr;prediction['drift_error']=er;prediction['temporal_available']=np.isfinite(er)
        prediction['threat_alert']=1-pp[:,0]>=bundle['thresholds']['threat']
        prediction['temporal_alert']=pd.array(np.where(np.isfinite(er),er>=bundle['thresholds']['drift'],None),dtype='boolean')
        prediction.to_csv(folder/'daily_predictions.csv',index=False)
        rank=host_rank(mm,er,last15=True);rank['host_alert']=rank.score>=thost;rank.to_csv(folder/'host_ranking_last15.csv',index=False)
        fullrank=host_rank(mm,er,last15=False);fullrank.to_csv(folder/'host_ranking_fullperiod_unthresholded.csv',index=False)
        known=mm.scenario_label.isin(CLASSES)
        info=dict(threat=measures(mm.binary_label,1-pp[:,0],bundle['thresholds']['threat']),
                  temporal=measures(mm.binary_label,er,bundle['thresholds']['drift']),
                  host_last15=measures(rank.binary_label,rank.score,thost),
                  host_fullperiod_ap=float(average_precision_score(fullrank.binary_label,fullrank.score)),
                  known_class_macro_f1=float(f1_score(mm.loc[known,'scenario_label'],np.asarray(CLASSES)[pp[known].argmax(axis=1)],labels=CLASSES,average='macro',zero_division=0)),
                  unavailable_temporal_rows=int((~np.isfinite(er)).sum()),per_scenario={})
        for sc,g in mm.groupby('scenario_label'):
            mask=mm.index.isin(g.index);finite=mask&np.isfinite(er)
            info['per_scenario'][sc]=dict(rows=int(mask.sum()),supervised_known=sc in CLASSES,
                threat_alert_rate=float((1-pp[mask,0]>=bundle['thresholds']['threat']).mean()),
                temporal_alert_rate=float((er[finite]>=bundle['thresholds']['drift']).mean()) if finite.any() else None)
        evaluations[name]=info
        log('evaluation',population=name,threat=info['threat'],temporal=info['temporal'],host15=info['host_last15'])
        return prediction,rank
    for name,mask in [('train_original',train&M.cohort.eq('original').to_numpy()),('train_augmented',train),('validation_original',v0),('validation_new',v1),('test',M.split.eq('test').to_numpy())]:
        evaluate(name,X.loc[mask].reset_index(drop=True),M.loc[mask].reset_index(drop=True),F.loc[mask],risk[mask],probs[mask],fused[mask],pred[mask],error[mask])
    for name,xx,mm in [('challenge',*pair(release/'challenge_30_days/daily_features')),
                       ('old_fresh',*pair(WORK/'anti_overfit_v2/fresh_holdout')),
                       ('prospective_holdout',xp,mp)]:
        ff,rr,pp,fu,pr,er=score(bundle,xx,mm);evaluate(name,xx,mm,ff,rr,pp,fu,pr,er)
    dump('evaluation.json',evaluations)
    # Explain the actual Tier 2 ensemble. TreeSHAP contributions average across both boosters.
    import xgboost as xgb
    testmask=M.split.eq('test').to_numpy();testmeta=M.loc[testmask].reset_index(drop=True);testF=F.loc[testmask].reset_index(drop=True)
    te=error[testmask];ranking=host_rank(testmeta,te,last15=True)
    chosen=[]
    for host in ranking.hostname.head(20):
        sub=testmeta.loc[testmeta.hostname.eq(host)].assign(error=te[testmeta.hostname.eq(host)])
        chosen.extend(sub.nlargest(3,'error').index.tolist())
    selected=testF.iloc[chosen];dm=xgb.DMatrix(selected,feature_names=list(selected))
    contrib=np.mean([b.get_booster().predict(dm,pred_contribs=True,strict_shape=True,approx_contribs=False) for b in boosters],axis=0)
    eachprobs=[b.predict_proba(selected) for b in boosters]
    findings=[];attributions=[]
    for i,pos in enumerate(chosen):
        cls=int(np.argmax(np.mean(eachprobs,axis=0)[i]));v=contrib[i,cls,:-1];top=np.argsort(-np.abs(v))[:5]
        findings.append(dict(hostname=testmeta.iloc[pos].hostname,date=testmeta.iloc[pos].date,scenario=CLASSES[cls],
            top_features=[dict(feature=selected.columns[j],value=float(selected.iloc[i,j]),signed_margin_contribution=float(v[j])) for j in top]))
        for c in range(6):
            for j,f in enumerate(list(selected)+['BIAS']):
                attributions.append(dict(hostname=testmeta.iloc[pos].hostname,date=testmeta.iloc[pos].date,scenario=CLASSES[c],feature=f,mean_signed_margin_contribution=float(contrib[i,c,j])))
    pd.DataFrame(attributions).to_csv(OUT/'treeshap_contributions.csv',index=False)
    dump('explanations.json',findings)
    pd.concat([testmeta.iloc[chosen][['hostname','date']].reset_index(drop=True),selected.reset_index(drop=True)],axis=1).to_csv(OUT/'selected_explanation_inputs.csv',index=False)
    residual=0.
    for b in boosters:
        bb=b.get_booster();cc=bb.predict(dm,pred_contribs=True,strict_shape=True);margin=bb.predict(dm,output_margin=True,strict_shape=True)
        residual=max(residual,float(np.abs(cc.sum(axis=-1)-margin).max()))
    # Check conservation/freeze and prospective inference without labels.
    reloaded=joblib.load(OUT/'pipeline.joblib')
    label_free=score(reloaded,xp,mp[['hostname','date']])
    ref=pd.read_csv(OUT/'prospective_holdout/daily_predictions.csv')
    assert np.allclose(label_free[2][:,0],ref.prob_BENIGN,atol=1e-7)
    assert np.allclose(label_free[-1],ref.drift_error,equal_nan=True,atol=1e-7)
    assert sha(OUT/'pipeline.joblib')==frozen['model_sha256']
    assert all(sha(WORK/p)==h for p,h in sourcehash.items())
    # Holdout exact-vector overlap is checked after generation, never removed selectively.
    overlap=int(pd.util.hash_pandas_object(xp,index=False).isin(set(train_hash)).sum())
    assert overlap==0
    check=dict(model_frozen_unchanged=True,source_inputs_unchanged=True,prospective_generated_after_freeze=True,
        prospective_exact_training_duplicates=overlap,label_free_reload_matches=True,
        grouped_forward_hosts_disjoint=True,normal_if_calibration_hosts_disjoint=True,
        tree_shap_max_margin_reconstruction_error=residual,
        explanation_note='Average per-booster margin contributions; these do not add to averaged probability or its logit.',
        ordered_inputs=40,probabilities=6,training_rows=int(train.sum()),
        clean_temporal_windows=tw['clean_training_windows'])
    dump('checks.json',check)
    dump('schema.json',dict(raw_columns=list(X),model_columns=list(F),classes=CLASSES))
    dump('environment.json',dict(python=platform.python_version(),packages={p:__import__(p).__version__ for p in ['numpy','pandas','sklearn','xgboost','torch','joblib']}))
    (OUT/'explanation_findings.md').write_text('# Ensemble local TreeSHAP findings\n\nMean signed per-booster class-margin contributions explain Tier 2, not RedRVFL or ensemble probability.\n\n'+'\n\n'.join(f"- {r['hostname']} / {r['date']}: {r['scenario']}; "+'; '.join(f"{f['feature']} {f['signed_margin_contribution']:+.4f}" for f in r['top_features']) for r in findings),encoding='utf8')
    log('complete',seconds=round(time.time()-start,1),checks=check)
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-dir',type=Path,default=OUT)
    args=parser.parse_args()
    OUT=args.run_dir.resolve();OUT.mkdir(parents=True,exist_ok=True)
    try:run()
    except Exception as e:
        log('run_error',error=repr(e));raise
