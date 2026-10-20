"""Label-free inference. Inputs must contain continuous daily history plus targets."""
import os
os.environ.setdefault('OMP_NUM_THREADS','2')
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from core import rvfl_class,score,host_rank
def main():
    p=argparse.ArgumentParser();p.add_argument('--features',required=True,type=Path)
    p.add_argument('--metadata',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--top-k',type=int,default=20,help='Number of ranked investigation candidates; not confirmed insiders')
    p.add_argument('--model',type=Path,default=Path(__file__).with_name('run')/'pipeline.joblib');a=p.parse_args()
    if a.top_k<1:raise ValueError('--top-k must be positive')
    rvfl_class()
    import torch
    torch.set_num_threads(2)
    bundle=joblib.load(a.model);X=pd.read_csv(a.features);M=pd.read_csv(a.metadata)[['hostname','date']]
    _,risk,prob,fused,pred,error=score(bundle,X,M)
    result=M.copy()
    for i,c in enumerate(bundle['classes']):result['prob_'+c]=prob[:,i]
    result['predicted_scenario']=np.asarray(bundle['classes'])[prob.argmax(axis=1)]
    result['if_risk']=risk;result['threat_probability']=1-prob[:,0];result['fused_risk']=fused
    result['forecasted_risk']=pred;result['drift_error']=error;result['temporal_available']=np.isfinite(error)
    result['threat_alert']=1-prob[:,0]>=bundle['thresholds']['threat']
    result['temporal_alert']=pd.array(np.where(np.isfinite(error),error>=bundle['thresholds']['drift'],None),dtype='boolean')
    a.output.mkdir(parents=True,exist_ok=True);result.to_csv(a.output/'daily_predictions.csv',index=False)
    rank=host_rank(M,error,last15=True);rank['host_alert']=rank.score>=bundle['thresholds']['host15']
    rank.to_csv(a.output/'host_ranking_last15.csv',index=False)
    queue=rank.loc[rank.eligible & rank.score.notna()].head(a.top_k).copy()
    queue['review_status']='review_candidate'
    queue['insider_confirmation']='not_assessed'
    queue.to_csv(a.output/'top_k_review_queue.csv',index=False)
    print(f'Predictions: {len(result)}; temporal targets available: {np.isfinite(error).sum()}')
if __name__=='__main__':main()
