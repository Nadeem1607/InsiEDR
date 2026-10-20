"""Evaluate ranked review queues; a review candidate is not a confirmed insider."""
from pathlib import Path
import json
import pandas as pd

ROOT=Path(__file__).resolve().parent
RUN=ROOT/'run'
KS=[5,10,15,20,30]

def main():
    rows=[]
    for population in ['test','challenge','prospective_holdout']:
        for window,filename in [('last15','host_ranking_last15.csv'),('fullperiod','host_ranking_fullperiod_unthresholded.csv')]:
            ranked=pd.read_csv(RUN/population/filename)
            ranked=ranked.loc[ranked.eligible&ranked.score.notna()].sort_values('rank')
            assert ranked.score.is_monotonic_decreasing
            attacks=int(ranked.binary_label.sum());normal=len(ranked)-attacks
            for k in KS:
                selected=ranked.head(k);tp=int(selected.binary_label.sum());fp=len(selected)-tp
                precision=tp/len(selected);recall=tp/attacks if attacks else 0
                rows.append(dict(population=population,window=window,k=k,eligible_hosts=len(ranked),
                    attack_hosts=attacks,attack_hosts_in_top_k=tp,normal_hosts_in_top_k=fp,
                    attack_hosts_outside_top_k=attacks-tp,precision_at_k=precision,recall_at_k=recall,
                    normal_host_review_rate=fp/normal if normal else 0,
                    review_fraction=len(selected)/len(ranked),
                    f1_at_k=2*precision*recall/(precision+recall) if precision+recall else 0))
    frame=pd.DataFrame(rows);frame.to_csv(RUN/'top_k_evaluation.csv',index=False)
    (RUN/'top_k_evaluation.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    lines=['# Top-K investigation queue evaluation','',
        'The model ranks hosts by max(error) × mean(error) × sqrt(sequence count). Top-K selects the first K ranked **review candidates**, irrespective of the binary alert threshold. It does not establish malicious intent or identify a confirmed insider. Positive/normal labels below are synthetic evaluation ground truth.','',
        'Primary results use the latest 15 eligible daily forecast errors for every host. Recall counts attack hosts within that same interval; it does not count every host attacked anywhere in the longer dataset. There are 216 eligible hosts per population.','']
    for window,title in [('last15','Equal 15-day ranking windows'),('fullperiod','Supplementary full-period rankings')]:
        lines+=['## '+title,'']
        if window=='fullperiod':lines+=['These intervals have different durations and different attack-host denominators. Do not compare these directly as equal-exposure evaluations. Test: 15 scored days; challenge: 23; prospective cohort: 53. The first seven standalone days lack forecasts.','']
        for population in ['test','challenge','prospective_holdout']:
            subset=frame.loc[frame.population.eq(population)&frame.window.eq(window)]
            lines += [f"### {population}: {int(subset.iloc[0].attack_hosts)} attack hosts",'',
                      '| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |',
                      '|---:|---:|---:|---:|---:|']
            for r in subset.itertuples():
                lines.append(f'| {r.k} | {r.attack_hosts_in_top_k}/{r.attack_hosts} | {r.normal_hosts_in_top_k} | {r.precision_at_k:.1%} | {r.recall_at_k:.1%} |')
            lines.append('')
    lines+=['## Interpretation','',
       'Recall@K answers how many attack hosts enter the investigation queue. Precision@K answers how many reviewed hosts truly have simulated attacks. Increasing K usually catches more attack hosts while increasing investigation workload. Neither metric is the model’s ordinary daily accuracy.',
       '', 'K values are reported as requested without selecting a preferred K on these test outcomes. Historical test/challenge data were previously inspected; the prospective cohort was generated after model freeze, but still shares synthetic mechanisms. Ground truth determines evaluation counts only, never the ranking order.']
    (RUN/'TOP_K_EVALUATION.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(frame.loc[frame.window.eq('last15'),['population','k','attack_hosts','attack_hosts_in_top_k','normal_hosts_in_top_k','precision_at_k','recall_at_k']].to_string(index=False))
if __name__=='__main__':main()
