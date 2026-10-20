"""Reproducible synthetic research telemetry. Does not modify source archives."""
from __future__ import annotations
import argparse, csv, hashlib, json, math, platform, shutil, sys, zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parent.parent
START=datetime(2026,1,1)
CLASSES=['BENIGN','CREDENTIAL_DUMP','USB_EXFILTRATION_PRECURSOR','IT_SABOTAGE','CLOUD_EXFILTRATION_PRECURSOR','DATA_HOARDING','HONEYTOKEN_TRIP','KILL_CHAIN_APT']
FEATURES=['successful_logons','failed_logons','after_hours_logon_ratio','unique_pc_count','pc_access_entropy','interactive_duration_seconds','mean_session_duration_seconds','weekend_activity','usb_connect_count','usb_disconnect_count','after_hours_usb_ratio','distinct_usb_devices','file_access_count','unique_filename_count','new_filename_count','file_delete_count','file_access_entropy','protected_file_touch_count','http_request_count','unique_domain_count','new_domain_count','external_domain_ratio','domain_access_entropy','file_sharing_visit_count','mean_process_count','peak_process_count','admin_process_count','temp_exec_count','bytes_sent','bytes_received','external_connection_count','unique_remote_ip_count','clipboard_copy_count','lsass_handle_request_count','memory_dump_attempt_count','decoy_access_count','wmi_query_count','named_pipe_event_count','dns_query_count','outbound_attachment_count']
FLOATS={'after_hours_logon_ratio','pc_access_entropy','mean_session_duration_seconds','after_hours_usb_ratio','file_access_entropy','external_domain_ratio','domain_access_entropy','mean_process_count'}
FLAGS={'weekend_activity'}
COUNT_FEATURES=[c for c in FEATURES if c not in FLOATS|FLAGS]
EVIDENCE={
 'CREDENTIAL_DUMP':['lsass-monitor','memory-scanner','process-watcher','short-term_edr_feature'],
 'USB_EXFILTRATION_PRECURSOR':['devices','file-integrity-monitor','usn-monitor','short-term_edr_feature'],
 'IT_SABOTAGE':['file-integrity-monitor','process-watcher','persistence-monitor','short-term_edr_feature'],
 'CLOUD_EXFILTRATION_PRECURSOR':['http','network','short-term_edr_feature'],
 'DATA_HOARDING':['clipboard-monitor','file-integrity-monitor','activity-monitor','short-term_edr_feature'],
 'HONEYTOKEN_TRIP':['decoy-monitor','file-integrity-monitor','logon'],
 'RECON':['wmi-activity','named-pipe-monitor','short-term_edr_feature','network'],
 'STAGING':['clipboard-monitor','file-integrity-monitor','decoy-monitor']}

def dump(path,obj):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(obj,indent=2,ensure_ascii=False,allow_nan=False),encoding='utf-8')

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def entropy(counts):
 a=np.asarray(counts,float);a=a[a>0]
 if not len(a):return 0.
 p=a/a.sum();return float(-(p*np.log(p)).sum())

def alloc(rng,n,weights):
 return rng.multinomial(int(n),np.asarray(weights)/np.sum(weights))

def memberships(rng,total,distinct,weights,seen,day,interval_totals):
 """Generate event-category counts; unique counts/entropy come from common events."""
 total=int(total);u=min(int(distinct),total,512)
 if u==0:return np.zeros(4,int),np.zeros(4,int),np.zeros(4),np.zeros(4,int)
 pool=128
 oldn=min(u,int(rng.binomial(u,.94)),pool)
 ids=list(rng.choice(pool,oldn,replace=False))+[1000000+day*1000+i for i in range(u-oldn)]
 counts=1+rng.multinomial(total-u,rng.dirichlet(np.full(u,2.)))
 event_categories=np.repeat(np.arange(u),counts)
 rng.shuffle(event_categories)
 cuts=np.r_[0,np.cumsum(interval_totals)]
 per=np.stack([np.bincount(event_categories[cuts[j]:cuts[j+1]],minlength=u) for j in range(4)],axis=1)
 cumulative=per.cumsum(axis=1)
 uniques=np.count_nonzero(cumulative,axis=0)
 newmask=np.array([int(i) not in seen for i in ids])
 news=np.count_nonzero((cumulative>0)&newmask[:,None],axis=0)
 ents=np.array([entropy(cumulative[:,j]) for j in range(4)])
 seen.update(int(i) for i in ids)
 return per.sum(axis=0),uniques,ents,news

def schedules(hosts,seed):
 rng=np.random.default_rng(seed);dev=list(rng.choice(hosts,36,replace=False))
 out=[]
 def add(host,split,lo,hi,scenario,index):
  duration=int(rng.integers(2,5));start=int(rng.integers(lo,hi-duration+1))
  out.append({'campaign_id':f'{split}-C{index:03d}','hostname':host,'split':split,'scenario':scenario,'start_day_index':start,'end_day_index_exclusive':start+duration,'start_time':(START+timedelta(days=start-1)).isoformat()+'Z','end_time':(START+timedelta(days=start+duration-1)).isoformat()+'Z','variant_id':int(rng.integers(1,2**31)),'severity':float(rng.uniform(.2,2.1) if split=='train' else rng.uniform(.2,2.1))})
 for rep in range(3):
  lo,hi=[(12,26),(29,43),(46,60)][rep]
  for i,h in enumerate(dev[:18]):add(h,'train',lo,hi,CLASSES[1+(i+rep*2)%7],rep*18+i)
 for split,subset,lo,hi in [('validation',dev[18:27],63,75),('test',dev[27:],78,90)]:
  for i,h in enumerate(subset):add(h,split,lo,hi,CLASSES[1+i%7],i)
 # Retain 180 previously observed hosts, including all campaign hosts; add 36 new.
 normal=[h for h in hosts if h not in dev]
 challenge_known=dev+list(rng.choice(normal,144,replace=False))
 newhosts=[f'SYNTH-HOLDOUT-{i:03d}' for i in range(1,37)]
 challenge_hosts=challenge_known+newhosts
 challenge_targets=list(rng.choice(challenge_known,12,replace=False))+list(rng.choice(newhosts,12,replace=False))
 for i,h in enumerate(challenge_targets):add(h,'challenge',94,120,CLASSES[1+i%7],i)
 return out,dev,challenge_hosts,newhosts

def build(out:Path,seed:int,write_feeds=True):
 if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
 out.mkdir(parents=True)
 ref_path=Path(__file__).with_name('reference_config.json')
 if ref_path.exists():
  ref=json.loads(ref_path.read_text(encoding='utf-8'));schemas=ref['schemas'];hosts=ref['hosts'];process_median=ref['process_median'];process_spread=ref['process_spread'];provenance=ref['provenance']
 else:
  profile=json.loads((ROOT/'dataset_comparison/dataset_profile.json').read_text(encoding='utf-8'))
  schemas={k:v['column_names'] for k,v in profile['datasets']['original'].items()}
  src=pd.read_pickle(ROOT/'dataset_comparison/original_process-watcher_local.pkl')
  hosts=sorted(src.hostname.unique());assert len(hosts)==216
  excluded={'SOCL2-64','DSL-174','DATASL-173','MCALAB1-07','SOCL8-53','SOCL8-03','SOCL4-61'}
  reference=src.loc[src.timestamp_dt.lt('2026-10-10')&~src.hostname.isin(excluded),'process_count']
  process_median=float(reference.median());process_spread=float(reference.std())
  provenance=json.loads((ROOT/'dataset_comparison/audit_provenance.json').read_text(encoding='utf-8'))
 ref={'schemas':schemas,'hosts':hosts,'process_median':process_median,'process_spread':process_spread,'provenance':provenance}
 dump(out/'reference_config.json',ref)
 campaigns,campaign_hosts,challenge_hosts,newhosts=schedules(hosts,seed)
 configs={'development_90_days':(1,60,hosts)}
 writers={};handles=[];rows_written=Counter();populated={feed:set() for feed in schemas}
 allmeta={k:[] for k in configs};allfeatures={k:[] for k in configs}
 evidence_counts=Counter();quality={'count_violations':0,'ratio_violations':0,'subset_violations':0,'identity_violations':0}
 for package in configs:
  for folder in ['feeds','daily_features','labels','splits']:(out/package/folder).mkdir(parents=True,exist_ok=True)
  for feed,columns in (schemas.items() if write_feeds else []):
   path=out/package/'feeds'/f'{feed}_dataset_generated.csv'
   f=path.open('w',newline='',encoding='utf-8');handles.append(f)
   w=csv.writer(f);w.writerow(columns);writers[package,feed]=w
 evidence_file=(out/'collector_evidence_labels.csv').open('w',newline='',encoding='utf-8');handles.append(evidence_file)
 ew=csv.writer(evidence_file);ew.writerow(['package','hostname','timestamp_utc','campaign_id','scenario_label','phase','active_collectors'])
 # Each host has persistent role, independent innovation RNG, and evolving state.
 states={}
 for index,h in enumerate(hosts+newhosts):
  r=np.random.default_rng(np.random.SeedSequence([seed, index, 761]))
  states[h]={'rng':r,'latent':0.,'role':float(r.lognormal(0,.35)),'trend':float(r.uniform(-.001,.001)), 'process_base':float(np.clip(r.normal(process_median,max(process_spread,15)),70,450)), 'sent_total':0,'recv_total':0,'clipboard_sequence':int(r.integers(10,1000)),'files':set(range(128)),'domains':set(range(128)),'index':index,'baseline_days':0}
 campmap={}
 for c in campaigns:
  for d in range(c['start_day_index'],c['end_day_index_exclusive']):campmap[c['hostname'],d]=c
 for day in range(1,61):
  date=START+timedelta(days=day-1);package='development_90_days' if day<=90 else 'challenge_30_days'
  activehosts=configs[package][2]
  for host in activehosts:
   s=states[host];rng=s['rng'];s['latent']=.87*s['latent']+float(rng.normal(0,.11))
   weekday=date.weekday();season=[1.,1.04,1.02,.98,.91,.38,.24][weekday]
   work=float(np.clip(season*s['role']*np.exp(s['latent']+s['trend']*day),.025,5.))
   # Small covariate shift in challenge; no dependence on scenario class.
   if day>90:work*=1.08
   weights=np.array([.035,.45,.46,.055])*rng.lognormal(0,.2,4);weights/=weights.sum()
   maintenance=bool(rng.random()<.035)
   benign_burst=bool(rng.random()<.045)
   base={'auth':int(rng.poisson(5*work)), 'failed':int(rng.poisson(.4*work)), 'usb':int(rng.poisson(.8*work)), 'files':int(rng.poisson(180*work)), 'delete':int(rng.poisson(3*work)), 'http':int(rng.poisson(100*work)), 'clipboard':int(rng.poisson(7*work)), 'handles':int(rng.poisson(.3+work*.08)), 'dumps':int(rng.random()<.009), 'decoy':int(rng.random()<.007),'wmi':int(rng.poisson(4*work+.2)),'pipes':int(rng.poisson(6*work+1)),'attachments':int(rng.poisson(1.2*work)),'protected':int(rng.poisson(.12*work))}
   if maintenance:
    base['handles']+=int(rng.integers(3,24));base['dumps']+=int(rng.random()<.35);base['wmi']+=int(rng.integers(4,25));base['pipes']+=int(rng.integers(4,25))
   if benign_burst:
    base['files']+=int(rng.integers(80,650));base['http']+=int(rng.integers(60,500));base['clipboard']+=int(rng.integers(3,35))
   c=campmap.get((host,day));scenario=c['scenario'] if c else 'BENIGN'
   phases=[]
   if c:
    if scenario=='KILL_CHAIN_APT':
     span=(c['end_day_index_exclusive']-c['start_day_index'])*4
     phase_names=['CREDENTIAL_DUMP','RECON','STAGING','CLOUD_EXFILTRATION_PRECURSOR']
     phases=[phase_names[min(3,((day-c['start_day_index'])*4+j)*4//span)] for j in range(4)]
    else:phases=[scenario]*4
   else:phases=['BENIGN']*4
   severity=(c['severity']*float(rng.lognormal(0,.25))) if c else 0.
   # Mechanism events overlap benign maintenance/burst magnitudes. They are not
   # fixed hardcoded class signatures, and vary within each campaign.
   extra={k:np.zeros(4,int) for k in ['auth','failed','usb','files','delete','http','clipboard','handles','dumps','decoy','wmi','pipes','attachments','protected']}
   for j,phase in enumerate(phases):
    if phase=='BENIGN':continue
    def inc(k,lo,hi):extra[k][j]+=int(rng.poisson(float(rng.uniform(lo,hi))*severity))
    if phase=='CREDENTIAL_DUMP':inc('handles',1,7);inc('dumps',.05,.8);inc('failed',0,2)
    elif phase=='USB_EXFILTRATION_PRECURSOR':inc('usb',0,2);inc('files',15,100)
    elif phase=='IT_SABOTAGE':inc('delete',4,35);inc('files',8,60);inc('protected',.2,3)
    elif phase=='CLOUD_EXFILTRATION_PRECURSOR':inc('http',15,100);inc('files',5,45)
    elif phase=='DATA_HOARDING':inc('files',20,100);inc('clipboard',2,12)
    elif phase=='HONEYTOKEN_TRIP':inc('decoy',.3,1.5);inc('files',3,20);inc('failed',0,1)
    elif phase=='RECON':inc('wmi',2,10);inc('pipes',1,8);inc('auth',0,2)
    elif phase=='STAGING':inc('files',20,100);inc('clipboard',1,8);inc('decoy',0,.7)
   totals={k:base[k]+int(extra[k].sum()) for k in extra}
   # Allocate baseline events independently of campaign timing, add the ordered
   # mechanism events at their actual interval. No labels enter the feature matrix.
   arr={k:alloc(rng,base[k],weights)+extra[k] for k in extra}
   filetotal=totals['files'];ftypes=min(filetotal,max(0,int(filetotal*rng.uniform(.3,.8))))
   files,fu,fe,fn=memberships(rng,filetotal,ftypes,weights,s['files'],day,arr['files'])
   # Reallocate file categories by interval including mechanism events while
   # preserving exact event totals: use category table's counts as the event stream.
   arr['files']=files
   httptotal=totals['http'];dtypes=min(httptotal,max(0,int(np.sqrt(httptotal)*rng.uniform(1,2.4))))
   requests,du,de,dn=memberships(rng,httptotal,dtypes,weights,s['domains'],day,arr['http'])
   arr['http']=requests
   deletes=np.minimum(arr['delete'],arr['files']);protected=np.minimum(arr['protected'],arr['files'])
   external=np.array([rng.binomial(int(n),float(rng.beta(4,2))) for n in requests])
   sharing=np.array([rng.binomial(int(n),.012+(.035*min(severity,2) if phases[j]=='CLOUD_EXFILTRATION_PRECURSOR' else 0)) for j,n in enumerate(requests)])
   successful=arr['auth'];failed=arr['failed'];auth=successful+failed
   afterhours=successful*np.array([1,0,0,1]);after_usb=arr['usb']*np.array([1,0,0,1])
   pc=int(min(int(successful.sum()),1+int(rng.poisson(.25*work))+(int(extra['auth'].sum())>0)))
   pcent=entropy(np.ones(pc))
   duration=int(min(86400,int(successful.sum())*rng.uniform(800,2600)))
   durations=alloc(rng,duration,successful) if successful.sum() else np.zeros(4,int)
   durations=np.minimum(durations,21600)
   duration=int(durations.sum())
   process=np.maximum(0,np.rint(s['process_base']+rng.normal(0,9,4)+s['latent']*12)).astype(int)
   admin=np.array([rng.poisson(.12*work+(.8 if maintenance else 0)+(.35*severity if phases[j] in ['CREDENTIAL_DUMP','IT_SABOTAGE'] else 0)) for j in range(4)])
   temp=np.array([rng.poisson(.08*work+(.3 if maintenance else 0)+(.25*severity if phases[j] in ['CREDENTIAL_DUMP','IT_SABOTAGE'] else 0)) for j in range(4)])
   process=np.maximum(process,admin+temp)
   sent=np.maximum(0,np.rint((requests*float(rng.lognormal(10.6,.4))+files*float(rng.lognormal(8,.4))+rng.lognormal(13,.4,4))*(1+.25*severity if c and scenario in ['CLOUD_EXFILTRATION_PRECURSOR','KILL_CHAIN_APT'] else 1))).astype(np.int64)
   received=np.maximum(0,np.rint(requests*float(rng.lognormal(12,.4))+rng.lognormal(14,.4,4))).astype(np.int64)
   conns=np.maximum(1,np.rint(requests*.15+rng.poisson(5,4))).astype(int)
   extcon=np.array([rng.binomial(int(n),.65) for n in conns]);uniqueips=int(min(int(extcon.sum()),max(0,int(np.sqrt(extcon.sum())*rng.uniform(1,2)))))
   dns=np.maximum(conns,np.array([rng.poisson(float(n)*1.4+3) for n in conns]))
   distinctusb=min(int(arr['usb'].sum()),int(rng.integers(1,4))) if arr['usb'].sum() else 0
   feature=[int(successful.sum()),int(failed.sum()),float(afterhours.sum()/max(successful.sum(),1)),pc,pcent,duration,float(duration/max(successful.sum(),1)),int(weekday>=5 and successful.sum()>0),int(arr['usb'].sum()),int(arr['usb'].sum()),float(after_usb.sum()/max(arr['usb'].sum(),1)),distinctusb,int(files.sum()),int(fu[-1]),int(fn[-1]),int(deletes.sum()),float(fe[-1]),int(protected.sum()),int(requests.sum()),int(du[-1]),int(dn[-1]),float(external.sum()/max(requests.sum(),1)),float(de[-1]),int(sharing.sum()),float(process.mean()),int(process.max()),int(admin.max()),int(temp.max()),int(sent.sum()),int(received.sum()),int(extcon.sum()),uniqueips,int(arr['clipboard'].sum()),int(arr['handles'].sum()),int(arr['dumps'].sum()),int(arr['decoy'].sum()),int(arr['wmi'].sum()),int(arr['pipes'].sum()),int(dns.sum()),int(arr['attachments'].sum())]
   v=dict(zip(FEATURES,feature));assert len(v)==40
   for key in COUNT_FEATURES:quality['count_violations']+=int(v[key]<0 or v[key]!=int(v[key]))
   for key in ['after_hours_logon_ratio','after_hours_usb_ratio','external_domain_ratio']:quality['ratio_violations']+=int(not 0<=v[key]<=1)
   quality['subset_violations']+=int(not (v['new_filename_count']<=v['unique_filename_count']<=v['file_access_count'] and v['new_domain_count']<=v['unique_domain_count']<=v['http_request_count'] and v['file_sharing_visit_count']<=v['http_request_count'] and v['unique_remote_ip_count']<=v['external_connection_count']))
   split='train' if day<=60 else 'validation' if day<=75 else 'test' if day<=90 else 'challenge'
   idx=len(allmeta[package]);meta={'row_id':idx,'date':date.strftime('%Y-%m-%d'),'day_index':day,'hostname':host,'agent_id':'AGENT-'+host,'split':split,'scenario_label':scenario,'binary_label':int(c is not None),'campaign_id':c['campaign_id'] if c else '', 'known_to_development':int(host not in newhosts),'benign_maintenance':int(maintenance and c is None),'benign_activity_burst':int(benign_burst and c is None),'observation_complete':1}
   allmeta[package].append(meta);allfeatures[package].append(feature)
   for j in range(4):
    timestamp=(date+timedelta(hours=6*(j+1))-timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    if c:
     active=EVIDENCE.get(phases[j],[])
     ew.writerow([package,host,timestamp,c['campaign_id'],scenario,phases[j],';'.join(active)])
     for feed in active:evidence_counts[package,feed]+=1
    cumreq=int(requests[:j+1].sum());cumext=int(external[:j+1].sum());cumlog=int(successful[:j+1].sum())
    total_auth=int(auth[j]);window=int(rng.binomial(total_auth,5/360));failwindow=int(rng.hypergeometric(int(failed[j]),int(successful[j]),window)) if total_auth and window else 0
    s['sent_total']+=int(sent[j]);s['recv_total']+=int(received[j]);s['clipboard_sequence']+=int(arr['clipboard'][j])
    record={
    'activity-monitor':{'is_user_active':int(successful[j]>0),'last_input_tick':int(day*86400000+j*21600000),'user_idle_seconds':float(rng.uniform(0,600) if successful[j]>0 else rng.uniform(600,21600))},
    'clipboard-monitor':{'clipboard_copy_count':int(arr['clipboard'][j]),'clipboard_sequence':s['clipboard_sequence'],'monitor_active':1},
    'decoy-monitor':{'current_size':36,'events_recorded':int(arr['decoy'][j]),'monitored_decoys':'["SYNTHETIC_CANARY.xlsx"]'},
    'devices':{'after_hours_usb_usage':int(after_usb[j]>0),'daily_device_connect_count':int(arr['usb'][:j+1].sum()),'daily_device_usage_flag':int(arr['usb'][:j+1].sum()>0),'first_usb_usage_time':float(np.flatnonzero(arr['usb'][:j+1])[0]*6) if arr['usb'][:j+1].sum() else '', 'usb_connect_count':int(arr['usb'][j]),'usb_device_names':'["SYNTHETIC_USB"]' if arr['usb'][j] else '[]','usb_devices_count':min(distinctusb,int(arr['usb'][j])),'usb_disconnect_count':int(arr['usb'][j])},
    'dns-monitor':{'channel':'synthetic','etw_realtime_active':1,'suspicious_queries_count':0,'total_queries_captured':int(dns[j])},
    'driver-monitor':{'driver_count':80,'drivers_sample':'["synthetic_driver.sys"]','running_drivers':80},
    'email-monitor':{'email_clients_installed':'["SYNTHETIC_MAIL"]','external_recipient_ratio':float(rng.beta(2,5)),'monitor_active':1,'outbound_attachment_count':int(arr['attachments'][j])},
    'file-integrity-monitor':{'daily_file_access_entropy':float(fe[j]),'daily_new_filename_count':int(fn[j]),'daily_unique_filename_count':int(fu[j]),'event_count':int(files[j]),'file_access_count':int(files[j]),'monitor_active':1},
    'http':{'browser_db_found':1,'daily_domain_access_entropy':float(de[j]),'daily_external_domain_ratio':cumext/max(cumreq,1),'daily_http_request_count':cumreq,'daily_new_domain_count':int(dn[j]),'daily_unique_domain_count':int(du[j]),'domain_entropy':float(de[j]),'external_url_ratio':cumext/max(cumreq,1),'file_sharing_site_visits':int(sharing[:j+1].sum()),'http_after_hours':int(j in [0,3] and requests[j]>0)},
    'keystroke-collector':{'backspace_rate':.04,'backspace_ratio':.04,'digraph_latency':float(rng.uniform(70,150)),'dwell_sample_count':int(successful[j]*20),'error_rate':.04,'flight_sample_count':int(successful[j]*20),'flight_time_mean':float(rng.uniform(50,140)),'hold_time_mean':float(rng.uniform(60,130)),'mean_dwell_time_ms':90.,'mean_flight_time_ms':80.,'std_dwell_time_ms':15.,'std_flight_time_ms':20.,'total_keys_sampled':int(successful[j]*40),'typing_speed_cpm':180.,'typing_speed_wpm':36.},
    'logon':{'after_hours_logon':int(afterhours[:j+1].sum()),'concurrent_sessions':int(successful[j]>0),'daily_after_hours_logon_ratio':float(afterhours[:j+1].sum()/max(cumlog,1)),'daily_pc_access_entropy':entropy(np.ones(min(pc,cumlog))),'daily_unique_pc_count':min(pc,cumlog),'etw_lifecycle_events_started_count':int(successful[j]),'etw_lifecycle_events_stopped_count':int(successful[j]),'event_count':int(auth[j]),'failed_logons':int(failed[j]),'interactive_duration_seconds':int(durations[j]),'logoff_count':int(successful[j]),'logon_count':cumlog,'logon_entropy':entropy(np.ones(min(pc,cumlog))),'logon_type':2 if successful[j] else 0,'session_duration_avg':float(durations[:j+1].sum()/max(cumlog,1)),'successful_logons':cumlog,'unique_pc_count':min(pc,cumlog),'weekend_logon':int(weekday>=5 and cumlog>0)},
    'lsass-monitor':{'event_count':int(arr['handles'][j]+arr['dumps'][j]),'handle_requests':int(arr['handles'][j]),'memory_dump_attempts':int(arr['dumps'][j]),'target_process':'lsass.exe'},
    'memory-scanner':{'phantom_hollowed_mappings':int(arr['dumps'][j]),'reflective_pe_injections':0,'target_processes_scanned':int(process[j]),'threats_detected':0,'unbacked_executable_regions':int(arr['handles'][j]//4)},
    'named-pipe-monitor':{'named_pipes_sample':'[]','pipe_count':int(arr['pipes'][j])},
    'network':{'active_connections_count':int(conns[j]),'connection_count':int(conns[j]),'bytes_received':s['recv_total'],'bytes_sent':s['sent_total']},
    'persistence-monitor':{'entry_count':int(35+admin[j]),'total_monitored_keys':120},
    'process-watcher':{'admin_process_count':int(admin[j]),'etw_realtime_active':1,'executables_from_temp_folder':int(temp[j]),'process_count':int(process[j]),'tunneling_process_count':0},
    'short-term_edr_feature':{'auth_fail_rate_300s':failwindow/5,'auth_rate_300s':window/5,'edr_auth_event_count_window':window,'edr_auth_events_per_minute_window':window/5,'edr_failed_auth_events_per_minute_window':failwindow/5,'edr_failed_auth_ratio_window':failwindow/max(window,1),'edr_unique_logon_type_count_window':int(window>0),'logon_velocity_zscore':float((window-.2)/max(.5,.2**.5)),'off_hours_auth_count':int(afterhours[j]),'unique_workstations_300s':min(pc,window)},
    'usn-monitor':{'usn_records_captured':int(files[j]+deletes[j]),'note':''},
    'wmi-activity':{'channel':'synthetic','total_queries_captured':int(arr['wmi'][j])}}
    for feed,columns in schemas.items():
     values={'timestamp':timestamp,'username':f'SYNTH_USER_{s["index"]:03d}','hostname':host,'agent_id':'AGENT-'+host,'status':'success',**record[feed]}
     populated[feed].update(k for k,val in values.items() if val!='')
     if write_feeds: writers[package,feed].writerow([values.get(k,'') for k in columns])
     rows_written[package,feed]+=1
  if day%10==0:print(f'Generated training day {day}/60',flush=True)
 for f in handles:f.close()
 sequence_stats={};matrix_stats={}
 for package in configs:
  p=out/package;X=pd.DataFrame(allfeatures[package],columns=FEATURES);meta=pd.DataFrame(allmeta[package]);X.to_csv(p/'daily_features/X.csv',index=False,float_format='%.10g');meta.to_csv(p/'daily_features/metadata.csv',index=False)
  meta[['row_id','hostname','date','scenario_label','binary_label','campaign_id']].to_csv(p/'labels/host_day_labels.csv',index=False)
  for split in meta.split.unique():
   mask=meta.split.eq(split);d=p/'splits'/split;d.mkdir()
   X.loc[mask].to_csv(d/'X.csv',index=False,float_format='%.10g');meta.loc[mask].to_csv(d/'metadata.csv',index=False)
  seq_inputs={};seq_targets={}
  for h,g in meta.groupby('hostname',sort=False):
   g=g.sort_values('day_index');ids=g.row_id.to_numpy();days=g.day_index.to_numpy();normal=g.binary_label.eq(0).to_numpy()
   for t in range(7,len(g)):
    if not np.all(np.diff(days[t-7:t+1])==1):continue
    split=g.iloc[t]['split']
    if split=='train' and not np.all(normal[t-7:t+1]):continue
    seq_inputs.setdefault(split,[]).append(ids[t-7:t]);seq_targets.setdefault(split,[]).append(ids[t])
  arrays={}
  for split in seq_inputs:
   arrays[split+'_input_rows']=np.asarray(seq_inputs[split],dtype=np.int32);arrays[split+'_target_rows']=np.asarray(seq_targets[split],dtype=np.int32)
  np.savez_compressed(p/'daily_features/sequence_indices.npz',**arrays)
  sequence_stats[package]={split:len(v) for split,v in seq_targets.items()}
  matrix_stats[package]={'rows':len(X),'features':len(X.columns),'attack_host_days':int(meta.binary_label.sum()),'attack_fraction':float(meta.binary_label.mean()),'normal_hosts_throughout':int(meta.groupby('hostname').binary_label.max().eq(0).sum()),'class_counts':meta.scenario_label.value_counts().to_dict(),'unique_vectors':int(pd.util.hash_pandas_object(X,index=False).nunique())}
  dump(p/'simulation_manifest.json',{'synthetic':True,'generator_seed':seed,'package':package,'start_date':meta.date.min(),'end_date':meta.date.max(),'hosts':list(configs[package][2]),'classes':CLASSES,'campaigns':[c for c in campaigns if (c['split']=='challenge')==(package=='challenge_30_days')],'observation_frequency':'four six-hour interval summaries per host per day','timezone':'UTC','daily_feature_contract':'FEATURE_DICTIONARY.md supersedes source semantics for the explicitly generated synthetic concepts'})
  dump(p/'split_manifest.json',{'split_dates':{split:{'start':g.date.min(),'end':g.date.max(),'rows':len(g)} for split,g in meta.groupby('split')},'campaign_hosts':{split:sorted({c['hostname'] for c in campaigns if c['split']==split}) for split in meta.split.unique()},'normal_training':'Only consecutive fully non-injected eight-day windows are selected for RedRVFL normal training. Synthetic normal status does not label source RealTime benign.','history_policy':'Validation/test targets can use prior observed history; future targets never enter training. Challenge indices start after its first seven days; cross-package context is not automatically imported.'})
  write_docs(p,schemas,populated)
 dump(out/'source_provenance.json',{'primary_reference':'Dataset_Simulated_Harmonized','source_archive_checksums':provenance['archives'],'source_parameter_estimation':{'data':'Harmonized process-watcher pre-2026-10-10, excludes all seven injected hosts','interpretation':'Uninjected reference, not verified benign','process_count_median':process_median,'process_count_std':process_spread},'all_other_rates':'Explicit synthetic priors; not estimates of real population prevalence or normality. No source rows copied.','source_versions':'dataset_comparison source audits retained separately','generator_sha256':sha(Path(__file__)),'seed':seed,'python':platform.python_version(),'numpy':np.__version__,'pandas':pd.__version__})
 dump(out/'generation_summary.json',{'quality_counters':quality,'daily_matrices':matrix_stats,'sequence_counts':sequence_stats,'feed_rows':{pkg:{feed:rows_written[pkg,feed] for feed in schemas} for pkg in configs},'always_normal_development_hosts':180,'new_challenge_hosts':newhosts,'all_features_finite':bool(all(np.isfinite(np.asarray(allfeatures[p],float)).all() for p in configs))})
 shutil.copy2(__file__,out/'generate.py')
 dump(out/'generation_config.json',{'seed':seed,'development_days':60,'challenge_days':0,'hosts_per_package':216,'snapshots_per_day':4,'features':FEATURES})
 print('Generation complete:',out,flush=True)

def write_docs(p,schemas,populated):
 definitions={
 'successful_logons':'Daily successful authentication count; nonnegative integer.', 'failed_logons':'Daily failed authentication count; nonnegative integer.',
 'after_hours_logon_ratio':'After-hours successful events / successful events, zero if denominator zero.',
 'unique_pc_count':'Daily distinct accessed-PC count, bounded by successful logons.', 'pc_access_entropy':'Entropy in nats of a synthetic uniform PC-count distribution; zero without accessed PCs.',
 'interactive_duration_seconds':'Daily session duration, capped at 86400 seconds.', 'mean_session_duration_seconds':'Daily duration / successful logons, zero without logons.', 'weekend_activity':'1 on Saturday/Sunday if successful logons occur.',
 'usb_connect_count':'Daily connection events.', 'usb_disconnect_count':'Daily disconnection events; each synthetic connection ends in the same six-hour interval.', 'after_hours_usb_ratio':'After-hours connections / all connections.', 'distinct_usb_devices':'Daily distinct devices, bounded by connections.',
 'file_access_count':'Daily file-access event count.', 'unique_filename_count':'Distinct generated file categories accessed today.', 'new_filename_count':'Distinct categories not previously seen for this host, excluding prehistory.', 'file_delete_count':'Daily deletes, bounded by accesses.', 'file_access_entropy':'Shannon entropy of generated file event counts, nats.', 'protected_file_touch_count':'Daily protected-file touches; includes legitimate maintenance.',
 'http_request_count':'Daily event count from the synthetic event process, NOT the disputed source http_count.', 'unique_domain_count':'Distinct generated domains requested today.', 'new_domain_count':'Domains not in this host synthetic prehistory.', 'external_domain_ratio':'External requests / all requests.', 'domain_access_entropy':'Entropy of domain request frequencies, nats.', 'file_sharing_visit_count':'Daily sharing-site requests, bounded by requests.',
 'mean_process_count':'Mean of four process gauges, not summed.', 'peak_process_count':'Maximum process-count gauge; a capacity proxy, NOT reconstructed true process identity cardinality.', 'admin_process_count':'Maximum admin-process gauge.', 'temp_exec_count':'Maximum temp-executable count.',
 'bytes_sent':'Daily bytes-sent increments. Feed bytes_sent is cumulative; daily model value uses increments.', 'bytes_received':'Daily received-byte increments.', 'external_connection_count':'Daily external connections.', 'unique_remote_ip_count':'Generated daily distinct remote-address count bounded by external connections.',
 'clipboard_copy_count':'Daily copy events.', 'lsass_handle_request_count':'Daily simulated handle requests, including authorized maintenance.', 'memory_dump_attempt_count':'Daily simulated dump attempts, including authorized diagnostics; not proof of maliciousness.', 'decoy_access_count':'Daily canary accesses, including authorized testing.', 'wmi_query_count':'Daily WMI queries including legitimate administration.', 'named_pipe_event_count':'Daily pipe events.', 'dns_query_count':'Daily DNS query events.', 'outbound_attachment_count':'Daily attachment events.'}
 text=['# Generated daily feature contract','','This is a synthetic research contract. File headers match the reference archive, but generated semantics below are explicit and are not a claim of matching the live Rust collector. Four six-hour summaries per day are not five-second telemetry.','', '## Model matrix','','`daily_features/X.csv` has exactly the following 40 numeric features in this order. Timestamps, dates, day indices, row IDs, identities, campaign information and labels exist only in separate metadata. No label-encoded alert flags are populated. The sequence index archive selects rows; it is not itself an input feature.','', '| Feature | Definition |','|---|---|']
 for f in FEATURES:text.append(f'| `{f}` | {definitions[f]} |')
 text+=['','## Collector schema and unresolved fields','','The schema preserves all original column names/order. Unsupported flattened arrays, OS strings and ambiguous fields remain empty. Empty means not generated/unknown, not zero. Do not pass every raw feed column into an old impute-to-zero runner. Use the reviewed daily matrix. Some auxiliary channels (driver, keystroke) are deliberately simple fixtures, not validated realistic signals.','', 'The auth count/rate identity is count / 5 for a sampled five-minute subwindow. `auth_rate_3600s` is left unpopulated pending a separately generated true one-hour window. HTTP daily fields and entropy/ratio aliases are cumulative within UTC day; ambiguous source `http_count`, upload fields and url_access_count remain empty. Logon count and successful-logon count are cumulative daily aliases. USB and clipboard event counts are disjoint six-hour counts. Network byte counters are cumulative without reboot resets in this version. Some identity-based cardinalities are explicit approximations described above.','']
 for feed,cols in schemas.items():
  absent=[c for c in cols if c not in populated[feed]]
  text.append(f'- **{feed}**: unpopulated fields: '+(', '.join(f'`{c}`' for c in absent) if absent else 'none')+'.')
 (p/'FEATURE_DICTIONARY.md').write_text('\n'.join(text),encoding='utf-8')
 (p/'README.md').write_text('''# Synthetic InsiEDR research dataset

This package is generated, not observed 90/30-day telemetry. No real-time source record is assigned a verified benign label. It preserves the 20-feed file layout, with four aligned six-hour synthetic summaries per host per day and a separate 40-feature daily matrix.

Use `daily_features/X.csv` with `daily_features/metadata.csv` aligned by row order; do not use metadata as model features. Split-specific matrices and metadata are in `splits/`. The raw feed timestamps remain for chronology; the model matrix has no dates or identity columns. Read FEATURE_DICTIONARY.md before use.

Train IF on non-injected training rows only; train the six-output XGBoost classifier on BENIGN and the five primitive classes present in training. HONEYTOKEN_TRIP and KILL_CHAIN_APT are held-out scenarios for anomaly/composition evaluation, not supervised output classes learned in training. Preserve their eight-class truth labels for evaluation.

For RedRVFL, generate deployment-like scalar risk scores with chronological cross-fitting or a preceding upstream-training block, then use `sequence_indices.npz` to select seven risk observations and the next target. The indices point to rows of the package-wide X/metadata tables, not split-local tables. The training index set contains only fully non-injected eight-day windows. Do not train on target labels or in-sample upstream probabilities and call that independent validation.

Validation/test windows retain legitimate preceding context. The standalone challenge package deliberately omits context before its first day; its sequence targets begin on day eight. Known and previously unseen challenge hosts are marked in metadata. Do not mix the 90-day test or challenge rows into training or tune to their results.

Shared campaign mechanisms and overlapping windows mean rows are not independent. Sparse synthetic attacks, nonconstant baselines, host holdouts and leakage checks reduce some risks but cannot guarantee generalization or absence of overfitting. External observed evaluation and independent attack scenarios remain necessary. Synthetic signatures can still be easier than real attacks.

The current GitHub runner is not a drop-in consumer: its dates, sequence length, model schema, ranking and paths require changes. These 40 daily behavioral features are a new documented input contract; the diagram's IF-enriched 40-input schema was not supplied and cannot be claimed exactly reproduced.
''',encoding='utf-8')

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=ROOT/'generated_insiedr_v1');parser.add_argument('--seed',type=int,default=20261020)
 parser.add_argument('--daily-only',action='store_true')
 a=parser.parse_args();build(a.output.resolve(),a.seed,not a.daily_only)
