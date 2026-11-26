#!/usr/bin/env python3
"""Educational, read-only folder triage toolkit. Does not collect live Windows logs."""
import argparse,csv,hashlib,json,os,pathlib,datetime
from collections import Counter

def iso(t): return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat()
def sha256(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def main():
 ap=argparse.ArgumentParser(description='Digital Forensics Investigation Toolkit (educational)')
 ap.add_argument('evidence',help='Folder containing evidence files')
 ap.add_argument('--events',help='Optional sample Windows Event Log export CSV: timestamp,event_id,description')
 ap.add_argument('--output',default='investigation_output')
 a=ap.parse_args(); root=pathlib.Path(a.evidence).resolve(); out=pathlib.Path(a.output).resolve()
 if not root.is_dir(): ap.error('Evidence directory does not exist')
 if out==root or root in out.parents: ap.error('Output must be outside evidence directory')
 out.mkdir(parents=True,exist_ok=True); files=[]; timeline=[]; errors=[]
 for folder,dirs,names in os.walk(root):
  dirs.sort()
  for name in sorted(names):
   p=pathlib.Path(folder)/name
   try:
    if p.is_symlink(): continue
    s=p.stat(); rel=str(p.relative_to(root)); ext=p.suffix.lower(); flag=ext in {'.exe','.bat','.ps1','.vbs','.js','.scr'}
    rec={'path':rel,'size_bytes':s.st_size,'extension':ext,'modified_utc':iso(s.st_mtime),'sha256':sha256(p),'review_flag':flag}
    files.append(rec);timeline.append({'timestamp':rec['modified_utc'],'source':'file metadata','description':'Modified: '+rel})
   except (OSError,PermissionError) as e: errors.append({'file':str(p),'error':str(e)})
 events=[]
 if a.events:
  try:
   with open(a.events,encoding='utf-8-sig',newline='') as f:
    for row in csv.DictReader(f):
     dt=datetime.datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
     if dt.tzinfo is None: dt=dt.replace(tzinfo=datetime.timezone.utc)
     event={'timestamp':dt.astimezone(datetime.timezone.utc).isoformat(),'event_id':row['event_id'],'description':row['description']}
     events.append(event);timeline.append({'timestamp':event['timestamp'],'source':'sample event CSV','description':f"Event {event['event_id']}: {event['description']}"})
  except (OSError,ValueError,KeyError) as e: errors.append({'events':a.events,'error':str(e)})
 timeline.sort(key=lambda x:x['timestamp']); report={'scope':str(root),'note':'Read-only folder analysis; event CSV is supplied sample/export data, not live Windows Event Log acquisition. Flags are leads, not malware verdicts.','files':files,'events':events,'timeline':timeline,'errors':errors,'summary':{'file_count':len(files),'flagged_count':sum(x['review_flag'] for x in files),'event_count':len(events)}}
 (out/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 with open(out/'timeline.csv','w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=['timestamp','source','description']);w.writeheader();w.writerows(timeline)
 print('DIGITAL FORENSICS INVESTIGATION TOOLKIT')
 print('Evidence folder:',root,'\nFiles analyzed:',len(files),'\nFiles flagged for review:',report['summary']['flagged_count'],'\nSample events:',len(events))
 for x in files: print(('REVIEW' if x['review_flag'] else 'FILE  '),x['path'],'SHA-256:',x['sha256'][:20]+'...')
 print('Report:',out/'report.json');print('Timeline:',out/'timeline.csv')
 if errors: print('Warnings:',len(errors),'(see report)')
if __name__=='__main__': main()
