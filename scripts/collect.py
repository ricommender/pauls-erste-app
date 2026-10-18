#!/usr/bin/env python3
"""Fetch public security intelligence. No third-party packages or credentials."""
import datetime as dt, email.utils, json, re, urllib.request, xml.etree.ElementTree as ET
from pathlib import Path
UTC=dt.timezone.utc
NOW=dt.datetime.now(UTC)
UA={"User-Agent":"PaulsSecurityBriefing/1.0 (+https://github.com/ricommender/pauls-erste-app)","Accept":"application/json, application/xml, text/xml, application/rss+xml, */*"}
SOURCES=[
 ("CISA KEV","https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json","kev"),
 ("BleepingComputer","https://www.bleepingcomputer.com/feed/","rss"),
 ("The Hacker News","https://feeds.feedburner.com/TheHackersNews","rss"),
]
TECH={"Microsoft 365":[r"microsoft 365",r"office 365",r"exchange online",r"sharepoint online",r"teams"],"Windows":[r"windows",r"active directory",r"microsoft exchange",r"ntlm"],"Azure":[r"azure",r"entra id",r"microsoft cloud"],"Sophos":[r"sophos"],"VMware":[r"vmware",r"vcenter",r"esxi",r"broadcom"]}
def get(url):
 req=urllib.request.Request(url,headers=UA)
 with urllib.request.urlopen(req,timeout=30) as response:
  return response.read(8_000_000)
def match(text):
 t=text.lower()
 return [name for name,patterns in TECH.items() if any(re.search(p,t) for p in patterns)]
def timestamp(text):
 if not text:return NOW.isoformat()
 try:
  d=dt.datetime.fromisoformat(text.replace("Z","+00:00"))
  return (d.replace(tzinfo=UTC) if d.tzinfo is None else d).astimezone(UTC).isoformat()
 except ValueError:pass
 try:return email.utils.parsedate_to_datetime(text).astimezone(UTC).isoformat()
 except (ValueError,TypeError):return NOW.isoformat()
def clean(s):
 return re.sub(r"\s+"," ",re.sub(r"<[^>]*>"," ",s or "")).strip()[:700]
def classify(text):
 t=text.lower()
 if re.search(r"ransomware|trojan|malware|stealer|botnet",t):return "Malware"
 if re.search(r"breach|data leak|data theft|stolen data|compromis",t):return "Breaches"
 if re.search(r"cve-\d{4}-\d+|vulnerab|zero.day|patch|security update",t):return "Schwachstellen"
 if re.search(r"phishing|exploit|attack|bypass|social engineering",t):return "Angriffswege"
 return "News"
def severity(text,kev=False):
 t=text.lower()
 if kev or re.search(r"actively exploited|critical vulnerability|emergency patch|zero.day exploit",t):return "critical"
 if re.search(r"ransomware|breach|remote code execution|rce|exploited|zero.day|critical",t):return "high"
 if re.search(r"patch|vulnerab|phishing|malware|attack",t):return "medium"
 return "low"
items=[];sources=[]
for name,url,kind in SOURCES:
 ok=False
 try:
  raw=get(url)
  if kind=="kev":
   rows=json.loads(raw).get("vulnerabilities",[])
   for v in rows:
    added=v.get("dateAdded","")
    title=f"{v.get('cveID','CVE')}: {v.get('vendorProject','')} {v.get('product','')} – {v.get('vulnerabilityName','')}"
    body=clean(v.get("shortDescription",""))+" "+clean(v.get("requiredAction",""))
    tech=match(title+" "+body)
    if not tech:continue
    items.append({"title":title[:250],"summary":body[:500],"url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","source":name,"published":timestamp(added+"T12:00:00+00:00"),"category":"Schwachstellen","technologies":tech,"severity":"critical","kev":True,"cve":v.get("cveID"),"vendor":v.get("vendorProject")})
  else:
   root=ET.fromstring(raw)
   rows=root.findall(".//item")
   if not rows:rows=root.findall(".//{http://www.w3.org/2005/Atom}entry")
   for item in rows[:80]:
    def field(*names):
     for tag in names:
      e=item.find(tag)
      if e is not None:
       if e.text:return e.text
       if tag.endswith("link") and e.get("href"):return e.get("href")
     return ""
    title=clean(field("title","{http://www.w3.org/2005/Atom}title"))
    summary=clean(field("description","{http://www.w3.org/2005/Atom}summary","{http://www.w3.org/2005/Atom}content"))
    link=field("link","{http://www.w3.org/2005/Atom}link").strip()
    published=timestamp(field("pubDate","{http://www.w3.org/2005/Atom}published","{http://www.w3.org/2005/Atom}updated"))
    if not title or not link.startswith("https://"):continue
    combined=title+" "+summary
    items.append({"title":title[:250],"summary":summary[:500],"url":link,"source":name,"published":published,"category":classify(combined),"technologies":match(combined),"severity":severity(combined),"kev":False,"cve":(re.search(r"CVE-\d{4}-\d{4,}",combined,re.I) or [None])[0]})
  ok=True
 except Exception as exc:print(f"WARNING {name}: {type(exc).__name__}: {str(exc)[:150]}")
 sources.append({"name":name,"url":url,"ok":ok})
rank={"critical":4,"high":3,"medium":2,"low":1}
cutoff=NOW-dt.timedelta(days=45)
items=[i for i in items if dt.datetime.fromisoformat(i["published"])>=cutoff]
seen=set();out=[]
for i in sorted(items,key=lambda x:(rank[x["severity"]],bool(x["technologies"]),x["published"]),reverse=True):
 key=i.get("cve") or i["url"].split("?")[0]
 if key in seen:continue
 seen.add(key);out.append(i)
out=out[:220]
path=Path(__file__).resolve().parent.parent/"data.json"
path.write_text(json.dumps({"generated_at":NOW.isoformat(),"items":out,"sources":sources},ensure_ascii=False,indent=2)+"\n",encoding="utf8")
print(f"Saved {len(out)} records, {sum(x['ok'] for x in sources)} sources succeeded")
