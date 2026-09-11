#!/usr/bin/env python3
import argparse, csv, html, json, os
from pathlib import Path
from collections import Counter, defaultdict

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def esc(x):
    return html.escape(str(x if x is not None else ""), quote=True)

def load_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default

def load_jsonl(path):
    out=[]
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try: out.append(json.loads(line))
                except Exception: pass
    except Exception:
        pass
    return out

def human_sev(s):
    return str(s or 'INFO').upper()

def overall_risk(findings):
    if not findings: return 'INFO'
    return max((human_sev(f.get('severity')) for f in findings), key=lambda x: SEV_RANK.get(x,0))

def classify_evidence(evidence):
    types = Counter(str(e.get('type','')) for e in evidence)
    sources = Counter(str(e.get('source','')) for e in evidence)
    hardening = [e for e in evidence if e.get('source')=='checksec' and e.get('type')=='binary_hardening']
    return types, sources, hardening

def supplementary_findings(evidence):
    """Create compact report-only observations from evidence classes.
    No raw values are copied into the report.
    """
    bytype=defaultdict(list)
    for e in evidence:
        t=str(e.get('type',''))
        if t and e.get('asset'):
            bytype[t].append(str(e.get('asset')))
    specs = [
        ('update','Firmware Update Mechanism','INFO','펌웨어 업데이트 또는 검증과 관련된 정적 흔적이 확인됨','업데이트 무결성·서명 검증이 실제로 강제되는지 추가 확인','업데이트 서명 검증과 무결성 검사를 릴리스 절차에 포함'),
        ('component','Embedded Component Information','INFO','주요 오픈소스/임베디드 구성요소 또는 버전 힌트가 확인됨','식별된 버전의 지원 상태와 알려진 취약점 여부 추가 확인','지원되는 최신 안정 버전 사용 및 구성요소 인벤토리 관리'),
        ('web_interface','Web / API Interface','INFO','Web/CGI/API 관리 인터페이스 관련 정적 흔적이 확인됨','인증·세션·입력 검증 로직에 대한 추가 확인','관리 인터페이스 접근통제 및 입력 검증 강화'),
        ('service','Network Service Indicator','INFO','원격 또는 네트워크 서비스 관련 실행파일/설정 흔적이 확인됨','실제 활성화 여부와 외부 노출 여부 추가 확인','불필요한 서비스 비활성화 및 최소 노출 원칙 적용'),
        ('crypto','Crypto / Key Material','INFO','암호화 알고리즘 또는 Key/Certificate 관련 정적 흔적이 확인됨','키 고유성·권한·실사용 서비스 및 알고리즘 용도 추가 확인','키 관리 정책 및 안전한 알고리즘 사용 여부 검토'),
        ('ssh','SSH Material','INFO','SSH 관련 Key/설정 흔적이 확인됨','장비별 고유 키 여부와 SSH 서비스 사용 정책 확인','불필요한 SSH 접근 제한 및 키 수명주기 관리'),
        ('credential','Credential Indicator','INFO','계정·비밀번호·인증정보 관련 후보가 확인됨','실제 고정 자격증명 여부와 사용 서비스 추가 확인','하드코딩 자격증명 제거 및 장비별 고유 자격증명 사용'),
        ('database','Database / Stored Data','INFO','DB 또는 저장 데이터 관련 파일 후보가 확인됨','민감정보 저장 여부 및 파일 권한 추가 확인','민감정보 최소 저장 및 접근권한 제한'),
    ]
    out=[]
    for typ,title,sev,result,extra,rem in specs:
        assets=sorted(set(bytype.get(typ,[])))
        if not assets: continue
        out.append({
            'kind':'supplementary','title':title,'severity':sev,'confidence':'LOW',
            'asset': assets[0] if len(assets)==1 else f"{assets[0]} 외 {len(assets)-1}개",
            'category':typ,'result':result,
            'basis':f"관련 경로 {len(assets)}개에서 해당 유형의 정적 탐지 결과 확인",
            'analysis':result,'additional_check':extra,'remediation':[rem],
            'locations':assets[:5],
        })
    return out

def build_findings(correlated, evidence):
    findings=[]
    for c in correlated.get('security_cases',[]) or []:
        findings.append({
            'kind':'security_case','source_id':c.get('id',''), 'title':c.get('title','Security Finding'),
            'severity':human_sev(c.get('severity')), 'confidence':c.get('confidence',''),
            'asset':c.get('asset','-'), 'category':c.get('category',''),
            'result':c.get('analysis','Static-analysis finding identified.'),
            'basis':'여러 정적 분석 관찰값의 상관분석을 통해 우선 검토 대상으로 분류됨',
            'analysis':c.get('analysis',''), 'additional_check':c.get('attack_scenario',''),
            'impact':c.get('potential_impact',[]) or [], 'remediation':c.get('remediation',[]) or [],
        })
    for s in correlated.get('systemic_findings',[]) or []:
        findings.append({
            'kind':'systemic','title':s.get('title','Systemic Finding'),
            'severity':human_sev(s.get('severity')), 'confidence':s.get('confidence',''),
            'asset':'Firmware-wide', 'category':'systemic_hardening',
            'result':s.get('analysis',''), 'basis':'다수 바이너리에서 반복되는 보호기법 패턴 확인',
            'analysis':s.get('analysis',''), 'additional_check':'빌드 정책 및 툴체인 설정을 확인',
            'impact':[], 'remediation':s.get('remediation',[]) or [],
        })
    findings += supplementary_findings(evidence)
    findings.sort(key=lambda f:(-SEV_RANK.get(human_sev(f.get('severity')),0), f.get('title','')))
    for i,f in enumerate(findings,1): f['id']=f"FW-{i:03d}"
    return findings

def owasp_mapping(evidence, findings):
    types=Counter(str(e.get('type','')) for e in evidence)
    cats=Counter(str(f.get('category','')) for f in findings)
    def has(*ts): return any(types.get(t,0)>0 for t in ts)
    def fids_for(*keywords):
        ids=[]
        for f in findings:
            blob=(f.get('category','')+' '+f.get('title','')).lower()
            if any(k.lower() in blob for k in keywords): ids.append(f['id'])
        return ', '.join(ids[:4]) if ids else '-'
    rows=[]
    rows.append(('I1','Weak, Guessable, or Hardcoded Passwords',
                 'Credential/Password 관련 정적 후보가 확인됨' if has('credential') or cats.get('credential_storage') else '직접 관련 증거가 제한적임',
                 fids_for('credential','password'), 'Evidence Found' if has('credential') or cats.get('credential_storage') else 'Limited'))
    rows.append(('I2','Insecure Network Services',
                 '네트워크/원격 서비스 실행파일 또는 설정 흔적이 확인됨' if has('service') else '서비스 관련 정적 증거가 제한적임',
                 fids_for('network_service','telnet','service'), 'Evidence Found' if has('service') else 'Limited'))
    rows.append(('I3','Insecure Ecosystem Interfaces',
                 'Web/CGI/API 인터페이스 관련 정적 흔적이 확인됨' if has('web_interface') else '인터페이스 보안을 정적 분석만으로 충분히 판단하기 어려움',
                 fids_for('web','interface'), 'Potential Evidence' if has('web_interface') else 'Limited'))
    rows.append(('I4','Lack of Secure Update Mechanisms',
                 'Firmware Update/검증 관련 정적 흔적이 확인됨' if has('update') else 'Secure Update 동작 여부를 현재 증거만으로 판단하기 어려움',
                 fids_for('update'), 'Partial Evidence' if has('update') else 'Limited'))
    rows.append(('I5','Use of Insecure or Outdated Components',
                 '구성요소 또는 버전 힌트가 확인됨' if has('component') else '구성요소 버전 정보가 제한적임',
                 fids_for('component','hardening'), 'Potential Evidence' if has('component') else 'Limited'))
    rows.append(('I6','Insufficient Privacy Protection',
                 'Credential/DB/민감정보 관련 저장 후보가 확인됨' if has('credential','database','sensitive_pattern') else '개인정보 처리 수준은 정적 펌웨어만으로 충분히 판단하기 어려움',
                 fids_for('credential','database'), 'Partial Evidence' if has('credential','database','sensitive_pattern') else 'Limited'))
    rows.append(('I7','Insecure Data Transfer and Storage',
                 'Crypto/SSH/Key Material 관련 정적 흔적이 확인됨' if has('crypto','ssh') else '전송·저장 보호 수준을 현재 증거만으로 충분히 판단하기 어려움',
                 fids_for('key','crypto','ssh'), 'Evidence Found' if has('crypto','ssh') else 'Limited'))
    rows.append(('I8','Lack of Device Management',
                 '원격관리/업데이트/SSH 관련 일부 관리 기능 흔적이 확인됨' if has('service','update','ssh') else '장치 수명주기 관리 수준은 정적 분석만으로 평가가 제한됨',
                 fids_for('service','update','ssh'), 'Partial Evidence' if has('service','update','ssh') else 'Limited'))
    rows.append(('I9','Insecure Default Settings',
                 'Credential 또는 서비스 기본 설정 검토 대상이 확인됨' if has('credential','service','config') else '기본 설정 안전성 판단을 위한 정적 증거가 제한적임',
                 fids_for('credential','service'), 'Potential Evidence' if has('credential','service','config') else 'Limited'))
    rows.append(('I10','Lack of Physical Hardening','펌웨어 파일 기반 정적 분석만으로 물리적 보호 수준을 판단하기 어려움','-','Not Assessed'))
    return [dict(code=a,category=b,summary=c,findings=d,status=e) for a,b,c,d,e in rows]

def cert_rows(findings):
    rows=[]; seen=set()
    for f in findings:
        cat=f.get('category','')
        if cat in seen: continue
        if 'credential' in cat:
            row=('Credential 관련 Finding','인증정보 악용 가능성','비인가 로그인·관리 인터페이스 접근 여부','인증 로그, 관리 인터페이스 접근 기록')
        elif 'key' in cat or cat in ('crypto','ssh'):
            row=('Key / Crypto 관련 Finding','키 유출·인증 재사용 가능성','장비별 고유 키 여부, 실제 사용 서비스','키/인증서 메타정보, TLS/SSH 설정')
        elif 'network_service' in cat or cat=='service':
            row=('Network Service 관련 Finding','원격 Attack Surface 증가 가능성','서비스 활성화·외부 노출·비인가 세션','서비스 설정, init 설정, 네트워크 로그')
        elif 'web' in cat:
            row=('Web Interface 관련 Finding','관리 인터페이스 악용 가능성','비인가 요청, 인증·세션 이상','웹/관리 인터페이스 로그')
        elif 'hardening' in cat:
            row=('Binary Hardening 관련 Finding','취약점 존재 시 악용 난이도에 영향','대상 ELF 우선 정적분석','ELF 메타정보, 디컴파일 결과')
        elif cat=='update':
            row=('Firmware Update 관련 Finding','비정상 펌웨어 배포·변조 위험 검토','업데이트 이력과 검증 실패 흔적','업데이트 로그, 서명/검증 설정')
        else: continue
        seen.add(cat); rows.append(row)
    return rows

def unique_remediations(findings):
    rows=[]; seen=set()
    for f in sorted(findings,key=lambda x:-SEV_RANK.get(human_sev(x.get('severity')),0)):
        sev=human_sev(f.get('severity'))
        for r in f.get('remediation',[]) or []:
            r=str(r).strip()
            if r and r not in seen:
                seen.add(r); rows.append((sev,r))
    return rows[:20]

def render(args):
    correlated=load_json(args.correlated, {'security_cases':[],'systemic_findings':[],'informational':[]})
    evidence=load_jsonl(args.evidence); assets=load_jsonl(args.assets)
    findings=build_findings(correlated,evidence)
    owasp=owasp_mapping(evidence,findings)
    cert=cert_rows(findings); rem=unique_remediations(findings)
    types,sources,hardening=classify_evidence(evidence)
    counts=Counter(human_sev(f.get('severity')) for f in findings)
    risk=overall_risk(findings)
    owasp_count=sum(1 for r in owasp if r['status'] not in ('Limited','Not Assessed'))
    target=Path(args.outdir).name
    rootfs_name=Path(args.rootfs.rstrip('/')).name or 'rootfs'

    safe_report={
      'tool':'IoT_fw_tool','target':target,
      'summary':{'overall_risk':risk,'critical':counts['CRITICAL'],'high':counts['HIGH'],'medium':counts['MEDIUM'],'low':counts['LOW'],'info':counts['INFO'],'findings':len(findings),'analyzed_elf':len(hardening),'owasp_evidence':owasp_count},
      'findings':findings,
      'owasp_iot_top10_mapping':owasp,
      'cert_dfir':[{'finding':a,'meaning':b,'check':c,'recommended_artifacts':d} for a,b,c,d in cert],
      'remediation':[{'priority':a,'recommendation':b} for a,b in rem],
      'limitations':[
        '본 보고서는 펌웨어 파일 기반 정적 점검 결과를 대상으로 한다.',
        'Raw Evidence는 최종 보고서와 report.json에 포함하지 않는다.',
        '자동 탐지 결과는 취약점 후보를 포함하므로 최종 판정에는 추가 검증이 필요하다.',
        'Checksec 결과는 보호기법 적용 상태이며 실제 취약 코드 존재를 직접 의미하지 않는다.',
        '구성요소 버전 힌트만으로 알려진 취약점 존재 여부를 확정하지 않는다.',
        'Firmware Update 관련 문자열만으로 Secure Update 동작의 안전성을 확정하지 않는다.',
        '실제 서비스 활성화·외부 노출·인증 우회 가능성은 동적 분석 또는 실제 장비 검증이 필요하다.',
        'OWASP I10 Physical Hardening은 펌웨어 정적 분석만으로 충분히 평가하기 어렵다.'
      ]
    }
    outdir=Path(args.outdir); outdir.mkdir(parents=True,exist_ok=True)
    (outdir/'report.json').write_text(json.dumps(safe_report,ensure_ascii=False,indent=2),encoding='utf-8')

    with open(outdir/'report.csv','w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f); w.writerow(['ID','Severity','Title','Location','Result','Additional Check'])
        for x in findings: w.writerow([x['id'],x['severity'],x['title'],x.get('asset','-'),x.get('result',''),x.get('additional_check','')])

    def td(x): return f'<td>{esc(x)}</td>'
    def code(x): return f'<code>{esc(x)}</code>'
    def badge(status):
        cls={'Evidence Found':'found','Potential Evidence':'potential','Partial Evidence':'partial','Limited':'limited','Not Assessed':'limited'}.get(status,'limited')
        return f'<span class="badge {cls}">{esc(status)}</span>'
    def metric(label,val,cls=''):
        return f'<div class="metric"><div class="label">{esc(label)}</div><div class="value {cls}">{esc(val)}</div></div>'

    css="""
:root{--bg:#f5f7fa;--card:#fff;--text:#1f2937;--muted:#667085;--line:#d9dee7;--head:#eef2f6;--critical:#8f1224;--high:#b42318;--med:#b54708;--low:#175cd3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,'Noto Sans KR','Malgun Gothic',sans-serif;line-height:1.55}.wrap{max-width:1120px;margin:28px auto;padding:0 14px}.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:14px}h1{font-size:27px;margin:0 0 8px}h2{font-size:21px;margin:30px 0 12px;border-bottom:2px solid #cfd5dd;padding-bottom:7px}h3{font-size:17px;margin:20px 0 9px}.muted{color:var(--muted);font-size:13px}table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:14px}th,td{border:1px solid var(--line);padding:9px 11px;text-align:left;vertical-align:top}th{background:var(--head)}code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace}.summary-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0 18px}.metric{border:1px solid var(--line);border-radius:10px;padding:13px;background:#fff}.metric .label{font-size:12px;color:#475467}.metric .value{font-size:23px;font-weight:700}.CRITICAL{color:var(--critical)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}.risk{font-weight:800}.note{background:#f8fafc;border-left:4px solid #94a3b8;padding:11px 13px;font-size:13px;margin:12px 0 18px}.finding{border:1px solid var(--line);border-left:5px solid #98a2b3;border-radius:7px;padding:15px 16px 4px;margin:15px 0 22px}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700}.found{background:#fee4e2;color:#912018}.potential{background:#fef0c7;color:#93370d}.partial{background:#e0f2fe;color:#075985}.limited{background:#eaecf0;color:#344054}ul{padding-left:20px}.footer{margin-top:35px;border-top:1px solid var(--line);padding-top:10px;color:var(--muted);font-size:12px}@media(max-width:900px){.summary-grid{grid-template-columns:repeat(3,1fr)}}@media print{body{background:#fff}.wrap{max-width:none;margin:0}.card{border:none;padding:0}.summary-grid{grid-template-columns:repeat(6,1fr)}table,.finding{break-inside:avoid}}
"""
    parts=[f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>IoT Firmware Security Assessment</title><style>{css}</style></head><body><div class="wrap">']
    parts.append('<div class="card"><h1>IoT Firmware Security Assessment</h1><div class="muted">Static firmware analysis · IoT_fw_tool · Preventive Security Checkup</div>')
    parts.append('<table style="margin-top:18px"><tr><th style="width:22%">구분</th><th>내용</th></tr>')
    for a,b in [('대상',target),('점검 방식','펌웨어 파일 기반 정적 보안 점검'),('분석 도구','IoT_fw_tool'),('기반 모듈','binwalk / firmwalker-lite / checksec-lite'),('분석 범위','Firmware 구조, 주요 설정·서비스·Web/API·Update·Component·Crypto/Key, 주요 ELF Hardening'),('출력','HTML / JSON / CSV')]:
        parts.append(f'<tr>{td(a)}{td(b)}</tr>')
    parts.append('</table>')
    parts.append('<h2>1. 요약</h2>')
    parts.append(f'<p>Overall Risk: <span class="risk {esc(risk)}">{esc(risk)}</span></p><p class="muted">주요 설정, 원격 서비스, Key/Certificate, Firmware Update, Component 정보와 주요 ELF 보호기법을 대상으로 예방적 정적 점검을 수행하였다. 자동 탐지 결과는 추가 검증이 필요한 보안 점검 후보를 포함한다.</p>')
    parts.append('<div class="summary-grid">'+metric('Critical',counts['CRITICAL'],'CRITICAL')+metric('High',counts['HIGH'],'HIGH')+metric('Medium',counts['MEDIUM'],'MEDIUM')+metric('Findings',len(findings))+metric('Analyzed ELF',len(hardening))+metric('OWASP Evidence',owasp_count)+'</div>')
    parts.append('<div class="note">Raw Evidence는 보고서에 포함하지 않는다. 전체 grep/strings 출력, 원문 자격증명 값, Private Key 본문 및 raw JSONL/TSV는 최종 보고서에 표시하지 않는다.</div></div>')

    parts.append('<div class="card"><h2>2. 점검 개요</h2><table><tr><th>항목</th><th>내용</th></tr>')
    for a,b in [('점검 대상',target),('수행 환경','Linux'),('분석 방식','Static Firmware Analysis'),('RootFS 식별명',rootfs_name),('점검 목적','배포 전 주요 위험 요소 및 보안 설정 상태를 빠르게 확인하기 위한 예방적 점검')]: parts.append(f'<tr>{td(a)}{td(b)}</tr>')
    parts.append('</table><h2>3. 대상 기기 및 펌웨어 정보</h2><table><tr><th>항목</th><th>내용</th></tr>')
    for a,b in [('분석 대상',target),('RootFS',rootfs_name),('추출 상태','SUCCESS'),('분석 자산 수',len(assets)),('주요 ELF 분석 대상',len(hardening))]: parts.append(f'<tr>{td(a)}{td(b)}</tr>')
    parts.append('</table>')

    parts.append('<h2>4. 점검 항목 매핑</h2><table><tr><th>점검 영역</th><th>주요 점검 항목</th><th>확인 정보</th><th>도구</th></tr>')
    mapping=[('Firmware Structure','File system / compression / extraction','펌웨어 구조 및 추출 가능 여부','binwalk'),('Credential','Password / secret / token / account','하드코딩 인증정보 후보','firmwalker-lite'),('Network Service','Telnet / FTP / SSH / HTTP / UPnP','서비스·설정·시작 흔적','firmwalker-lite'),('Web Interface','CGI / API / login / session','Web 관리 인터페이스 흔적','firmwalker-lite'),('Firmware Update','upgrade / verify / signature / checksum','업데이트·검증 관련 흔적','firmwalker-lite'),('Component','BusyBox / OpenSSL / Dropbear 등','구성요소 및 version hint','firmwalker-lite'),('Crypto / Key','Legacy/modern crypto / certificate / key','암호화 및 Key Material 후보','firmwalker-lite'),('Binary Hardening','RELRO / Canary / NX / PIE / Fortify / Separate Code / CFI / Stack Clash','주요 ELF 보호기법 상태','checksec-lite')]
    for r in mapping: parts.append('<tr>'+''.join(td(x) for x in r)+'</tr>')
    parts.append('</table><h2>5. 위험도 등급 기준</h2><table><tr><th>등급</th><th>기준</th></tr>')
    levels=[('Critical','즉시 대응이 필요한 매우 높은 위험'),('High','실제 악용 가능성과 직접 연결될 수 있어 우선 검증이 필요한 항목'),('Medium','추가 조건이 필요하지만 공격 표면 또는 악용 난이도에 영향을 줄 수 있는 항목'),('Low','즉각적인 악용 가능성은 낮지만 개선이 필요한 항목'),('Info','보안 상태 및 추가 분석 우선순위를 판단하기 위한 정보')]
    for a,b in levels: parts.append(f'<tr>{td(a)}{td(b)}</tr>')
    parts.append('</table>')

    parts.append('<h2>6. 진단 결과 요약</h2><table><tr><th>ID</th><th>점검 항목</th><th>진단 결과</th><th>위험도</th><th>위치</th></tr>')
    for f in findings: parts.append(f'<tr>{td(f["id"])}{td(f["title"])}{td(f.get("result",""))}<td class="{esc(f["severity"])}">{esc(f["severity"].title())}</td><td>{code(f.get("asset","-"))}</td></tr>')
    if not findings: parts.append('<tr><td colspan="5">보고 임계치를 충족한 Finding이 없습니다.</td></tr>')
    parts.append('</table><h2>7. 진단 상세</h2><p class="muted">Raw Evidence 원문은 삽입하지 않으며, 위치·탐지 결과·확인 근거·보안 영향·추가 확인·조치 방안을 요약하여 제공한다.</p>')
    for f in findings:
        cls='high' if f['severity'] in ('CRITICAL','HIGH') else ('medium' if f['severity']=='MEDIUM' else '')
        parts.append(f'<section class="finding {cls}"><h3>{esc(f["id"])} · {esc(f["title"])} [{esc(f["severity"].title())}]</h3><table>')
        rows=[('위치',f.get('asset','-')),('점검 결과',f.get('result','')),('확인 근거 요약',f.get('basis','')),('보안 영향', '; '.join(f.get('impact',[]) or []) or f.get('analysis','')),('추가 확인',f.get('additional_check','')),('조치 방안','; '.join(f.get('remediation',[]) or []))]
        for a,b in rows: parts.append(f'<tr><th style="width:22%">{esc(a)}</th><td>{esc(b)}</td></tr>')
        parts.append('</table></section>')

    parts.append('<h2>8. CERT / DFIR 활용 관점</h2><table><tr><th>Finding</th><th>위협대응 의미</th><th>사고 발생 시 확인사항</th><th>권장 증적</th></tr>')
    for r in cert: parts.append('<tr>'+''.join(td(x) for x in r)+'</tr>')
    if not cert: parts.append('<tr><td colspan="4">현재 Finding에서 별도 CERT/DFIR 매핑 항목이 생성되지 않았습니다.</td></tr>')
    parts.append('</table><div class="note">정상 펌웨어에 존재하는 서비스·설정·Key 파일은 그 자체로 IOC가 아니다. 실제 침해 판단에는 정상 기준선, 서비스 상태, 인증·네트워크 로그 등 추가 증거가 필요하다.</div>')

    parts.append('<h2>9. OWASP IoT Top 10 증거 매핑</h2><p class="muted">OWASP 위반 여부를 자동 확정하는 표가 아니라, 정적 점검에서 확인된 결과가 각 위험 항목과 어떤 관련성을 가지는지 요약한다.</p><table><tr><th>OWASP</th><th>Category</th><th>확인된 증거 요약</th><th>관련 Finding</th><th>상태</th></tr>')
    for r in owasp: parts.append(f'<tr>{td(r["code"])}{td(r["category"])}{td(r["summary"])}{td(r["findings"])}<td>{badge(r["status"])}</td></tr>')
    parts.append('</table><h3>상태 기준</h3><table><tr><th>상태</th><th>의미</th></tr>')
    statusdefs=[('Evidence Found','현재 Finding/탐지 결과가 해당 항목과 비교적 직접적으로 연결됨'),('Potential Evidence','관련 흔적은 확인되었으나 취약 여부 판단에는 추가 검증이 필요함'),('Partial Evidence','정적 분석에서 일부 증거만 확인 가능함'),('Limited / Not Assessed','현재 도구와 정적 분석만으로 충분한 평가가 어려움')]
    for a,b in statusdefs: parts.append(f'<tr>{td(a)}{td(b)}</tr>')
    parts.append('</table>')

    parts.append('<h2>10. 종합 조치 방안</h2><table><tr><th>우선순위</th><th>권고사항</th></tr>')
    for a,b in rem: parts.append(f'<tr>{td(a.title())}{td(b)}</tr>')
    if not rem: parts.append('<tr><td>Info</td><td>현재 보고 결과에 따른 별도 조치 항목이 없습니다.</td></tr>')
    parts.append('</table><h2>11. 점검 범위 및 유의사항</h2><ul>')
    for x in safe_report['limitations']: parts.append(f'<li>{esc(x)}</li>')
    parts.append('</ul><div class="footer">IoT_fw_tool · Firmware Security Checkup Report</div></div></div></body></html>')
    (outdir/'report.html').write_text(''.join(parts),encoding='utf-8')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('rootfs'); p.add_argument('correlated'); p.add_argument('evidence'); p.add_argument('assets'); p.add_argument('outdir')
    render(p.parse_args())
