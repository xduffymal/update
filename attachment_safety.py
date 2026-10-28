"""Bounded static inspection; no attachment is executed or extracted to disk."""
import hashlib
import io
import mimetypes
import re
import zipfile
from pathlib import Path,PurePosixPath

ALLOWED={'.pdf','.docx','.xlsx','.txt','.csv','.zip','.png','.jpg','.jpeg','.gif','.docm','.xlsm','.pptm','.js','.ps1','.bat','.cmd','.vbs','.exe','.scr','.com','.msi','.7z','.rar'}

def inspect(name,content,mime='application/octet-stream'):
    ext=Path(name).suffix.lower(); findings=[]; text=''; details={}
    if ext not in ALLOWED: findings.append('Unsupported format; manual review required')
    if ext in {'.exe','.com','.bat','.cmd','.ps1','.js','.vbs','.scr','.msi'}: findings.append('Executable or script: malware risk')
    if ext in {'.docm','.xlsm','.pptm'}: findings.append('Macro-enabled document')
    if re.search(r'\.(pdf|docx|txt|jpg|xlsx)\.',name,re.I): findings.append('Double extension')
    if re.search(r'password|urgent|invoice|payment',name,re.I): details['sensitive_filename']=True
    signatures={'.pdf':b'%PDF','.docx':b'PK','.xlsx':b'PK','.zip':b'PK','.png':b'\x89PNG','.jpg':b'\xff\xd8','.jpeg':b'\xff\xd8','.gif':b'GIF','.exe':b'MZ'}
    if ext in signatures and not content.startswith(signatures[ext]): findings.append('Extension and file signature mismatch')
    expected=mimetypes.guess_type(name)[0]
    if expected and mime not in {'application/octet-stream',expected} and not (ext in {'.docx','.xlsx','.zip'} and mime=='application/zip'):
        findings.append('Extension and declared MIME type mismatch')
    if ext in {'.txt','.csv'}: text=content[:2*1024*1024].decode('utf-8-sig','replace')
    if ext=='.pdf' and content.startswith(b'%PDF'):
        try:
            from pypdf import PdfReader
            reader=PdfReader(io.BytesIO(content),strict=False)
            if reader.is_encrypted: findings.append('Password-protected PDF; content unreadable')
            else: text='\n'.join((p.extract_text() or '')[:50000] for p in list(reader.pages)[:20])[:250000]
        except Exception: findings.append('Unreadable PDF; manual review required')
    if ext in {'.zip','.docx','.xlsx','.docm','.xlsm','.pptm'} and content.startswith(b'PK'):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                entries=archive.infolist(); details['archive_entries']=len(entries)
                size=sum(e.file_size for e in entries); details['expanded_bytes']=size
                unsafe=len(entries)>200 or size>32*1024*1024 or any(e.file_size>4*1024*1024 or (e.file_size/max(1,e.compress_size)>200) for e in entries)
                encrypted=any(e.flag_bits&1 for e in entries)
                if encrypted: findings.append('Password-protected archive or document')
                if any('..' in PurePosixPath(e.filename.replace('\\','/')).parts or e.filename.startswith(('/','\\')) or re.match(r'^[A-Za-z]:',e.filename) for e in entries): findings.append('Archive contains unsafe paths')
                if unsafe: findings.append('Archive expansion limits exceeded; content not inspected')
                if any(e.filename.lower().endswith('vbaproject.bin') for e in entries): findings.append('Embedded Office macro project')
                dangerous=[e.filename for e in entries if Path(e.filename).suffix.lower() in {'.exe','.bat','.cmd','.ps1','.js','.vbs','.scr'}]
                if dangerous: findings.append('Archive contains executable/script entries'); details['dangerous_entries']=dangerous[:20]
                if ext=='.zip': findings.append('Archive requires caution; contents never executed')
                if not unsafe and not encrypted:
                    from defusedxml import ElementTree
                    pieces=[]
                    for entry in entries:
                        if entry.filename in {'word/document.xml','xl/sharedStrings.xml'} or entry.filename.startswith('xl/worksheets/') and entry.filename.endswith('.xml'):
                            try: pieces.extend(ElementTree.fromstring(archive.read(entry)).itertext())
                            except Exception: findings.append('Unreadable document XML')
                        elif ext=='.zip' and Path(entry.filename).suffix.lower() in {'.txt','.csv'}:
                            pieces.append(archive.read(entry).decode('utf-8','replace'))
                    text=' '.join(pieces)[:250000]
        except Exception: findings.append('Unreadable archive/document')
    if ext in {'.rar','.7z'}: findings.append('Archive format requires manual inspection')
    urls=sorted(set(u.rstrip('.,;)>]') for u in re.findall(r'https?://[^\s<>"\x27]+',text)))
    return {'name':Path(name).name,'extension':ext,'mime':mime,'size':len(content),'sha256':hashlib.sha256(content).hexdigest(),'findings':list(dict.fromkeys(findings)),'urls':urls,'details':details,'text_excerpt':text[:2000]}
