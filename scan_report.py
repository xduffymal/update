"""Escaped, paginated static reports with complete saved evidence."""
import json
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

def build_pdf(buffer,result):
    styles=getSampleStyleSheet(); font=Path('C:/Windows/Fonts/arial.ttf')
    if font.exists():
        if 'ReportArial' not in pdfmetrics.getRegisteredFontNames(): pdfmetrics.registerFont(TTFont('ReportArial',str(font)))
        for style in styles.byName.values(): style.fontName='ReportArial'
    styles['BodyText'].splitLongWords=1; styles['BodyText'].leading=14
    story=[]
    def paragraph(value,style='BodyText'):
        story.append(Paragraph(escape(str(value)).replace('\n','<br/>'),styles[style])); story.append(Spacer(1,7))
    paragraph('NLP THREAT INTELLIGENCE · Email analysis report','Title')
    for line in [result['id'],result['created_at'],result['email'].get('subject',''),f"Classification: {result['classification']} | Combined risk: {result['risk_score']}/100",f"Email model: {result['email_model']['prediction']} | Confidence: {result['email_model']['confidence']}",f"Model version: {result['email_model'].get('version','Unavailable')}",f"Rule score: {result['rule_score']}/100",result['recommendation']]: paragraph(line)
    for title,value in [('Rule findings',result['rule_findings']),('URL predictions and evidence',result['urls']),('Attachment inspection',result['email']['attachments']),('Entities',result.get('entities',{})),('Local correlation',result.get('correlation',{})),('Supplied email headers',result['email'].get('headers',{}))]:
        paragraph(title,'Heading2'); paragraph(json.dumps(value,ensure_ascii=False,indent=2))
    paragraph('Model confidence is separate from combined risk. Static attachment inspection does not confirm malware. Supplied authentication headers are not independently verified.')
    def footer(canvas,doc):
        canvas.setFont('Helvetica',8); canvas.drawString(45,28,'Local capstone analysis · saved evidence'); canvas.drawRightString(550,28,f'Page {doc.page}')
    SimpleDocTemplate(buffer,rightMargin=45,leftMargin=45,topMargin=42,bottomMargin=45).build(story,onFirstPage=footer,onLaterPages=footer)
