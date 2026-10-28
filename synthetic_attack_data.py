"""Explicitly synthetic text-category fixtures, never mixed with real email data."""
import json
import uuid
import lab_core as core

PATTERNS = {
 'legitimate': [
  'The project meeting is scheduled for Tuesday. Please review the agenda.',
  'Your requested monthly report is ready in the usual internal workspace.',
  'Thank you for your support ticket. Our team will reply during business hours.',
  'The team lunch will be held next week. Let us know your food preference.',
  'The approved invoice is attached for accounting review at the regular meeting.',
  'Here are the notes from our planning session and the agreed schedule.',
  'Our office will close for the holiday. Normal service resumes Monday.',
  'Please confirm your attendance at the staff training session tomorrow.' ],
 'phishing': [
  'Urgent: your account is suspended. Verify your password at the supplied login page.',
  'Your mailbox will be deleted unless you confirm your credentials immediately.',
  'Security verification required: enter your banking password to restore access.',
  'A payment failed. Follow this link and submit your account login and card details.',
  'Your payroll access expires today. Validate your password through this login link.',
  'We detected unusual sign-in activity. Provide your account password and one-time code.',
  'Your account is locked. Visit the verification page and enter your credentials.',
  'Claim your refund now by signing into the attached account verification form.' ],
 'ransomware': [
  'Your files are encrypted. Pay the ransom to receive the decryption key.',
  'We locked your documents and backups. Send cryptocurrency to decrypt the files.',
  'Your data is encrypted and will remain inaccessible until you pay our ransom demand.',
  'A ransom payment is required to recover the encrypted company files.',
  'We encrypted your server. Purchase the decryptor before the ransom deadline.',
  'Pay for the decryption key or your locked backups and documents will be destroyed.',
  'Your business files are encrypted. Transfer the ransom within 48 hours for recovery.',
  'The encryption is complete. Only our paid decryption tool can restore your data.' ],
 'malware': [
  'Open this executable attachment and disable antivirus to install the urgent update.',
  'Run the attached installer. Ignore the security warning and enable execution.',
  'Enable document macros and run the downloaded payload to view your shipping notice.',
  'Install the attached program and turn off endpoint protection if it blocks the file.',
  'Execute the provided script to see the invoice. Allow the program through antivirus.',
  'The attachment requires macros. Enable active content and install its helper executable.',
  'Download and run this executable update after disabling your antivirus protection.',
  'Start the attachment installer and permit the script to execute despite the warning.' ]
}

def create_demo(user):
    ident=uuid.uuid4().hex; directory=core.ROOT/'data/processed'/ident; directory.mkdir(parents=True)
    train=[]; test=[]
    for label,patterns in PATTERNS.items():
        for group,text in enumerate(patterns):
            for variant in range(3):
                assignment='training' if group<6 else 'testing'
                record={field:'' for field in core.FIELDS}
                record.update(record_id=uuid.uuid4().hex,subject='Synthetic demonstration',body=text+f' Reference {variant+1}.',label=label,
                              source='Generated synthetic demonstration',source_type='synthetic',original_label=label,
                              collected_at=core.now(),origin=f'{label}_template_{group}',reviewed='false',split_assignment=assignment,
                              intended_use='demonstration',usage_notes='Synthetic category cues. No real message, incident or independent label. Template groups separated across partitions.')
                (train if assignment=='training' else test).append(record)
    core.write_csv(directory/'training_set.csv',train); core.write_csv(directory/'testing_set.csv',test)
    core.write_csv(directory/'synthetic_attack_dataset.csv',train+test)
    split=dict(id=ident,dataset=str((directory/'synthetic_attack_dataset.csv').relative_to(core.ROOT)).replace('\\','/'),
               train=str((directory/'training_set.csv').relative_to(core.ROOT)).replace('\\','/'),
               test=str((directory/'testing_set.csv').relative_to(core.ROOT)).replace('\\','/'),train_count=len(train),test_count=len(test),
               seed=42,ratio=.25,actual_test_ratio=.25,synthetic=True,classes={label:24 for label in PATTERNS},created_at=core.now(),
               split_method='First six template groups per class train; remaining two test. Variants stay together.')
    for key in ['dataset','train','test']: split[key+'_checksum']=core.checksum(core.artifact(split[key]))
    (directory/'split.json').write_text(json.dumps(split,indent=2))
    core.audit('create_synthetic_attack_demo',user,{'split':ident,'records':96,'classes':list(PATTERNS)})
    return split
