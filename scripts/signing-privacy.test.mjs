import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,readFile,stat,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { prepareClaim,maskCommand } from './prepare-signing-claim.mjs';
import { runPrivateSigner } from './run-signing-private.mjs';
test('claim materials are individually masked and private files preserve values',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'privacy-claim-'));try{
    const claim={job_id:'job',claim_token:'claim-secret',source_ipa_url:'https://files.example/source.ipa',p12_base64:Buffer.from('mock-key').toString('base64'),p12_password:'safe-password',mobileprovision_base64:Buffer.from('mock-profile').toString('base64'),upload_headers:{Authorization:'upload-secret'}};
    const path=join(dir,'claim.json');await writeFile(path,JSON.stringify(claim));const logs=[];
    await prepareClaim(path,dir,line=>logs.push(line));
    assert.ok(logs.every(l=>l.startsWith('::add-mask::')));for(const key of ['claim_token','source_ipa_url','p12_base64','p12_password','mobileprovision_base64'])assert.ok(logs.includes(maskCommand(claim[key])));
    assert.equal(await readFile(join(dir,'p12.password'),'utf8'),claim.p12_password);assert.equal((await stat(join(dir,'p12.password'))).mode&0o777,0o600);
    claim.p12_password='1';await writeFile(path,JSON.stringify(claim));const short=[];await prepareClaim(path,dir,l=>short.push(l));assert.ok(!short.includes('::add-mask::1'));assert.equal(await readFile(join(dir,'p12.password'),'utf8'),'1');
  }finally{await rm(dir,{recursive:true,force:true})}
});
test('workflow mask data is escaped rather than interpreted as a command',()=>assert.equal(maskCommand('secret%\r\n::warning::data'),'::add-mask::secret%25%0D%0A::warning::data'));
test('malformed claims emit no original response or exception details',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'privacy-bad-'));try{const file=join(dir,'claim.json');await writeFile(file,'secret-token invalid JSON');const logs=[];await assert.rejects(prepareClaim(file,dir,l=>logs.push(l)),/ECLAIM/);assert.deepEqual(logs,[])}finally{await rm(dir,{recursive:true,force:true})}
});
test('signer output suppresses identities, secrets and forged workflow commands',async()=>{
  const logs=[];
  const text='>>> AppName: private-app\n>>> SubjectCN: private-owner\n>>> TeamId: PRIVATE_TEAM\npassword=secret-password\n::warning::leaked-key\n>>> Signed OK! (1.234s, 1234000us)\n>>> Archive OK! (20 MB) (2.345s, 2345000us)\n';
  const code=await runPrivateSigner({command:process.execPath,args:['-e','process.stdout.write('+JSON.stringify(text)+');process.stderr.write("private-error")'],log:l=>logs.push(l)});
  assert.equal(code,0);assert.ok(logs.includes('Signing completed in 1.234s'));assert.ok(logs.includes('Archiving completed in 2.345s'));assert.ok(!/private|secret|PRIVATE_TEAM|::warning/.test(logs.join('\n')));
});
test('failed signer keeps exit status without printing its raw error',async()=>{
  const logs=[];const code=await runPrivateSigner({command:process.execPath,args:['-e','console.error("secret-certificate and signed URL");process.exit(7)'],log:l=>logs.push(l)});assert.equal(code,7);assert.ok(logs.includes('Signing failed (exit 7)'));assert.ok(!logs.join('\n').includes('secret-certificate'));
});
