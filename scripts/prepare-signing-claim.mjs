import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export function maskCommand(value) {
  return '::add-mask::'+value.replace(/%/g,'%25').replace(/\r/g,'%0D').replace(/\n/g,'%0A');
}
export async function prepareClaim(path='claim.json', directory='.', log=console.log) {
  let claim;
  try { claim=JSON.parse(await readFile(path,'utf8')); } catch { throw new Error('ECLAIM'); }
  for(const key of ['job_id','claim_token','source_ipa_url','p12_base64','p12_password','mobileprovision_base64']) {
    if(typeof claim[key]!=='string'||!claim[key])throw new Error('ECLAIM');
  }
  const source=new URL(claim.source_ipa_url);
  if(source.protocol!=='https:'||source.username||source.password)throw new Error('ECLAIM');
  const values=[claim.claim_token,claim.source_ipa_url,claim.p12_base64,claim.mobileprovision_base64,claim.upload_url,claim.signed_ipa_url,...Object.values(claim.upload_headers||{})];
  // Very short passwords (e.g. "1") never go to stdout. Registering them as
  // masks would erase unrelated status codes and timings from every log line.
  if(claim.p12_password.length>=4)values.push(claim.p12_password);
  const original=process.env.SOURCE_STORAGE_HOST,accelerated=process.env.SOURCE_ACCELERATED_HOST;
  if(original&&accelerated&&source.hostname===original){source.hostname=accelerated;values.push(source.href);}
  for(const value of new Set(values.filter(v=>typeof v==='string'&&v.length>=4)))log(maskCommand(value));
  for(const [name,value] of [['p12.b64',claim.p12_base64],['p12.password',claim.p12_password],['mobileprovision.b64',claim.mobileprovision_base64]])await writeFile(directory+'/'+name,value,{mode:0o600});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)prepareClaim(process.argv[2]).catch(()=>{console.error('Signing claim preparation failed');process.exitCode=1});
