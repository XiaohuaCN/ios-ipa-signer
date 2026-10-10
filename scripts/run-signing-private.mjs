import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function runPrivateSigner({ command='bash',args=['scripts/sign-ipa.sh','input.ipa','signed.ipa'],env=process.env,log=console.log }={}) {
  return new Promise(resolve=>{
    const started=Date.now();let finished=false,buffer='';
    const child=spawn(command,args,{env,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});
    const onSignal=signal=>{try{process.platform==='win32'?child.kill(signal):process.kill(-child.pid,signal)}catch{}};
    const term=()=>onSignal('SIGTERM'),interrupt=()=>onSignal('SIGINT');
    process.on('SIGTERM',term);process.on('SIGINT',interrupt);
    const inspect=bytes=>{
      buffer=(buffer+bytes.toString('utf8')).slice(-8192);
      // No original signer line, application identity, file path or exception
      // is forwarded. Only fixed messages and bounded numeric timings pass.
      for(const [pattern,label] of [[/>>> Signed OK! \(([0-9]{1,6}(?:\.[0-9]{1,6})?)s,/,'Signing'],[/>>> Archive OK! .*?\(([0-9]{1,6}(?:\.[0-9]{1,6})?)s,/,'Archiving']]){
        const match=buffer.match(pattern);if(match){log(label+' completed in '+Number(match[1]).toFixed(3)+'s');buffer=buffer.slice(buffer.indexOf(match[0])+match[0].length);}
      }
    };
    child.stdout.on('data',inspect);child.stderr.on('data',inspect);
    const finish=code=>{if(finished)return;finished=true;process.removeListener('SIGTERM',term);process.removeListener('SIGINT',interrupt);log(code===0?'Signing completed successfully':'Signing failed (exit '+code+')');log('Signing step elapsed '+((Date.now()-started)/1000).toFixed(2)+'s');resolve(code)};
    child.on('error',()=>finish(1));child.on('close',(code,signal)=>finish(Number.isInteger(code)?code:signal==='SIGTERM'?143:signal==='SIGINT'?130:1));
  });
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)runPrivateSigner({args:['scripts/sign-ipa.sh',process.argv[2]||'input.ipa',process.argv[3]||'signed.ipa']}).then(code=>{process.exitCode=code});
