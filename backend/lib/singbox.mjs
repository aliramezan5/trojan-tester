import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { resolvePublicHost } from './security.mjs';
import { probeHttpsThroughSocks, measureThroughputThroughSocks } from './socks-probe.mjs';

const SING_BOX_BIN=process.env.SING_BOX_BIN||'sing-box';
const TEST_HOST='www.cloudflare.com';
const TEST_PATH='/cdn-cgi/trace';

function tlsConfig(c){
  if(!c.tls)return undefined;
  const t={enabled:true,server_name:c.sni||c.address,insecure:Boolean(c.insecure)};
  if(c.alpn?.length)t.alpn=c.alpn;
  if(c.fingerprint)t.utls={enabled:true,fingerprint:c.fingerprint};
  if(c.reality){if(!c.publicKey)throw new Error('Reality public key missing');t.reality={enabled:true,public_key:c.publicKey,short_id:c.shortId||''}}
  return t;
}
function transportConfig(c){
  if(!c.transport||c.transport==='tcp'||c.transport==='quic')return undefined;
  if(c.transport==='ws')return {type:'ws',path:c.path||'/',headers:c.host?{Host:c.host}:undefined};
  if(c.transport==='http')return {type:'http',host:c.host?[c.host]:undefined,path:c.path||'/'};
  if(c.transport==='grpc')return {type:'grpc',service_name:c.serviceName||''};
  if(c.transport==='httpupgrade')return {type:'httpupgrade',host:c.host||undefined,path:c.path||'/'};
  throw new Error(`Transport ${c.transport} is not supported by this verifier`);
}
export function buildOutbound(c,serverIp){
  const common={tag:'proxy',server:serverIp,server_port:Number(c.port)};let o;
  if(c.protocol==='vless'){if(!c.uuid)throw new Error('VLESS UUID missing');o={type:'vless',...common,uuid:c.uuid,flow:c.flow||undefined,tls:tlsConfig(c),transport:transportConfig(c)}}
  else if(c.protocol==='trojan'){if(!c.password)throw new Error('Trojan password missing');o={type:'trojan',...common,password:c.password,tls:tlsConfig(c),transport:transportConfig(c)}}
  else if(c.protocol==='vmess'){if(!c.uuid)throw new Error('VMess UUID missing');o={type:'vmess',...common,uuid:c.uuid,security:c.vmessSecurity||'auto',alter_id:Number(c.alterId||0),tls:tlsConfig(c),transport:transportConfig(c)}}
  else if(c.protocol==='ss'){if(!c.method||!c.password)throw new Error('Shadowsocks credentials missing');if(c.plugin)throw new Error('Shadowsocks plugin configs are not supported by this verifier');o={type:'shadowsocks',...common,method:c.method,password:c.password}}
  else if(c.protocol==='hysteria2'){if(!c.password)throw new Error('Hysteria2 password missing');o={type:'hysteria2',...common,password:c.password,tls:tlsConfig(c)};if(c.obfs){if(c.obfs!=='salamander')throw new Error('Unsupported Hysteria2 obfs');o.obfs={type:'salamander',password:c.obfsPassword||''}}}
  else if(c.protocol==='tuic'){if(!c.uuid)throw new Error('TUIC UUID missing');o={type:'tuic',...common,uuid:c.uuid,password:c.password||'',congestion_control:c.congestionControl||'cubic',udp_relay_mode:c.udpRelayMode||'native',zero_rtt_handshake:Boolean(c.zeroRtt),tls:tlsConfig(c)}}
  else throw new Error(`Protocol ${c.protocol} unsupported`);
  return JSON.parse(JSON.stringify(o));
}

async function freePort(){return new Promise((resolve,reject)=>{const s=net.createServer();s.unref();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p))})})}
function waitPort(port,timeoutMs=5000){const until=Date.now()+timeoutMs;return new Promise((resolve,reject)=>{const tryIt=()=>{const s=net.connect({host:'127.0.0.1',port});s.once('connect',()=>{s.destroy();resolve()});s.once('error',()=>{s.destroy();if(Date.now()>until)reject(new Error('sing-box did not become ready'));else setTimeout(tryIt,80)})};tryIt()})}
function median(nums){if(!nums.length)return null;const a=[...nums].sort((x,y)=>x-y);const m=Math.floor(a.length/2);return a.length%2?a[m]:Math.round((a[m-1]+a[m])/2)}
function calcScore({attempts,successes,handshakeMs,ttfbMs,throughputMbps}){
  const connection=successes>0?35:0;const stability=20*(successes/Math.max(1,attempts));
  const latency=handshakeMs==null?0:15*Math.max(0,1-handshakeMs/2000);
  const ttfb=ttfbMs==null?0:10*Math.max(0,1-ttfbMs/3000);
  const speed=throughputMbps==null?0:15*Math.min(1,throughputMbps/20);
  const error=5*(successes/Math.max(1,attempts));return Math.round(Math.min(100,connection+stability+latency+ttfb+speed+error));
}

async function stopProcess(child){if(!child||child.exitCode!=null)return;child.kill('SIGTERM');await new Promise(r=>setTimeout(r,250));if(child.exitCode==null)child.kill('SIGKILL')}

export async function verifyConfig(c,{attempts=3,throughput=true,timeoutMs=8000}={}){
  const resolved=await resolvePublicHost(c.address);const chosen=resolved.find(x=>x.family===4)||resolved[0];const outbound=buildOutbound(c,chosen.address);const port=await freePort();
  const dir=await mkdtemp(join(tmpdir(),'tt-sb-'));const configPath=join(dir,'config.json');
  const config={log:{level:'warn',timestamp:false},inbounds:[{type:'socks',tag:'socks-in',listen:'127.0.0.1',listen_port:port}],outbounds:[outbound],route:{final:'proxy'}};
  await writeFile(configPath,JSON.stringify(config),{mode:0o600});let child;let stderr='';
  try{
    child=spawn(SING_BOX_BIN,['run','-c',configPath],{stdio:['ignore','ignore','pipe']});child.stderr.on('data',d=>{stderr=(stderr+d.toString()).slice(-2048)});await waitPort(port,5000);
    const rows=[];for(let i=0;i<attempts;i++){try{const r=await probeHttpsThroughSocks({socksPort:port,host:TEST_HOST,path:TEST_PATH,timeoutMs,maxBody:65536});const text=r.body.toString('utf8');const exitIp=(text.match(/^ip=(.+)$/m)||[])[1]?.trim()||null;rows.push({...r,ok:true,exitIp})}catch(e){rows.push({ok:false,error:e?.message||'probe failed'})}}
    const good=rows.filter(x=>x.ok);let speed=null;if(throughput&&good.length){try{speed=(await measureThroughputThroughSocks({socksPort:port,bytes:262144,timeoutMs:12000})).mbps}catch{}}
    const successes=good.length;const handshakeMs=median(good.map(x=>x.proxyHandshakeMs));const tlsMs=median(good.map(x=>x.tlsMs));const ttfbMs=median(good.map(x=>x.ttfbMs));const exitIp=good.find(x=>x.exitIp)?.exitIp||null;
    const score=calcScore({attempts,successes,handshakeMs,ttfbMs,throughputMbps:speed});const verified=successes>=Math.ceil(attempts*2/3);
    return {status:verified?'verified':'failed',latency:handshakeMs,score,reason:verified?'Proxy traffic verified':'Insufficient successful proxy attempts',probeType:'sing-box',testedAt:Date.now(),verification:{attempts,successes,successRate:successes/attempts,proxyHandshakeMs:handshakeMs,tlsMs,ttfbMs,throughputMbps:speed,exitIp}};
  }catch(e){
    const reason=/not become ready/i.test(e?.message||'')&&stderr?'sing-box config/start failed':(e?.message||'Verification failed');
    return {status:'failed',latency:null,score:0,reason,probeType:'sing-box',testedAt:Date.now(),verification:{attempts,successes:0,successRate:0,proxyHandshakeMs:null,tlsMs:null,ttfbMs:null,throughputMbps:null,exitIp:null}};
  }finally{await stopProcess(child);await rm(dir,{recursive:true,force:true})}
}

export async function getSingBoxVersion(){return new Promise(resolve=>{const c=spawn(SING_BOX_BIN,['version'],{stdio:['ignore','pipe','ignore']});let out='';const t=setTimeout(()=>{c.kill();resolve(null)},2500);c.stdout.on('data',d=>out+=d);c.on('close',()=>{clearTimeout(t);resolve((out.match(/sing-box version\s+([^\s]+)/i)||[])[1]||null)});c.on('error',()=>{clearTimeout(t);resolve(null)})})}
