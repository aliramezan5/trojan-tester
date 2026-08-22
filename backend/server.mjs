import http from 'node:http';
import { parseProxyUri } from './lib/parser.mjs';
import { clientIp, createRateLimiter, constantTimeTokenOk, resolvePublicHost } from './lib/security.mjs';
import { fetchSubscriptionText } from './lib/subscription.mjs';
import { getSingBoxVersion, verifyConfig } from './lib/singbox.mjs';

const PORT=Number(process.env.PORT||8787);const HOST=process.env.HOST||'0.0.0.0';const API_TOKEN=process.env.TT_API_TOKEN||'';
const ALLOWED_ORIGINS=(process.env.TT_ALLOWED_ORIGINS||'https://aliramezan5.github.io,http://localhost:8080,http://127.0.0.1:8080').split(',').map(x=>x.trim()).filter(Boolean);
const MAX_BATCH=Math.max(1,Math.min(50,Number(process.env.TT_MAX_BATCH||20)));const VERIFY_CONCURRENCY=Math.max(1,Math.min(8,Number(process.env.TT_VERIFY_CONCURRENCY||4)));
const limit=createRateLimiter({windowMs:60_000,max:Number(process.env.TT_RATE_LIMIT||12)});

function cors(req,res){const origin=req.headers.origin;if(origin&&ALLOWED_ORIGINS.includes(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin')}res.setHeader('Access-Control-Allow-Headers','Authorization, Content-Type');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Cache-Control','no-store')}
function json(res,status,data){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(data))}
function authorized(req){const h=String(req.headers.authorization||'');const provided=h.startsWith('Bearer ')?h.slice(7):'';return constantTimeTokenOk(provided,API_TOKEN)}
async function bodyJson(req){const max=256*1024;let size=0;const chunks=[];for await(const d of req){size+=d.length;if(size>max)throw Object.assign(new Error('Request too large'),{status:413});chunks.push(d)}try{return JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}')}catch{throw Object.assign(new Error('Invalid JSON'),{status:400})}}
async function mapPool(items,worker,concurrency){let next=0;const out=new Array(items.length);await Promise.all(Array.from({length:Math.min(concurrency,items.length)},async()=>{while(true){const i=next++;if(i>=items.length)return;out[i]=await worker(items[i],i)}}));return out}

const server=http.createServer(async(req,res)=>{
  cors(req,res);if(req.method==='OPTIONS'){res.statusCode=204;return res.end()}
  const url=new URL(req.url||'/',`http://${req.headers.host||'localhost'}`);
  if(url.pathname==='/health'&&req.method==='GET'){
    const version=await getSingBoxVersion();return json(res,version?200:503,{ok:Boolean(version),service:'trojan-tester-backend',singBoxVersion:version,maxBatch:MAX_BATCH});
  }
  if(!url.pathname.startsWith('/api/'))return json(res,404,{error:'Not found'});
  if(!authorized(req))return json(res,401,{error:'Unauthorized'});
  const rl=limit(clientIp(req));if(!rl.ok){res.setHeader('Retry-After',String(Math.ceil(rl.retryAfterMs/1000)));return json(res,429,{error:'Rate limit exceeded'})}
  try{
    if(url.pathname==='/api/subscription'&&req.method==='GET'){
      const target=url.searchParams.get('url');if(!target) return json(res,400,{error:'url is required'});
      const text=await fetchSubscriptionText(target);res.statusCode=200;res.setHeader('Content-Type','text/plain; charset=utf-8');return res.end(text);
    }
    if(url.pathname==='/api/verify'&&req.method==='POST'){
      const b=await bodyJson(req);if(!Array.isArray(b.configs)||!b.configs.length)return json(res,400,{error:'configs must be a non-empty array'});if(b.configs.length>MAX_BATCH)return json(res,400,{error:`Maximum ${MAX_BATCH} configs per request`});
      const attempts=Math.max(1,Math.min(5,Number(b.attempts||3)));const throughput=b.throughput!==false;
      const parsed=[];for(const item of b.configs){if(!item||typeof item.raw!=='string'||item.raw.length>8192){parsed.push({item,error:'Invalid config'});continue}const cfg=parseProxyUri(item.raw);if(!cfg){parsed.push({item,error:'Unsupported or malformed config'});continue}try{await resolvePublicHost(cfg.address);parsed.push({item,cfg})}catch(e){parsed.push({item,error:e.message})}}
      const results=await mapPool(parsed,async entry=>{
        if(entry.error)return {fingerprintId:entry.item?.fingerprintId||'',status:'failed',latency:null,score:0,reason:entry.error,probeType:'sing-box',testedAt:Date.now(),verification:null};
        const r=await verifyConfig(entry.cfg,{attempts,throughput});return {fingerprintId:entry.item.fingerprintId||'',...r};
      },VERIFY_CONCURRENCY);
      return json(res,200,{results});
    }
    return json(res,404,{error:'Not found'});
  }catch(e){return json(res,e.status||400,{error:e?.message||'Request failed'})}
});
server.requestTimeout=30_000;server.headersTimeout=10_000;server.keepAliveTimeout=5_000;
server.listen(PORT,HOST,()=>console.log(`trojan-tester backend listening on ${HOST}:${PORT}`));
