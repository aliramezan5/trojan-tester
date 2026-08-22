import dns from 'node:dns/promises';
import net from 'node:net';
import { timingSafeEqual } from 'node:crypto';
function ipv4ToInt(ip){return ip.split('.').reduce((n,x)=>((n<<8)+Number(x))>>>0,0)>>>0}
function in4(ip,cidr,bits){const a=ipv4ToInt(ip),b=ipv4ToInt(cidr),mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return(a&mask)===(b&mask)}
const BLOCK_V4=[['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]];
export function isBlockedIp(ip){const family=net.isIP(ip);if(!family)return true;if(family===4)return BLOCK_V4.some(([n,b])=>in4(ip,n,b));const x=ip.toLowerCase();if(x.startsWith('::ffff:')){const mapped=x.slice(7);if(net.isIP(mapped)===4)return isBlockedIp(mapped)}return x==='::'||x==='::1'||/^fe[89ab]/.test(x)||x.startsWith('fc')||x.startsWith('fd')||x.startsWith('ff')||x.startsWith('2001:db8:')}
export async function resolvePublicHost(host){if(!host||host.length>253)throw new Error('Invalid host');if(net.isIP(host)){if(isBlockedIp(host))throw new Error('Private/reserved address blocked');return[{address:host,family:net.isIP(host)}]}const rows=await dns.lookup(host,{all:true,verbatim:true});if(!rows.length)throw new Error('DNS returned no addresses');if(rows.some(r=>isBlockedIp(r.address)))throw new Error('Host resolves to private/reserved address');return rows}
export async function validateHttpsUrl(raw){let u;try{u=new URL(raw)}catch{throw new Error('Invalid URL')}if(u.protocol!=='https:')throw new Error('Only HTTPS subscriptions are allowed');if(u.username||u.password)throw new Error('Credentials in URL are not allowed');if(u.port&&u.port!=='443')throw new Error('Only HTTPS port 443 is allowed');await resolvePublicHost(u.hostname);return u}
export function createRateLimiter({windowMs=60_000,max=10}={}){const buckets=new Map();return key=>{const now=Date.now();let b=buckets.get(key);if(!b||now-b.start>=windowMs){b={start:now,count:0};buckets.set(key,b)}b.count++;if(b.count>max)return{ok:false,retryAfterMs:windowMs-(now-b.start)};if(buckets.size>5000)for(const[k,v]of buckets)if(now-v.start>windowMs*2)buckets.delete(k);return{ok:true,remaining:Math.max(0,max-b.count)}}}
export function clientIp(req){
  if(process.env.RAILWAY_ENVIRONMENT_ID){const xr=String(req.headers['x-real-ip']||'').trim();if(net.isIP(xr))return xr}
  const trust=String(process.env.TT_TRUST_PROXY||'').toLowerCase()==='true';
  if(trust){const xf=req.headers['x-forwarded-for'];if(typeof xf==='string'&&xf){const ip=xf.split(',')[0].trim();if(net.isIP(ip))return ip}}
  return req.socket.remoteAddress||'unknown';
}
export function constantTimeTokenOk(provided,expected){if(!expected)return true;if(!provided)return false;const a=Buffer.from(provided),b=Buffer.from(expected);if(a.length!==b.length)return false;return timingSafeEqual(a,b)}
