import https from 'node:https';
import { resolvePublicHost, validateHttpsUrl } from './security.mjs';

const MAX_BYTES=2*1024*1024;
export async function fetchSubscriptionText(rawUrl,{maxRedirects=2,signal}={}){
  let current=await validateHttpsUrl(rawUrl);
  for(let redirect=0;redirect<=maxRedirects;redirect++){
    const rows=await resolvePublicHost(current.hostname);const chosen=rows.find(x=>x.family===4)||rows[0];
    const result=await new Promise((resolve,reject)=>{
      const req=https.request({hostname:current.hostname,port:443,path:`${current.pathname}${current.search}`,method:'GET',servername:current.hostname,headers:{'User-Agent':'TrojanTester/1.1','Accept':'text/plain,*/*;q=.5'},lookup:(hostname,opts,cb)=>cb(null,chosen.address,chosen.family),timeout:8000},res=>{
        if(res.statusCode>=300&&res.statusCode<400&&res.headers.location){res.resume();return resolve({redirect:new URL(res.headers.location,current)})}
        if(res.statusCode<200||res.statusCode>=300){res.resume();return reject(new Error(`Subscription HTTP ${res.statusCode}`))}
        const declared=Number(res.headers['content-length']||0);if(declared>MAX_BYTES){res.resume();return reject(new Error('Subscription too large'))}
        const chunks=[];let size=0;res.on('data',d=>{size+=d.length;if(size>MAX_BYTES){req.destroy(new Error('Subscription too large'));return}chunks.push(d)});res.on('end',()=>resolve({text:Buffer.concat(chunks).toString('utf8')}));res.on('error',reject)
      });
      req.on('timeout',()=>req.destroy(new Error('Subscription timeout')));req.on('error',reject);
      if(signal){if(signal.aborted)req.destroy(new Error('Aborted'));else signal.addEventListener('abort',()=>req.destroy(new Error('Aborted')),{once:true})}
      req.end();
    });
    if(result.text!=null)return result.text;
    current=await validateHttpsUrl(result.redirect.toString());
  }
  throw new Error('Too many redirects');
}
