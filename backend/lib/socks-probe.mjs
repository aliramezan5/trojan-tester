import net from 'node:net';
import tls from 'node:tls';

class Reader {
  constructor(socket){
    this.socket=socket;this.buf=Buffer.alloc(0);this.waiters=[];this.error=null;
    socket.on('data',d=>{this.buf=Buffer.concat([this.buf,d]);this.flush()});
    socket.on('error',e=>{this.error=e;this.flush()});
    socket.on('close',()=>{if(!this.error)this.error=new Error('Socket closed');this.flush()});
  }
  flush(){
    while(this.waiters.length){const w=this.waiters[0];if(this.error){this.waiters.shift();w.reject(this.error);continue}if(this.buf.length<w.n)break;this.waiters.shift();const out=this.buf.subarray(0,w.n);this.buf=this.buf.subarray(w.n);w.resolve(out)}
  }
  read(n,timeoutMs=5000){return new Promise((resolve,reject)=>{const t=setTimeout(()=>{const i=this.waiters.findIndex(x=>x.resolve===wrappedResolve);if(i>=0)this.waiters.splice(i,1);reject(new Error('Read timeout'))},timeoutMs);const wrappedResolve=v=>{clearTimeout(t);resolve(v)};const wrappedReject=e=>{clearTimeout(t);reject(e)};this.waiters.push({n,resolve:wrappedResolve,reject:wrappedReject});this.flush()})}
  takeBuffered(){const b=this.buf;this.buf=Buffer.alloc(0);return b}
}

function connectTcp(host,port,timeoutMs){return new Promise((resolve,reject)=>{const s=net.connect({host,port});const t=setTimeout(()=>{s.destroy();reject(new Error('SOCKS connect timeout'))},timeoutMs);s.once('connect',()=>{clearTimeout(t);resolve(s)});s.once('error',e=>{clearTimeout(t);reject(e)})})}

async function socksConnect(socksPort,targetHost,targetPort,timeoutMs){
  const started=performance.now();const socket=await connectTcp('127.0.0.1',socksPort,timeoutMs);const r=new Reader(socket);
  socket.write(Buffer.from([0x05,0x01,0x00]));const hello=await r.read(2,timeoutMs);if(hello[0]!==5||hello[1]!==0){socket.destroy();throw new Error('SOCKS authentication negotiation failed')}
  const host=Buffer.from(targetHost,'utf8');if(host.length>255){socket.destroy();throw new Error('Target hostname too long')}
  const req=Buffer.alloc(7+host.length);req[0]=5;req[1]=1;req[2]=0;req[3]=3;req[4]=host.length;host.copy(req,5);req.writeUInt16BE(targetPort,5+host.length);socket.write(req);
  const head=await r.read(4,timeoutMs);if(head[0]!==5||head[1]!==0){socket.destroy();throw new Error(`SOCKS connect rejected (${head[1]})`)}
  if(head[3]===1)await r.read(6,timeoutMs);else if(head[3]===4)await r.read(18,timeoutMs);else if(head[3]===3){const n=(await r.read(1,timeoutMs))[0];await r.read(n+2,timeoutMs)}else{socket.destroy();throw new Error('SOCKS invalid address type')}
  const extra=r.takeBuffered(); if(extra.length) socket.unshift(extra);
  return {socket,handshakeMs:Math.round(performance.now()-started)};
}

function tlsWrap(socket,servername,timeoutMs){return new Promise((resolve,reject)=>{const started=performance.now();const t=tls.connect({socket,servername,ALPNProtocols:['http/1.1'],rejectUnauthorized:true});const timer=setTimeout(()=>{t.destroy();reject(new Error('Destination TLS timeout'))},timeoutMs);t.once('secureConnect',()=>{clearTimeout(timer);resolve({socket:t,tlsMs:Math.round(performance.now()-started)})});t.once('error',e=>{clearTimeout(timer);reject(e)})})}

function readHttp(socket,{maxBody=1024*1024,timeoutMs=6000}={}){
  return new Promise((resolve,reject)=>{
    let buffer=Buffer.alloc(0),headerEnd=-1,status=0,bodyBytes=0,firstByteAt=null,headers=null,settled=false;const started=performance.now();
    const timer=setTimeout(()=>finish(new Error('HTTP response timeout')),timeoutMs);
    const finish=(err)=>{
      if(settled)return;settled=true;clearTimeout(timer);
      socket.removeAllListeners('data');socket.removeAllListeners('end');socket.removeAllListeners('error');
      const result={status,headers,body:headerEnd>=0?buffer.subarray(headerEnd+4,Math.min(buffer.length,headerEnd+4+maxBody)):Buffer.alloc(0),bodyBytes,ttfbMs:firstByteAt==null?null:Math.round(firstByteAt-started),elapsedMs:Math.round(performance.now()-started)};
      if(!socket.destroyed)socket.destroy();
      if(err)reject(err);else resolve(result);
    };
    socket.on('data',chunk=>{
      if(firstByteAt==null)firstByteAt=performance.now();buffer=Buffer.concat([buffer,chunk]);
      if(headerEnd<0){headerEnd=buffer.indexOf('\r\n\r\n');if(headerEnd>=0){const h=buffer.subarray(0,headerEnd).toString('latin1');const lines=h.split('\r\n');status=Number((lines[0].match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/)||[])[1]||0);headers={};for(const line of lines.slice(1)){const i=line.indexOf(':');if(i>0)headers[line.slice(0,i).toLowerCase()]=line.slice(i+1).trim()}bodyBytes=buffer.length-(headerEnd+4)}}else bodyBytes+=chunk.length;
      if(buffer.length>(headerEnd<0?65536:headerEnd+4+maxBody))finish();
      const len=Number(headers?.['content-length']||0);if(headerEnd>=0&&len>0&&bodyBytes>=Math.min(len,maxBody))finish();
    });
    socket.once('end',()=>finish());socket.once('error',e=>finish(e));
  })
}

export async function probeHttpsThroughSocks({socksPort,host,path='/',timeoutMs=7000,maxBody=65536}){
  const {socket,handshakeMs}=await socksConnect(socksPort,host,443,timeoutMs);
  const wrapped=await tlsWrap(socket,host,timeoutMs);
  wrapped.socket.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: TrojanTester/1.1\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
  const response=await readHttp(wrapped.socket,{maxBody,timeoutMs});
  if(response.status<200||response.status>=400)throw new Error(`Test destination HTTP ${response.status}`);
  return {proxyHandshakeMs:handshakeMs,tlsMs:wrapped.tlsMs,ttfbMs:response.ttfbMs,status:response.status,body:response.body};
}

export async function measureThroughputThroughSocks({socksPort,bytes=262144,timeoutMs=12000}){
  const host='speed.cloudflare.com';const path=`/__down?bytes=${Math.max(32768,Math.min(1048576,bytes))}`;
  const started=performance.now();const result=await probeHttpsThroughSocks({socksPort,host,path,timeoutMs,maxBody:bytes+1024});const elapsed=Math.max(1,performance.now()-started);const got=result.body.length;return {bytes:got,mbps:Number(((got*8)/(elapsed/1000)/1_000_000).toFixed(2))};
}
