const SUPPORTED = new Set(['vless', 'trojan', 'vmess', 'hysteria2', 'hy2', 'ss', 'tuic']);

function b64decode(input) {
  if (!input) return null;
  try {
    let s = String(input).trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64').toString('utf8');
  } catch { return null; }
}

function dec(v='') { try { return decodeURIComponent(v); } catch { return v; } }
function yes(v) { return ['1','true','yes','on'].includes(String(v ?? '').toLowerCase()); }
function transport(v='') {
  const x = String(v).toLowerCase();
  if (x === 'websocket') return 'ws';
  if (x === 'h2') return 'http';
  return x || 'tcp';
}
function base(raw, protocol) {
  return {
    raw, protocol, address:'', port:443, uuid:'', password:'', method:'', tag:'',
    transport:'tcp', host:'', path:'/', serviceName:'', security:'none', tls:false,
    sni:'', alpn:[], fingerprint:'', insecure:false, reality:false, publicKey:'', shortId:'',
    flow:'', vmessSecurity:'auto', alterId:0, plugin:'', pluginOpts:'', obfs:'', obfsPassword:'',
    congestionControl:'', udpRelayMode:'', zeroRtt:false
  };
}

function parseVmess(raw) {
  const text = b64decode(raw.slice(8));
  if (!text) return null;
  let d; try { d = JSON.parse(text); } catch { return null; }
  if (!d.add || !d.id) return null;
  const c = base(raw,'vmess');
  c.address = String(d.add); c.port = Number(d.port || 443); c.uuid = String(d.id);
  c.tag = String(d.ps || 'VMess'); c.transport = transport(d.net || d.type || 'tcp');
  c.host = String(d.host || ''); c.path = String(d.path || '/');
  c.serviceName = String(d.serviceName || (c.transport === 'grpc' ? d.path || '' : ''));
  c.security = String(d.tls || 'none').toLowerCase(); c.tls = ['tls','reality'].includes(c.security);
  c.reality = c.security === 'reality'; c.sni = String(d.sni || d.serverName || d.host || '');
  c.alpn = String(d.alpn || '').split(',').map(x=>x.trim()).filter(Boolean);
  c.fingerprint = String(d.fp || ''); c.insecure = yes(d.allowInsecure);
  c.vmessSecurity = String(d.scy || d.security || 'auto'); c.alterId = Number(d.aid || 0);
  c.flow = String(d.flow || ''); c.publicKey = String(d.pbk || ''); c.shortId = String(d.sid || '');
  return c;
}

function decodeSsCred(v) {
  let t = dec(v || '');
  if (!t.includes(':')) { const d = b64decode(t); if (d) t = d; }
  const i=t.indexOf(':'); return i>0 ? {method:t.slice(0,i),password:t.slice(i+1)} : {method:'',password:t};
}
function parseSs(raw) {
  const body = raw.slice(5); const hash=body.indexOf('#');
  const noHash = hash>=0?body.slice(0,hash):body; const qi=noHash.indexOf('?');
  const payload=qi>=0?noHash.slice(0,qi):noHash; const params=new URLSearchParams(qi>=0?noHash.slice(qi+1):'');
  let creds,address,port;
  if (payload.includes('@')) {
    const at=payload.lastIndexOf('@'); creds=decodeSsCred(payload.slice(0,at));
    try { const u=new URL(`ss://x@${payload.slice(at+1)}`); address=u.hostname; port=Number(u.port||8388); } catch { return null; }
  } else {
    const d=b64decode(payload); if (!d || !d.includes('@')) return null;
    const at=d.lastIndexOf('@'); creds=decodeSsCred(d.slice(0,at));
    try { const u=new URL(`ss://x@${d.slice(at+1)}`); address=u.hostname; port=Number(u.port||8388); } catch { return null; }
  }
  if (!address || !creds.method) return null;
  const c=base(raw,'ss'); c.address=address;c.port=port;c.method=creds.method;c.password=creds.password;
  c.tag = hash>=0?dec(body.slice(hash+1)):'Shadowsocks';
  const plug=params.get('plugin')||''; if (plug.includes(';')) { const [n,...o]=plug.split(';'); c.plugin=n;c.pluginOpts=o.join(';'); } else c.plugin=plug;
  return c;
}

export function parseProxyUri(rawInput) {
  const raw=String(rawInput||'').trim(); if (!raw.includes('://')) return null;
  if (raw.startsWith('vmess://')) return parseVmess(raw);
  if (raw.startsWith('ss://')) return parseSs(raw);
  let u; try {u=new URL(raw);} catch {return null;}
  let p=u.protocol.slice(0,-1).toLowerCase(); if (!SUPPORTED.has(p)) return null; if (p==='hy2') p='hysteria2';
  const q=Object.fromEntries(u.searchParams.entries()); const c=base(raw,p);
  c.address=u.hostname;c.port=Number(u.port||443);c.tag=dec(u.hash.slice(1))||p.toUpperCase();
  c.security=String(q.security || (['trojan','hysteria2','tuic'].includes(p)?'tls':'none')).toLowerCase();
  c.tls=['tls','reality'].includes(c.security)||['trojan','hysteria2','tuic'].includes(p);c.reality=c.security==='reality';
  c.sni=String(q.sni||q.serverName||q.peer||'');c.alpn=String(q.alpn||'').split(',').map(x=>x.trim()).filter(Boolean);
  c.fingerprint=String(q.fp||q.fingerprint||'');c.insecure=yes(q.allowInsecure||q.insecure);
  c.publicKey=String(q.pbk||q.publicKey||'');c.shortId=String(q.sid||q.shortId||'');c.flow=String(q.flow||'');
  c.transport=transport(q.type||q.net||(['hysteria2','tuic'].includes(p)?'quic':'tcp'));
  c.host=String(q.host||'');c.path=dec(q.path||'/');c.serviceName=dec(q.serviceName||q.service||(c.transport==='grpc'?q.path||'':''));
  c.obfs=String(q.obfs||'');c.obfsPassword=dec(q['obfs-password']||q.obfsPassword||'');
  c.congestionControl=String(q.congestion_control||q.congestionControl||q.cc||'');c.udpRelayMode=String(q.udp_relay_mode||q.udpRelayMode||'');c.zeroRtt=yes(q.zero_rtt_handshake||q.zeroRtt);
  if (p==='vless') c.uuid=dec(u.username||'');
  if (p==='trojan') c.password=dec(u.username||'');
  if (p==='hysteria2') c.password=dec(u.username||q.password||q.auth||'');
  if (p==='tuic') { c.uuid=dec(u.username||'');c.password=dec(u.password||q.password||''); }
  return c;
}
