import test from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp } from '../backend/lib/security.mjs';
import { parseProxyUri } from '../backend/lib/parser.mjs';
import { buildOutbound } from '../backend/lib/singbox.mjs';

const uuid='11111111-1111-4111-8111-111111111111';

test('blocks private and documentation IPv4 ranges',()=>{
  for(const ip of ['127.0.0.1','10.0.0.1','192.168.1.1','169.254.169.254','100.64.0.1','198.51.100.5','203.0.113.5'])assert.equal(isBlockedIp(ip),true,ip);
  assert.equal(isBlockedIp('1.1.1.1'),false);
});

test('blocks loopback and ULA IPv6',()=>{
  assert.equal(isBlockedIp('::1'),true);assert.equal(isBlockedIp('fd00::1'),true);assert.equal(isBlockedIp('2606:4700:4700::1111'),false);
});

test('builds VLESS Reality sing-box outbound',()=>{
  const c=parseProxyUri(`vless://${uuid}@example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUB&sid=abcd&flow=xtls-rprx-vision`);
  const o=buildOutbound(c,'1.1.1.1');assert.equal(o.type,'vless');assert.equal(o.server,'1.1.1.1');assert.equal(o.tls.server_name,'www.microsoft.com');assert.equal(o.tls.reality.public_key,'PUB');assert.equal(o.flow,'xtls-rprx-vision');
});

test('builds Trojan WS outbound with Host header',()=>{
  const c=parseProxyUri('trojan://secret@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws&sni=example.com');
  const o=buildOutbound(c,'1.1.1.1');assert.equal(o.type,'trojan');assert.equal(o.password,'secret');assert.equal(o.transport.type,'ws');assert.equal(o.transport.headers.Host,'cdn.example.com');
});

test('builds VMess outbound with cipher and alter id',()=>{
  const raw=Buffer.from(JSON.stringify({add:'example.com',port:'443',id:uuid,aid:'0',net:'tcp',tls:'tls',sni:'example.com',scy:'auto'})).toString('base64');
  const c=parseProxyUri(`vmess://${raw}`);const o=buildOutbound(c,'1.1.1.1');assert.equal(o.type,'vmess');assert.equal(o.security,'auto');assert.equal(o.alter_id,0);
});

test('builds Hysteria2 salamander outbound',()=>{
  const c=parseProxyUri('hysteria2://pass@example.com:443?sni=example.com&obfs=salamander&obfs-password=obf');
  const o=buildOutbound(c,'1.1.1.1');assert.equal(o.type,'hysteria2');assert.equal(o.password,'pass');assert.deepEqual(o.obfs,{type:'salamander',password:'obf'});
});

test('rejects SS plugins to avoid executing missing external binaries',()=>{
  const cred=Buffer.from('aes-256-gcm:pass').toString('base64url');const c=parseProxyUri(`ss://${cred}@1.1.1.1:8388?plugin=v2ray-plugin%3Btls`);
  assert.throws(()=>buildOutbound(c,'1.1.1.1'),/plugin/i);
});
