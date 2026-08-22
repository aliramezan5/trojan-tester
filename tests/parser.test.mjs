import test from 'node:test';
import assert from 'node:assert/strict';
import { parseProxyURI, canonicalConfigKey, deduplicateConfigs, browserProbeCapability, decodeSubscriptionText } from '../src/parser.js';

const uuid='11111111-1111-4111-8111-111111111111';

test('parses VLESS Reality structural fields',()=>{
  const c=parseProxyURI(`vless://${uuid}@example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=pubkey&sid=abcd&type=tcp#R`);
  assert.equal(c.protocol,'vless');assert.equal(c.address,'example.com');assert.equal(c.reality,true);assert.equal(c.publicKey,'pubkey');assert.equal(c.shortId,'abcd');
});

test('parses Trojan websocket',()=>{
  const c=parseProxyURI('trojan://secret@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws&sni=example.com#T');
  assert.equal(c.protocol,'trojan');assert.equal(c.auth,'secret');assert.equal(c.transport,'ws');assert.equal(c.path,'/ws');assert.equal(c.host,'cdn.example.com');
});

test('parses VMess base64 JSON',()=>{
  const raw=Buffer.from(JSON.stringify({v:'2',ps:'vm',add:'example.com',port:'443',id:uuid,aid:'0',net:'ws',host:'example.com',path:'/x',tls:'tls',sni:'example.com',scy:'auto'})).toString('base64');
  const c=parseProxyURI(`vmess://${raw}`);assert.equal(c.protocol,'vmess');assert.equal(c.vmessSecurity,'auto');assert.equal(c.transport,'ws');
});

test('parses SIP002 Shadowsocks',()=>{
  const cred=Buffer.from('aes-256-gcm:pass').toString('base64url');
  const c=parseProxyURI(`ss://${cred}@1.1.1.1:8388#SS`);assert.equal(c.method,'aes-256-gcm');assert.equal(c.auth,'pass');assert.equal(c.address,'1.1.1.1');
});

test('dedup key preserves different paths',()=>{
  const a=parseProxyURI(`vless://${uuid}@example.com:443?security=tls&type=ws&host=example.com&path=%2Fa&sni=example.com`);
  const b=parseProxyURI(`vless://${uuid}@example.com:443?security=tls&type=ws&host=example.com&path=%2Fb&sni=example.com`);
  assert.notEqual(canonicalConfigKey(a),canonicalConfigKey(b));assert.equal(deduplicateConfigs([a,b]).length,2);
});

test('browser probe refuses Reality and mismatched SNI',()=>{
  const reality=parseProxyURI(`vless://${uuid}@example.com:443?security=reality&sni=www.microsoft.com&pbk=x&sid=aa`);
  assert.equal(browserProbeCapability(reality).testable,false);
  const custom=parseProxyURI(`trojan://p@example.com:443?security=tls&sni=cdn.example.net`);
  assert.equal(browserProbeCapability(custom).testable,false);
});

test('decodes base64 subscription',()=>{
  const text=`vless://${uuid}@example.com:443?security=tls&sni=example.com`;
  const encoded=Buffer.from(text).toString('base64');assert.deepEqual(decodeSubscriptionText(encoded),[text]);
});
