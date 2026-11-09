// 0.5.0: validateContentToken requires Skye Meta's receipt, so a JWT requested directly from
// InsumerAPI (skipping the licensed, proof-checked proxy) is refused. 2026-11-09 scan, F1.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { validateContentToken, verifyConditions } from '../build/index.js';

const HOLDER = '0x1111111111111111111111111111111111111111';
const SITE = 'shop.example';
const COND = { type: 'token_balance', chainId: 8453, contractAddress: '0xabc', threshold: '1' };
let server, url, attKey, receiptKey, strangerKey, opts, proxyReply;

before(async () => {
  attKey = await generateKeyPair('ES256');
  receiptKey = await generateKeyPair('ES256');
  strangerKey = await generateKeyPair('ES256');
  const attJwk = { ...(await exportJWK(attKey.publicKey)), kid: 'insumer-attest-v2', alg: 'ES256' };
  const recJwk = { ...(await exportJWK(receiptKey.publicKey)), kid: 'skyemeta-receipt-test', alg: 'ES256' };
  server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/jwks.json') return res.end(JSON.stringify({ keys: [attJwk] }));
    if (req.url === '/receipt-jwks.json') return res.end(JSON.stringify({ keys: [recJwk] }));
    if (req.url === '/api/verify') return res.end(JSON.stringify(proxyReply));
    res.statusCode = 404; res.end('{}');
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  url = `http://127.0.0.1:${server.address().port}`;
  opts = { jwksUrl: `${url}/jwks.json`, receiptJwksUrl: `${url}/receipt-jwks.json`, audience: SITE, expectedConditions: [COND] };
});
after(() => server.close());

const ath = (jwt) => createHash('sha256').update(jwt).digest('base64url');

function attestation(sub = HOLDER) {
  return new SignJWT({ pass: true, results: [{ met: true, evaluatedCondition: { ...COND, operator: 'gte' } }] })
    .setProtectedHeader({ alg: 'ES256', kid: 'insumer-attest-v2' })
    .setIssuer('https://api.insumermodel.com').setSubject(sub).setIssuedAt().setExpirationTime('30m').setJti('ATST-1')
    .sign(attKey.privateKey);
}
function receipt(jwt, { aud = SITE, sub = HOLDER, hash = ath(jwt), key = receiptKey.privateKey, typ = 'skyegate-receipt+jwt', iss = 'https://skyemeta.com', exp = '5m' } = {}) {
  return new SignJWT({ ath: hash, lic: 'abc123' })
    .setProtectedHeader({ alg: 'ES256', kid: 'skyemeta-receipt-test', typ })
    .setIssuer(iss).setAudience(aud).setSubject(sub).setIssuedAt().setExpirationTime(exp)
    .sign(key);
}

test('a JWT with its receipt, for this site, passes', async () => {
  const jwt = await attestation();
  const r = await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt) });
  assert.equal(r.pass, true, r.error);
});

test('the scan\'s attack: a JWT requested directly from InsumerAPI, with no receipt, is refused', async () => {
  const r = await validateContentToken(await attestation(), opts);
  assert.equal(r.pass, false);
  assert.match(r.error, /receipt/i);
});

test('a receipt for another site is refused', async () => {
  const jwt = await attestation();
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt, { aud: 'other.example' }) })).pass, false);
});

test('a receipt for another attestation is refused', async () => {
  const jwt = await attestation();
  const other = await attestation();
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(other) })).pass, false);
});

test('a receipt naming another wallet is refused', async () => {
  const jwt = await attestation();
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt, { sub: '0x2222222222222222222222222222222222222222' }) })).pass, false);
});

test('a receipt signed by a key outside the receipt JWKS is refused', async () => {
  const jwt = await attestation();
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt, { key: strangerKey.privateKey }) })).pass, false);
});

test('a receipt with the wrong type, issuer, or already expired is refused', async () => {
  const jwt = await attestation();
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt, { typ: 'JWT' }) })).pass, false);
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt, { iss: 'https://api.insumermodel.com' }) })).pass, false);
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: await receipt(jwt, { exp: Math.floor(Date.now() / 1000) - 10 }) })).pass, false);
});

test('the attestation JWT itself cannot stand in for a receipt', async () => {
  const jwt = await attestation();
  assert.equal((await validateContentToken(jwt, { ...opts, receipt: jwt })).pass, false);
});

test('audience and expectedConditions are required', async () => {
  const jwt = await attestation();
  const rec = await receipt(jwt);
  const noAud = await validateContentToken(jwt, { ...opts, audience: undefined, receipt: rec });
  assert.equal(noAud.pass, false); assert.match(noAud.error, /audience/);
  const noCond = await validateContentToken(jwt, { ...opts, expectedConditions: [], receipt: rec });
  assert.equal(noCond.pass, false); assert.match(noCond.error, /expectedConditions/);
  const omitted = await validateContentToken(jwt, { receipt: rec });
  assert.equal(omitted.pass, false);
});

test('allowDirectAttestations lets a JWT through without a receipt (servers that prove the wallet themselves)', async () => {
  const r = await validateContentToken(await attestation(), { ...opts, allowDirectAttestations: true, expectedWallet: { address: HOLDER } });
  assert.equal(r.pass, true, r.error);
});

test('verifyConditions returns the proxy\'s receipt beside the JWT', async () => {
  const jwt = await attestation();
  const rec = await receipt(jwt);
  proxyReply = { ok: true, data: { jwt, attestation: { pass: true } }, receipt: rec };
  const r = await verifyConditions({ address: HOLDER, conditions: [COND], licenseKey: 'test', endpoint: `${url}/api/verify`, domain: SITE });
  assert.equal(r.receipt, rec);
  proxyReply = { ok: true, data: { jwt, attestation: { pass: true } } };
  const none = await verifyConditions({ address: HOLDER, conditions: [COND], licenseKey: 'test', endpoint: `${url}/api/verify`, domain: SITE });
  assert.equal(none.receipt, undefined);
});
