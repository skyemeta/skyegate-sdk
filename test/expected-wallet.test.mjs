// Regression test for the 2026-11-09 security scan finding F1: a valid attestation JWT about
// someone else's wallet must not pass when the caller names the wallet its own sign-in proved.
// Run: npm test   (SDK_BUILD=<dir> points it at another build, e.g. an older release)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

const buildDir = process.env.SDK_BUILD || path.resolve(import.meta.dirname, '..', 'build');
const { validateContentToken } = await import(pathToFileURL(path.join(buildDir, 'index.js')).href);

const ISS = 'https://api.insumermodel.com';
const KID = 'insumer-attest-v2';
const HOLDER = '0x1111111111111111111111111111111111111111';
const VISITOR = '0x2222222222222222222222222222222222222222';
const SOL = 'So1anaWa11etAddre55xxxxxxxxxxxxxxxxxxxxxxxx';
let server, jwksUrl, privateKey;

before(async () => {
  const kp = await generateKeyPair('ES256');
  privateKey = kp.privateKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: KID, alg: 'ES256', use: 'sig' };
  server = http.createServer((_q, r) => { r.setHeader('content-type', 'application/json'); r.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  jwksUrl = `http://127.0.0.1:${server.address().port}/jwks.json`;
});
after(() => server.close());

const evm = (chainId = 8453) => ({ met: true, evaluatedCondition: { type: 'token_balance', chainId, contractAddress: '0xabc', threshold: '1', operator: 'gte' } });
const sol = () => ({ met: true, evaluatedCondition: { type: 'token_balance', chainId: 'solana', contractAddress: 'Mint1', threshold: '1', operator: 'gte' } });

function sign(sub, results) {
  return new SignJWT({ pass: true, results })
    .setProtectedHeader({ alg: 'ES256', kid: KID })
    .setIssuer(ISS).setSubject(sub).setIssuedAt().setExpirationTime('30m').setJti('att_test')
    .sign(privateKey);
}

test('a JWT minted for a public holder is refused when the session proved another wallet', async () => {
  const jwt = await sign(HOLDER, [evm()]);
  const r = await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: VISITOR } });
  assert.equal(r.valid, true);
  assert.equal(r.pass, false);
});

test('the same JWT passes for the wallet it names (EVM case-insensitive)', async () => {
  const jwt = await sign(HOLDER, [evm()]);
  const r = await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: HOLDER.toUpperCase().replace('0X', '0x') } });
  assert.equal(r.pass, true, r.error);
});

test('a JWT that also evaluates another chain family is not bound to the session wallet', async () => {
  const jwt = await sign(HOLDER, [evm(), sol()]);
  const r = await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: HOLDER } });
  assert.equal(r.pass, false);
});

test('a Solana session wallet must match sub exactly, and every result must be Solana', async () => {
  const jwt = await sign(SOL, [sol()]);
  assert.equal((await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: SOL, walletType: 'solana' } })).pass, true);
  assert.equal((await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: SOL.toLowerCase(), walletType: 'solana' } })).pass, false);
  assert.equal((await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: SOL } })).pass, false, 'walletType defaults to evm');
});

test('an empty or unknown expectedWallet never passes', async () => {
  const jwt = await sign(HOLDER, [evm()]);
  assert.equal((await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: '' } })).pass, false);
  assert.equal((await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: HOLDER, walletType: 'toString' } })).pass, false);
});

test('Farcaster results (signed without a chain) count as EVM', async () => {
  const jwt = await sign(HOLDER, [{ met: true, evaluatedCondition: { type: 'farcaster_id', operator: 'registered' } }]);
  assert.equal((await validateContentToken(jwt, { jwksUrl, expectedWallet: { address: HOLDER } })).pass, true);
});

test('without expectedWallet the behaviour is unchanged (backward compatible)', async () => {
  const jwt = await sign(HOLDER, [evm()]);
  assert.equal((await validateContentToken(jwt, { jwksUrl })).pass, true);
});
