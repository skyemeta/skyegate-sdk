/**
 * @skyemeta/skyegate — condition-based content gating for Vercel / Next.js.
 *
 * SkyeGate is a SkyeMeta product. It is powered by InsumerAPI, the condition-based
 * access API (signed boolean attestations over wallet conditions), an independent
 * product of InsumerModel. SkyeGate is powered by InsumerAPI;
 * they are separate companies.
 *
 * The SDK talks to the SkyeMeta proxy (skyemeta.com/api/verify) with a SKYE
 * license key. The proxy authenticates the key, forwards the request to
 * InsumerAPI, and returns a signed JWT. Server endpoints validate the JWT via
 * JWKS before serving gated content.
 *
 * Trust model: every result is cryptographically signed (ECDSA P-256 + JWKS),
 * independently verifiable by any third party. Trust the math, not a company —
 * including us.
 *
 * Bring your own wallet stack — wagmi, RainbowKit, ConnectKit, Privy, etc.
 * This SDK only provides the gating layer.
 *
 * Companion to the SkyeGate WordPress plugin: same SKYE license key, same
 * conditions, same proxy. One license, two stacks.
 */

import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';
import { verifyPqCompanion, pqFails, type PqResult, type PqStatus } from './pq.js';
export type { PqResult, PqStatus };

// ── Public types ──────────────────────────────────────────────────────────

/** A SkyeGate condition — same shape the WordPress Pro plugin sends. */
export interface Condition {
  /** Condition kind. */
  type: 'token_balance' | 'nft_ownership' | 'eas_attestation' | 'farcaster_id';
  /** Token / NFT contract address, or `"native"` for chain-native tokens. */
  contractAddress?: string;
  /**
   * Numeric chain ID for EVM chains, or the chain name for the others: `"solana"`, `"xrpl"`,
   * `"bitcoin"`, `"tron"`, `"stellar"`, `"sui"`. Set {@link VerifyConditionsParams.walletType} to
   * the matching wallet kind. A numeric string (`"8453"`) matches the signed number.
   */
  chainId?: number | string;
  /**
   * Minimum balance for `token_balance`. Prefer a decimal string (`'100'`) —
   * it keeps full precision and is the form v2 signing keys require; a number
   * is accepted and converted to its decimal-string form before sending.
   */
  threshold?: number | string;
  /**
   * Leave this out. The token's own decimals are always read from the chain, so a value here
   * changes nothing when it is right and is refused by the API when it is wrong. The SkyeMeta
   * proxy removes it before forwarding, and {@link validateContentToken} ignores it.
   */
  decimals?: number;
  /** EAS template name, e.g. `"coinbase_verified_account"`, `"gitcoin_passport_active"`. */
  template?: string;
  /** XRPL trust line currency code (hex). */
  currency?: string;
  /** Free-form label echoed back in the attestation result. */
  label?: string;
  /** Stellar asset code, for a non-native Stellar asset. */
  assetCode?: string;
}

/** Which kind of wallet `address` is. Each maps to the request field InsumerAPI reads it from. */
export type WalletType = 'evm' | 'solana' | 'xrpl' | 'bitcoin' | 'tron' | 'stellar' | 'sui';

const WALLET_FIELD: Record<WalletType, string> = {
  evm: 'wallet',
  solana: 'solanaWallet',
  xrpl: 'xrplWallet',
  bitcoin: 'bitcoinWallet',
  tron: 'tronWallet',
  stellar: 'stellarWallet',
  sui: 'suiWallet',
};

export interface VerifyConditionsParams {
  /** Wallet address, in the format of its {@link walletType} (EVM hex by default). */
  address: string;
  /** One or more conditions; pass=true requires every condition to be met. */
  conditions: Condition[];
  /** Your SKYE license key (format: `SKYE-XXXX-XXXX-XXXX`). Provision one at skyemeta.com/skyegate/. */
  licenseKey: string;
  /**
   * The kind of wallet `address` is: `"evm"` (default), `"solana"`, `"xrpl"`, `"bitcoin"`,
   * `"tron"`, `"stellar"` or `"sui"`. Picks which body field carries the address. EVM,
   * Solana, Sui and Tron wallets can prove ownership ({@link walletProof}); XRPL, Bitcoin
   * and Stellar wallets cannot, and a gate that requires proof refuses them.
   */
  walletType?: WalletType;
  /** Override the verification endpoint. Defaults to the production proxy. */
  endpoint?: string;
  /**
   * Domain to claim for license-binding. Defaults to `window.location.hostname`
   * in browsers; required for SSR / Node.js calls. Localhost, `*.vercel.app`,
   * and `*.local` are treated as dev/preview and never bind the license.
   */
  domain?: string;
  /**
   * Wallet ownership proof token from {@link proveWalletOwnership}. Proves the
   * person presenting the address actually controls it; without it, the
   * attestation only says the address meets the conditions. EVM, Solana, Sui
   * and Tron wallets.
   */
  walletProof?: string;
}

export interface VerifyConditionsResult {
  /** True only if every condition was met by the wallet. */
  pass: boolean;
  /** Signed JWT proving the result. Pass to {@link validateContentToken} on the server. */
  jwt: string | null;
  /**
   * Post-quantum companion of `jwt` (compact JWS, alg ML-DSA-65), when the API returned one.
   * Pass it alongside `jwt` to {@link validateContentToken} as `options.pqJwt`.
   */
  pqJwt: string | null;
  /** Full InsumerAPI response envelope, for advanced inspection. */
  raw: unknown;
  /**
   * Set when no verdict came back: the proxy or the API refused the request, or could not be
   * reached. Always a string. A signed "not met" is `pass: false` with no `error`.
   */
  error?: string;
}

export interface ValidateContentTokenOptions {
  /** Override the JWKS endpoint. Defaults to InsumerAPI's public JWKS. */
  jwksUrl?: string;
  /** Expected `iss` claim. Defaults to InsumerAPI. */
  issuer?: string;
  /**
   * Optional replay protection: ensure the signed conditions in the JWT match
   * the conditions you require for this route. Pass the same conditions you gave
   * {@link verifyConditions}: each must match one signed result. `template` is
   * checked through what it resolves to, `label` against the signed label, and
   * `decimals` is ignored (it is never signed). An unknown template never matches.
   */
  expectedConditions?: Condition[];
  /**
   * The wallet the person presenting this JWT has proven they control, through your own
   * server-side sign-in (for example a Sign-In with Ethereum session you verified), never a
   * value the browser sends with the JWT.
   *
   * Strongly recommended. Anyone can obtain a valid attestation JWT for any public wallet
   * straight from InsumerAPI, without the SkyeGate proxy and without proving they control that
   * wallet. Without this option, `validateContentToken` cannot tell that JWT from one your own
   * visitor earned. With it, the JWT must name this wallet as `sub`, and every signed result must
   * be on that wallet's chain family, or the call returns `pass: false`.
   */
  expectedWallet?: { address: string; walletType?: WalletType };
  /** The `pqJwt` sibling returned with the JWT, if you have it. Reported as `pq` in the result. */
  pqJwt?: string;
  /**
   * Your own post-quantum cutoff. A companion that is present and fails always rejects. An absent or
   * unverifiable companion rejects only once this date has passed (judged by this server's clock).
   * Undefined = reported only. Install `@noble/post-quantum` to verify companions.
   */
  pqRequiredFrom?: string | Date;
  /**
   * ES256 key ids accepted for the JWT. Defaults to InsumerAPI's attestation signing keys
   * (`insumer-attest-v1`, `insumer-attest-v2`); a JWT signed by any other key in the JWKS is refused.
   */
  allowedKids?: string[];
}

export interface ValidateContentTokenResult {
  /** True if the JWT signature, issuer, and expiry all check out. */
  valid: boolean;
  /** True only if `valid` *and* the verification passed *and* (if requested) conditions match. */
  pass: boolean;
  /** Decoded JWT payload (only present when `valid` is true). */
  payload?: JWTPayload & { pass?: boolean; results?: unknown[] };
  /** Reason for failure when `valid` or `pass` is false. */
  error?: string;
  /** Post-quantum companion verdict: verified | refuted | absent | unverifiable. Always reported. */
  pq?: PqResult;
}

// ── Constants ─────────────────────────────────────────────────────────────

// ── Decimal-string thresholds ─────────────────────────────────────────────
// v2 InsumerAPI signing keys require token_balance thresholds as decimal
// strings (a JSON number has already lost precision by parse time). Numbers
// are still accepted here and converted before sending; the exponent-free
// form matches the upstream grammar ^\d+(\.\d+)?$.

function numberToDecimalString(n: number): string | null {
  const s = String(n);
  const m = s.match(/^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/);
  if (!m) return null; // negative, NaN, Infinity — not representable upstream
  const [, int, frac = '', expStr] = m;
  if (expStr === undefined) return s;
  const digits = int + frac;
  const exp = parseInt(expStr, 10) - frac.length;
  if (exp >= 0) return digits + '0'.repeat(exp);
  const point = digits.length + exp;
  return point <= 0
    ? '0.' + '0'.repeat(-point) + digits
    : digits.slice(0, point) + '.' + digits.slice(point);
}

// Canonical form for era-tolerant equality: a v1-signed JWT echoes thresholds
// as numbers, a v2-signed JWT as canonical decimal strings ("00.50" → "0.5").
function canonicalThreshold(v: unknown): string | null {
  let s: string | null;
  if (typeof v === 'number' && Number.isFinite(v)) {
    s = numberToDecimalString(v);
    if (s === null) return null;
  } else if (typeof v === 'string') {
    s = v.trim();
    if (/[eE]/.test(s)) {
      const n = Number(s);
      if (!Number.isFinite(n)) return null;
      s = numberToDecimalString(n);
      if (s === null) return null;
    }
    if (!/^\d+(\.\d+)?$/.test(s)) return null;
  } else {
    return null;
  }
  const [int, frac = ''] = s.split('.');
  const i = int.replace(/^0+(?=\d)/, '');
  const f = frac.replace(/0+$/, '');
  return f ? i + '.' + f : i;
}

function withStringThresholds(conditions: Condition[]): Condition[] {
  return conditions.map((c) => {
    if (typeof c.threshold === 'number' && Number.isFinite(c.threshold)) {
      const s = numberToDecimalString(c.threshold);
      if (s !== null) return { ...c, threshold: s };
    }
    return c;
  });
}

const DEFAULT_VERIFY_ENDPOINT = 'https://skyemeta.com/api/verify';
const DEFAULT_PROOF_ENDPOINT = 'https://skyemeta.com/api/wallet-proof';
const DEFAULT_JWKS_URL = 'https://api.insumermodel.com/.well-known/jwks.json';
const DEFAULT_ISSUER = 'https://api.insumermodel.com';
// Content tokens are attestation JWTs: only InsumerAPI's attestation signing keys issue them.
const DEFAULT_ATTEST_KIDS = ['insumer-attest-v1', 'insumer-attest-v2'];

// ── verifyConditions ─────────────────────────────────────────────────────

/**
 * Ask the SkyeMeta proxy whether a wallet meets one or more conditions.
 *
 * The proxy authenticates your SKYE license key (per-domain, rate-limited),
 * forwards the request to InsumerAPI, and returns the signed result. On pass,
 * use the returned JWT as a bearer token to fetch gated content from your
 * server, where {@link validateContentToken} verifies it before responding.
 *
 * @example
 * ```ts
 * import { verifyConditions } from '@skyemeta/skyegate';
 *
 * // Licensed EVM calls require a wallet-ownership proof (403 without it):
 * const proof = await proveWalletOwnership({ address: walletAddress, provider: window.ethereum });
 *
 * const result = await verifyConditions({
 *   address: walletAddress,
 *   conditions: [{
 *     type: 'token_balance',
 *     contractAddress: 'native',
 *     chainId: 1,
 *     threshold: '0.01',
 *   }],
 *   licenseKey: process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!,
 *   walletProof: proof.proofToken!,
 * });
 *
 * if (result.pass && result.jwt) {
 *   // POST result.jwt to your /api/gated-content endpoint
 * }
 * ```
 */
export async function verifyConditions(
  params: VerifyConditionsParams
): Promise<VerifyConditionsResult> {
  const endpoint = params.endpoint ?? DEFAULT_VERIFY_ENDPOINT;
  const walletField = WALLET_FIELD[params.walletType ?? 'evm'];
  if (!walletField) {
    return { pass: false, jwt: null, pqJwt: null, raw: null, error: `Unknown walletType "${String(params.walletType)}"` };
  }

  const body: Record<string, unknown> = {
    conditions: withStringThresholds(params.conditions),
    format: 'jwt',
  };
  body[walletField] = params.address;
  if (params.walletProof) body.wallet_proof = params.walletProof;

  const domain =
    params.domain ??
    (typeof window !== 'undefined' && window.location ? window.location.hostname : undefined);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-SkyeGate-License': params.licenseKey,
  };
  if (domain) headers['X-SkyeGate-Domain'] = domain;

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  } catch (err) {
    return {
      pass: false,
      jwt: null,
      pqJwt: null,
      raw: null,
      error: err instanceof Error ? err.message : 'Network error reaching SkyeMeta proxy',
    };
  }

  let data: any;
  try {
    data = await response.json();
  } catch {
    return {
      pass: false,
      jwt: null,
      pqJwt: null,
      raw: null,
      error: `Invalid JSON from proxy (HTTP ${response.status})`,
    };
  }

  if (!response.ok) {
    return {
      pass: false,
      jwt: null,
      pqJwt: null,
      raw: data,
      error: errorText(data, response.status),
    };
  }

  // A 200 that carries no signed verdict (ok:false, or no boolean pass) is not a "not met".
  const attestation = data?.data?.attestation;
  if (data?.ok === false || typeof attestation?.pass !== 'boolean' || (attestation.pass && typeof data?.data?.jwt !== 'string')) {
    const e = data?.error ? errorText(data, response.status) : 'No verdict in the response';
    return { pass: false, jwt: null, pqJwt: null, raw: data, error: e };
  }
  const jwt = data?.data?.jwt ?? null;
  const pqJwt = typeof data?.data?.pqJwt === 'string' ? data.data.pqJwt : null;
  const pass = attestation?.pass === true;

  return { pass, jwt, pqJwt, raw: data };
}

// The proxy passes InsumerAPI errors through as { code, message }; its own are strings.
function errorText(data: any, status: number): string {
  const e = data?.error;
  if (typeof e === 'string' && e) return e;
  if (e && typeof e.message === 'string' && e.message) return e.message;
  return `HTTP ${status}`;
}

// ── proveWalletOwnership ─────────────────────────────────────────────────

/** Minimal EIP-1193 provider surface — what `window.ethereum` exposes. */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

/** Wallet families that can sign an ownership proof. */
export type ProvableWalletType = 'evm' | 'solana' | 'sui' | 'tron';

export interface ProveWalletOwnershipParams {
  /** The wallet address to prove control of. */
  address: string;
  /**
   * The kind of wallet `address` is: `"evm"` (default), `"solana"`, `"sui"` or
   * `"tron"`. Non-EVM wallets need a `signMessage` callback.
   */
  walletType?: ProvableWalletType;
  /**
   * An EIP-1193 provider (e.g. `window.ethereum`) used to request the
   * signature. Ignored when `signMessage` is supplied.
   */
  provider?: Eip1193Provider;
  /**
   * Bring-your-own signer: given the challenge message, return the signature
   * in the wallet's own format.
   * - EVM: the hex signature, e.g. wagmi `signMessageAsync({ message })`,
   *   viem wallet clients, Privy.
   * - Solana: the 64 signature bytes from Wallet Standard `signMessage`
   *   (a `Uint8Array`, or its base64 string).
   * - Sui: the `signature` string from `sui:signPersonalMessage`.
   * - Tron: the hex string from TronLink `tronWeb.trx.signMessageV2(message)`.
   */
  signMessage?: (message: string) => Promise<string | Uint8Array>;
  /** Domain to stamp into the challenge. Defaults to `window.location.hostname`. */
  domain?: string;
  /** Override the proof endpoint. Defaults to the production proxy. */
  proofEndpoint?: string;
}

export interface ProveWalletOwnershipResult {
  /** Pass to {@link verifyConditions} as `walletProof`. Null on failure. */
  proofToken: string | null;
  /** Seconds the token stays valid; one signature covers the whole visit. */
  expiresInSec?: number;
  /** Populated when the challenge, signature, or verification failed. */
  error?: string;
}

/**
 * Prove the person present controls the wallet, not just that they typed its
 * address. Requests a one-time challenge from the SkyeMeta proof endpoint,
 * has the wallet sign it (EIP-191 `personal_sign` — free, gasless, no
 * transaction), and exchanges the signature for a short-lived proof token.
 *
 * The signature goes from the member's browser to the proof endpoint
 * directly — it never passes through your server, and the verification stays
 * an air gap: your server still only sees the address and the signed boolean.
 * Smart-contract wallets (e.g. Coinbase Smart Wallet passkeys) are verified
 * on-chain via EIP-1271/6492. Solana, Sui and Tron wallets prove the same way
 * with their own message signature: pass `walletType` and a `signMessage`
 * callback.
 *
 * The token is session-scoped: prove once when the wallet connects, then pass
 * the token to every {@link verifyConditions} call for the rest of the visit.
 *
 * @example
 * ```ts
 * import { proveWalletOwnership, verifyConditions } from '@skyemeta/skyegate';
 *
 * const proof = await proveWalletOwnership({
 *   address: walletAddress,
 *   provider: window.ethereum,
 * });
 * if (!proof.proofToken) throw new Error(proof.error);
 *
 * const result = await verifyConditions({
 *   address: walletAddress,
 *   conditions,
 *   licenseKey: process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!,
 *   walletProof: proof.proofToken,
 * });
 * ```
 */
export async function proveWalletOwnership(
  params: ProveWalletOwnershipParams
): Promise<ProveWalletOwnershipResult> {
  const endpoint = params.proofEndpoint ?? DEFAULT_PROOF_ENDPOINT;
  const domain =
    params.domain ??
    (typeof window !== 'undefined' && window.location ? window.location.hostname : undefined);

  const family: ProvableWalletType = params.walletType ?? 'evm';
  if (!params.signMessage && (!params.provider || family !== 'evm')) {
    return {
      proofToken: null,
      error: family === 'evm'
        ? 'Pass a provider (window.ethereum) or a signMessage callback'
        : `Pass a signMessage callback for ${family} wallets`,
    };
  }

  let challenge: { challengeId?: string; message?: string; error?: string };
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'challenge', wallet: params.address, family, domain }),
    });
    challenge = await res.json();
    if (!res.ok || !challenge.challengeId || !challenge.message) {
      return { proofToken: null, error: challenge.error ?? `Challenge failed (HTTP ${res.status})` };
    }
  } catch (err) {
    return {
      proofToken: null,
      error: err instanceof Error ? err.message : 'Network error reaching proof endpoint',
    };
  }

  let signature: string;
  try {
    if (params.signMessage) {
      const signed = await params.signMessage(challenge.message);
      signature = typeof signed === 'string' ? signed : toBase64(signed);
    } else {
      // personal_sign takes the message hex-encoded; wallets render the UTF-8.
      const hex =
        '0x' +
        Array.from(new TextEncoder().encode(challenge.message))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      signature = (await params.provider!.request({
        method: 'personal_sign',
        params: [hex, params.address],
      })) as string;
    }
  } catch (err) {
    return {
      proofToken: null,
      error: err instanceof Error ? err.message : 'Signature request was rejected',
    };
  }

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'prove',
        challengeId: challenge.challengeId,
        wallet: params.address,
        family,
        signature,
      }),
    });
    const data = await res.json();
    if (!res.ok || !data.proofToken) {
      return { proofToken: null, error: data.error ?? `Proof failed (HTTP ${res.status})` };
    }
    return { proofToken: data.proofToken, expiresInSec: data.expiresInSec };
  } catch (err) {
    return {
      proofToken: null,
      error: err instanceof Error ? err.message : 'Network error reaching proof endpoint',
    };
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return typeof btoa === 'function' ? btoa(binary) : Buffer.from(bytes).toString('base64');
}

// ── validateContentToken ─────────────────────────────────────────────────

const jwksByUrl = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(url: string) {
  let jwks = jwksByUrl.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url));
    jwksByUrl.set(url, jwks);
  }
  return jwks;
}

// What each EAS template resolves to in the signed condition. Public: served by
// GET https://api.insumermodel.com/v1/compliance/templates. A template not listed
// here never matches, so an unknown or misspelled name fails closed.
const EAS_TEMPLATES: Record<string, Record<string, string | number>> = {
  coinbase_verified_account: { chainId: 8453, schemaId: '0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9', attester: '0x357458739F90461b99789350868CD7CF330Dd7EE' },
  coinbase_verified_country: { chainId: 8453, schemaId: '0x1801901fabd0e6189356b4fb52bb0ab855276d84f7ec140839fbd1f6801ca065', attester: '0x357458739F90461b99789350868CD7CF330Dd7EE' },
  coinbase_one: { chainId: 8453, schemaId: '0x254bd1b63e0591fefa66818ca054c78627306f253f86be6023725a67ee6bf9f4', attester: '0x357458739F90461b99789350868CD7CF330Dd7EE' },
  // The decoder method decides what "met" means (isHuman = score >= 20, getScore = any score),
  // so it must be signed for the two Gitcoin templates to be told apart.
  gitcoin_passport_score: { chainId: 10, decoder: '0x5558D441779Eca04A329BcD6b47830D2C6607769', decoderMethod: 'isHuman' },
  gitcoin_passport_active: { chainId: 10, decoder: '0x5558D441779Eca04A329BcD6b47830D2C6607769', decoderMethod: 'getScore' },
};

// Hex values (addresses, schema ids) compare case-insensitively; everything else exactly.
function sameValue(a: unknown, b: unknown): boolean {
  if (typeof a === 'string' && typeof b === 'string' && /^0x/i.test(a) && /^0x/i.test(b)) {
    return a.toLowerCase() === b.toLowerCase();
  }
  return a === b;
}

// A numeric chain id may be written as a number or a numeric string.
function sameChain(a: unknown, b: unknown): boolean {
  if (a === undefined || a === null || b === undefined || b === null) return false;
  return String(a).toLowerCase() === String(b).toLowerCase();
}

const NON_EVM_CHAINS: ReadonlySet<string> = new Set(['solana', 'xrpl', 'bitcoin', 'tron', 'stellar', 'sui']);

/** The wallet family a signed result was evaluated on, or null when it cannot be told. */
function resultFamily(result: any): WalletType | null {
  const signed = result?.evaluatedCondition;
  if (!signed || typeof signed !== 'object') return null;
  const c = signed.chainId;
  if (typeof c === 'number' && Number.isInteger(c) && c > 0) return 'evm';
  if (typeof c === 'string') {
    if (/^[1-9][0-9]*$/.test(c)) return 'evm';
    const name = c.toLowerCase();
    return NON_EVM_CHAINS.has(name) ? (name as WalletType) : null;
  }
  // A Farcaster identity is read for an EVM address; it is the only type signed without a chain.
  if (c === undefined && signed.type === 'farcaster_id') return 'evm';
  return null;
}

/** EVM and Sui addresses are hex, so case does not matter. The rest are case-sensitive. */
function sameWallet(a: unknown, b: string, family: WalletType): boolean {
  if (typeof a !== 'string' || !a || !b) return false;
  if (family === 'evm' || family === 'sui') return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

/**
 * Is this JWT about the wallet the caller proved, and only that wallet? `sub` names one wallet,
 * so a token that also evaluated another family's wallet is not bound to it.
 */
function boundToWallet(payload: JWTPayload & { results?: unknown[] }, expected: { address: string; walletType?: WalletType }): string | null {
  const family: WalletType = expected.walletType ?? 'evm';
  if (!Object.prototype.hasOwnProperty.call(WALLET_FIELD, family)) return `expectedWallet.walletType is not a wallet type: ${String(family)}`;
  if (typeof expected.address !== 'string' || !expected.address.trim()) return 'expectedWallet.address is empty';
  if (!sameWallet(payload.sub, expected.address.trim(), family)) return 'JWT is about a different wallet than the one this session proved';
  const results = Array.isArray(payload.results) ? payload.results : [];
  if (results.length === 0) return 'JWT carries no signed results';
  for (const r of results) {
    if (resultFamily(r) !== family) return 'JWT evaluates a wallet outside the proven wallet\'s chain family';
  }
  return null;
}

const nfc = (v: unknown) => (typeof v === 'string' ? v.normalize('NFC') : v);

/**
 * Does one signed result (`results[i]` of the JWT) satisfy one expected condition?
 * Every key the caller set must be vouched for by what was signed; a key that is
 * never signed (other than `decimals`) cannot be confirmed, so it does not match.
 */
function matchesExpected(result: any, expected: Condition): boolean {
  const signed = result?.evaluatedCondition;
  if (!signed || typeof signed !== 'object') return false;
  for (const [key, value] of Object.entries(expected) as [string, unknown][]) {
    if (value === undefined) continue;
    switch (key) {
      case 'decimals':
        continue; // never signed on v2 keys; the token's own decimals are read from the chain
      case 'label':
        // The label is signed on the result, not inside the condition (NFC on v2 keys).
        if (typeof result.label !== 'string' || nfc(result.label) !== nfc(value)) return false;
        continue;
      case 'template': {
        // Own properties only: 'constructor', '__proto__' etc. are not templates.
        const t = typeof value === 'string' && Object.prototype.hasOwnProperty.call(EAS_TEMPLATES, value) ? EAS_TEMPLATES[value] : undefined;
        if (!t || signed.type !== 'eas_attestation') return false;
        for (const [f, v] of Object.entries(t)) {
          if (f === 'chainId' ? !sameChain(signed.chainId, v) : !sameValue(signed[f], v)) return false;
        }
        continue;
      }
      case 'chainId':
        if (!sameChain(signed.chainId, value)) return false;
        continue;
      case 'threshold':
        if (signed.type === 'nft_ownership') {
          // NFT ownership is signed as "more than 0 held" (threshold 0). It vouches for
          // "at least one", so only a threshold of 0 or 1 can be confirmed.
          const want = canonicalThreshold(value);
          if (want !== '0' && want !== '1') return false;
          continue;
        }
        {
          const a = canonicalThreshold(signed.threshold);
          if (a === null || a !== canonicalThreshold(value)) return false;
        }
        continue;
      default:
        if (!sameValue(signed[key], value)) return false;
    }
  }
  return true;
}

/**
 * Validate a JWT returned by {@link verifyConditions} on your server.
 *
 * Verifies the ECDSA P-256 signature against InsumerAPI's JWKS, checks the
 * issuer + expiry, and (optionally) confirms that the signed conditions match
 * what your route requires — preventing a JWT earned for one condition set
 * from being replayed against a different one.
 *
 * Important: a valid JWT with `pass: true` says a wallet meets the conditions. It does not
 * say the person presenting it controls that wallet, or that it came through the SkyeGate
 * proxy. Anyone can request one for any public wallet directly from InsumerAPI. Pass
 * `expectedWallet` (the wallet your own server-side sign-in proved) so a JWT about someone
 * else's wallet is refused.
 *
 * Caching: nothing here caches a verdict, so every call re-verifies the signature.
 * If you add a cache, key it on something only the person who passed could produce
 * (the JWT itself, or a session you issued them) — never on the wallet address or a
 * content id. Both are public, and a cache hit returns before this function runs, so
 * a cached "yes" filed under a public value hands out access without any signature
 * ever being checked.
 *
 * @example Next.js route handler
 * ```ts
 * import { validateContentToken } from '@skyemeta/skyegate';
 *
 * export async function POST(req: Request) {
 *   const { jwt, pqJwt } = await req.json();
 *   const session = await getSession(req); // your own sign-in, verified on the server
 *   const result = await validateContentToken(jwt, {
 *     pqJwt, // the post-quantum companion returned beside jwt; reported as result.pq
 *     expectedConditions: [{ type: 'farcaster_id' }],
 *     expectedWallet: { address: session.wallet },
 *   });
 *   if (!result.pass) {
 *     return Response.json({ error: result.error }, { status: 403 });
 *   }
 *   return Response.json({ secret: 'gated content here' });
 * }
 * ```
 */
export async function validateContentToken(
  jwt: string,
  options: ValidateContentTokenOptions = {}
): Promise<ValidateContentTokenResult> {
  if (!jwt || typeof jwt !== 'string') {
    return { valid: false, pass: false, error: 'Missing or invalid JWT' };
  }

  const jwksUrl = options.jwksUrl ?? DEFAULT_JWKS_URL;
  const issuer = options.issuer ?? DEFAULT_ISSUER;
  const kids = options.allowedKids ?? DEFAULT_ATTEST_KIDS;

  // A malformed cutoff is the caller's configuration error: report it on every call, not only
  // when the companion happens to be missing, and never as a thrown exception.
  if (options.pqRequiredFrom !== undefined && isNaN(new Date(options.pqRequiredFrom).getTime())) {
    return { valid: false, pass: false, error: `pqRequiredFrom is not a valid date: ${String(options.pqRequiredFrom)}` };
  }

  let payload: JWTPayload & { pass?: boolean; results?: unknown[] };
  try {
    const verified = await jwtVerify(jwt, getJwks(jwksUrl), { issuer, algorithms: ['ES256'] });
    if (!kids.includes(String(verified.protectedHeader.kid))) {
      return { valid: false, pass: false, error: `JWT is signed by "${String(verified.protectedHeader.kid)}", not an attestation key` };
    }
    payload = verified.payload as typeof payload;
  } catch (err) {
    return {
      valid: false,
      pass: false,
      error: err instanceof Error ? err.message : 'JWT verification failed',
    };
  }

  // Post-quantum companion: always reported, on every outcome below. Refuted always fails;
  // absent/unverifiable fail only past the caller's own pqRequiredFrom cutoff.
  const pq = await verifyPqCompanion(options.pqJwt as unknown, payload as Record<string, unknown>, jwksUrl);

  if (payload.pass !== true) {
    return { valid: true, pass: false, payload, pq, error: 'Verification did not pass' };
  }

  if (options.expectedWallet !== undefined) {
    const unbound = boundToWallet(payload, options.expectedWallet);
    if (unbound) return { valid: true, pass: false, payload, pq, error: unbound };
  }

  if (options.expectedConditions && options.expectedConditions.length > 0) {
    const signed = Array.isArray(payload.results) ? (payload.results as any[]) : [];
    const allMatched = options.expectedConditions.every((expected) =>
      signed.some(
        (r) =>
          r && typeof r === 'object' && matchesExpected(r, expected)
      )
    );
    if (!allMatched) {
      return {
        valid: true,
        pass: false,
        payload,
        pq,
        error: 'Signed conditions do not match expected conditions',
      };
    }
  }

  if (pqFails(pq, options.pqRequiredFrom)) {
    return {
      valid: true,
      pass: false,
      payload,
      pq,
      error: `Post-quantum companion ${pq.status}${pq.reason ? ` (${pq.reason})` : ''}`,
    };
  }

  return { valid: true, pass: true, payload, pq };
}
