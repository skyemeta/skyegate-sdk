# @skyemeta/skyegate

[![npm](https://img.shields.io/npm/v/@skyemeta/skyegate?color=0a1628&label=npm)](https://www.npmjs.com/package/@skyemeta/skyegate) [![license](https://img.shields.io/github/license/skyemeta/skyegate-sdk?color=0a1628)](LICENSE) [![release](https://img.shields.io/github/v/release/skyemeta/skyegate-sdk?color=0a1628)](https://github.com/skyemeta/skyegate-sdk/releases)

**SkyeGate Pro for Vercel.** Condition-based content gating for Next.js apps: wallet-verified access to pages, posts, files, or API routes. Gate on token balance, NFT ownership, EAS attestation, or Farcaster identity. Companion to the [SkyeGate WordPress plugin](https://skyemeta.com/skyegate/): same SKYE license key, same conditions, same proxy. **One license, two stacks.**

> **Powered by [InsumerAPI](https://insumermodel.com/developers/), the condition-based access API.** SkyeGate is a [Skye Meta](https://skyemeta.com) product; InsumerAPI is an independent product of [InsumerModel](https://insumermodel.com). Two companies: send a condition in, get a signed answer out.

```bash
npm install @skyemeta/skyegate
```

Bring your own wallet stack: wagmi, RainbowKit, ConnectKit, Privy, whatever your Next.js app already uses. This SDK only provides the gating layer.

## Quick start

Get a key:

- **[Annual, $350/yr](https://buy.stripe.com/8x26oA9F6eWAeAC7S804805)** (save 40%)
- [Monthly, $49/mo](https://buy.stripe.com/eVqbIU18A6q43VY7S804800)

Same key works on the [WordPress plugin](https://skyemeta.com/skyegate/) and this SDK: one license, two stacks. See [skyemeta.com/skyegate](https://skyemeta.com/skyegate/) for the comparison and FAQ.

### 1. Client: verify the wallet

```tsx
'use client';
import { useEffect, useState } from 'react';
import { useAccount, useSignMessage } from 'wagmi';
import { proveWalletOwnership } from '@skyemeta/skyegate';
import { GatedContent } from '@skyemeta/skyegate/react';

export default function Page() {
  const { address } = useAccount();
  const { signMessageAsync } = useSignMessage();

  // One free signature proves the visitor controls the address. The proxy
  // requires it for licensed EVM calls; the token covers the whole visit.
  const [proof, setProof] = useState<string>();
  useEffect(() => {
    let cancelled = false;
    setProof(undefined);
    if (!address) return;
    proveWalletOwnership({
      address,
      signMessage: (message) => signMessageAsync({ message }),
    }).then((r) => {
      if (cancelled) return;
      if (r.error) console.warn('wallet proof:', r.error);
      setProof(r.proofToken ?? undefined);
    });
    return () => { cancelled = true; };
  }, [address, signMessageAsync]);

  return (
    <GatedContent
      address={address}
      walletProof={proof}
      enabled={!!proof}
      conditions={[{ type: 'farcaster_id' }]}
      licenseKey={process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!}
      loading={<p>Verifying...</p>}
      fallback={<p>Connect a Farcaster-linked wallet to view this.</p>}
      onPass={async (jwt, pqJwt) => {
        const res = await fetch('/api/gated-content', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jwt, pqJwt }),
        });
        const { secret } = await res.json();
        // render `secret` somewhere
      }}
    >
      <p>Welcome, Farcaster user.</p>
    </GatedContent>
  );
}
```

### 2. Server: validate the JWT before serving gated content

```ts
// app/api/gated-content/route.ts
import { validateContentToken } from '@skyemeta/skyegate';

export async function POST(req: Request) {
  const { jwt, pqJwt } = await req.json();
  const result = await validateContentToken(jwt, {
    expectedConditions: [{ type: 'farcaster_id' }],
    pqJwt, // post-quantum companion; reported as result.pq, refuted always fails
  });
  if (!result.pass) {
    return Response.json({ error: result.error }, { status: 403 });
  }
  return Response.json({ secret: 'Real gated content here.' });
}
```

The browser only ever receives the gated content after the JWT clears server-side validation. The text isn't in the page source or the bundle; it's fetched only after a signed verification.

### If you cache the result, key it on the JWT

Nothing in this SDK caches a verdict. Every call to `validateContentToken` re-verifies the
signature, so a route that follows the example above is checking cryptographic proof on every
request. Caching that away is a reasonable optimisation, and it is where this goes wrong.

Key any cache on something only the person who passed could produce: the JWT itself, or a
session you issued them. **Never key it on the wallet address, and never on a content or
product id.** Both are public. A cached "yes" filed under a public value can be claimed by
anyone who knows it, and because a cache hit returns before your validation runs, the
signature you were relying on is never checked at all.

A wallet address feels like an identifier for a person. It isn't a secret. It's a name anyone
can read off a block explorer, and anyone can send you one.

## API

### `verifyConditions(params)` → `Promise<VerifyConditionsResult>`

Low-level imperative call. The React hook + component use this internally.

| Field | Type | Notes |
|---|---|---|
| `address` | `string` | Wallet address, in the format of its `walletType` |
| `conditions` | `Condition[]` | One or more conditions; `pass=true` requires *all* to be met |
| `licenseKey` | `string` | Your `SKYE-XXXX-XXXX-XXXX` key |
| `walletType` | `'evm'` \| `'solana'` \| `'xrpl'` \| `'bitcoin'` \| `'tron'` \| `'stellar'` \| `'sui'` | Default `'evm'`. Picks which request field carries the address |
| `endpoint` | `string` | Override the proxy URL (advanced) |
| `walletProof` | `string` | Proof token from `proveWalletOwnership`. **Required for licensed EVM calls**: the proxy rejects them with 403 `wallet_proof_required` without it. See **Wallet ownership** below |

Returns `{ pass, jwt, pqJwt, raw, error? }`. `error` is always a string, and is set only when no verdict came back (a refused request, a license problem, an outage); a signed "not met" is `pass: false` with no `error`. On `pass:true`, hand `jwt` and `pqJwt` (the post-quantum companion, when present) to your server endpoint and call `validateContentToken` there with `pqJwt` in the options.

### `proveWalletOwnership(params)` → `Promise<ProveWalletOwnershipResult>`

Proves the person present controls the wallet, not just that an address was supplied. Requests a one-time challenge, has the wallet sign it (EIP-191 `personal_sign`; free, gasless, no transaction), and exchanges the signature for a short-lived proof token. Smart-contract wallets (e.g. Coinbase Smart Wallet passkeys) are verified on-chain via EIP-1271/6492. The signature goes from the visitor's browser to the proof endpoint directly; it never passes through your server.

| Field | Type | Notes |
|---|---|---|
| `address` | `string` | The EVM wallet address to prove |
| `provider` | `Eip1193Provider` | e.g. `window.ethereum`; used to request the signature |
| `signMessage` | `(message: string) => Promise<string>` | BYO signer (wagmi `signMessageAsync`, viem wallet client, Privy); takes precedence over `provider` |
| `domain` | `string` | Defaults to `window.location.hostname` |
| `proofEndpoint` | `string` | Override the proof URL (advanced) |

Returns `{ proofToken, expiresInSec?, error? }`. The token is session-scoped: prove once when the wallet connects, then pass it as `walletProof` to every `verifyConditions` call for the rest of the visit. EVM wallets only in this wave.

### `validateContentToken(jwt, options?)` → `Promise<ValidateContentTokenResult>`

Server-side JWT validation. Verifies the ECDSA P-256 signature against InsumerAPI's JWKS, checks issuer + expiry, and (optionally) confirms the signed conditions match what your route requires.

| Option | Type | Notes |
|---|---|---|
| `jwksUrl` | `string` | Default: InsumerAPI's public JWKS |
| `issuer` | `string` | Default: `https://api.insumermodel.com` |
| `expectedConditions` | `Condition[]` | Replay protection: pass the same conditions you gave `verifyConditions`, and each must match a signed result. `template` is checked through what it resolves to (an unknown template never matches), `label` against the signed label, `chainId` as a number or numeric string, addresses case-insensitively; `decimals` is ignored because it is never signed |
| `pqJwt` | `string` | The post-quantum companion returned beside `jwt`. Checked and reported as `pq` |
| `pqRequiredFrom` | `string \| Date` | Your own cutoff. A companion that is present and fails always rejects; an absent or unverifiable one rejects only once this date has passed, judged by your server's clock |

Returns `{ valid, pass, payload?, pq?, error? }`. Only treat the request as authorized when `pass === true`. `pq.status` is one of `verified`, `refuted`, `absent`, `unverifiable` and is reported on every outcome once the JWT itself verified. Install the optional peer `@noble/post-quantum` to verify companions; without it a present companion is reported `unverifiable`. The companion is bound to the JWT by the full claim set: every claim in the two tokens must match, compared as parsed JSON, so `verified` vouches for the `results` that `expectedConditions` is matched against, not only for `pass`.

### `useSkyeGate(options)` → `UseSkyeGateResult`

React hook. Same options as `verifyConditions` (including `walletProof`), plus `enabled?: boolean` to gate the call. Returns `{ status, pass, jwt, pqJwt, error, refetch }` where `status` cycles through `'idle' → 'verifying' → 'pass' | 'fail' | 'error'`.

### `<GatedContent />`

Declarative wrapper. Same options as the hook. Renders `children` only when the gate passes; renders `fallback` when the wallet does not meet the conditions; renders `loading` while verifying. Set `errorFallback` (a node, or `(error) => node`) to show something different when no verdict came back, such as an outage or a license problem; without it an error renders `fallback`, as before. Optional `onPass(jwt, pqJwt?)` callback fires once when the gate first passes; forward both tokens to your server.

## Condition types

Same vocabulary as the [SkyeGate Pro WordPress plugin](https://skyemeta.com/skyegate/) and [InsumerAPI](https://insumermodel.com/developers/). All four types are supported:

| Type | What it checks |
|---|---|
| `token_balance` | ERC-20 / SPL / native balance ≥ threshold on a chain |
| `nft_ownership` | Holds an NFT from a collection: an ERC-721 contract on EVM chains, or a verified collection address on Solana (one NFT's own address matches that NFT only) |
| `eas_attestation` | Ethereum Attestation Service templates (Coinbase Verified, Gitcoin Passport, …) |
| `farcaster_id` | Wallet linked to a Farcaster identity |

34 chains supported for gating, the same set as SkyeGate Pro: 31 EVM chains plus Solana, Sui and Tron. Set `walletType` to the wallet's chain family (`'evm'` covers all 31 EVM chains). Every one of them proves wallet ownership with `proveWalletOwnership`. XRP Ledger, Bitcoin and Stellar wallets cannot sign an ownership proof, so a licensed call naming one is refused. See [skyemeta.com/skyegate](https://skyemeta.com/skyegate/) for the full list.

Leave `decimals` out of your conditions: the token's own decimals are always read from the chain. An `nft_ownership` condition is evaluated and signed as "holds at least one", so `expectedConditions` confirms a threshold of `0` or `1` (or none) for it, and nothing higher.

## How it works

```
your Next.js app
  ↓ proveWalletOwnership(address, provider | signMessage)
  ↓
skyemeta.com/api/wallet-proof  ← one-time challenge; the wallet signs it
  ↓                              (EIP-191, free) and a session-scoped
  ↓                              proof token comes back
  ↓ verifyConditions(address, conditions, licenseKey, walletProof)
  ↓
skyemeta.com/api/verify   ← Skye Meta proxy validates SKYE key + domain
  ↓                         + the ownership proof for the address
  ↓
api.insumermodel.com      ← InsumerAPI returns a signed boolean; no balances leak
  ↓
JWT signed with ECDSA P-256
  ↓ POSTed to your server
  ↓
validateContentToken(jwt, { pqJwt }) ← jose + JWKS, signature + issuer + expiry + condition match
                                        + post-quantum companion (ML-DSA-65) reported as pq
  ↓
gated content delivered
```

Every result is cryptographically signed (ECDSA P-256 + JWKS) and independently verifiable by any third party. **Trust the math, not a company, including us.** The wallet's actual balances never reach your server or your customers; only the signed yes-or-no on whether the condition was met.

## Security notes

- **License key exposure.** `NEXT_PUBLIC_SKYE_LICENSE_KEY` is a public env var by design. The proxy auto-binds your key to your production domain on first use; subsequent calls from any other apex are rejected. To move a key to a different domain, use the self-serve **Move License to New Domain** flow at [skyemeta.com/account](https://skyemeta.com/account/).
- **Cross-condition replay protection.** Pass `expectedConditions` to `validateContentToken` to ensure a JWT earned for one route can't unlock another. This scopes a token to a condition; it does not bind it to whoever presents it. See **Wallet ownership** below.
- **Wallet ownership.** The address passed to `verifyConditions` is supplied by the caller. The JWT attests that *this address* meets the conditions, signed by InsumerAPI and verified against its JWKS. It does **not** attest that whoever presents the JWT controls that address, and `validateContentToken` does not bind the token to its presenter. Addresses meeting a given condition are public chain state. The proxy **requires** proof of control for licensed calls: call `proveWalletOwnership` after the wallet connects and pass the resulting token as `walletProof` to `verifyConditions`. The proxy verifies the wallet's signature over a one-time, domain-bound challenge before attesting: EIP-191 for EVM (EIP-1271/6492 for smart wallets), ed25519 for Solana, the personal-message signature for Sui (ed25519, secp256k1 or secp256r1 accounts), and `signMessageV2` for Tron. A licensed call without it is rejected (403 `wallet_proof_required`), and one naming an XRP Ledger, Bitcoin or Stellar wallet is rejected too (403 `wallet_proof_unsupported`). A proof minted on a dev host (localhost, `*.vercel.app`) only works on a dev host. Note the JWT itself remains a bearer token: `validateContentToken` still does not bind it to its presenter, so keep JWT handling server-side and treat short expiry as load-bearing. The JWT's `sub` is the wallet a condition evaluated; when a token's conditions span chain families it names only the first (EVM, then Solana, XRPL, Bitcoin, Tron, Stellar, Sui), and the other families' wallets are evaluated but not named. `expectedConditions` checks that each expected condition is among the signed ones, not that nothing else is. So if you bind a session on `sub`, also check that every entry in the token's `results` is on that wallet's chain family (`evaluatedCondition.chainId`), and treat a token that mixes families as not bound to that wallet.

  For a non-EVM wallet, pass `walletType` and a `signMessage` callback that returns the wallet's own signature:

  ```ts
  // Solana (Wallet Standard / Phantom): the 64 signature bytes
  const proof = await proveWalletOwnership({
    address: solanaAddress,
    walletType: 'solana',
    signMessage: async (m) => (await window.phantom.solana.signMessage(new TextEncoder().encode(m), 'utf8')).signature,
  });
  // Sui: the `signature` from sui:signPersonalMessage. Tron: tronWeb.trx.signMessageV2(m).
  ```
- **JWT freshness.** JWTs are short-lived; `validateContentToken` enforces the `exp` claim via `jose`. Each verification produces a fresh JWT.
- **Dev / preview hosts.** `localhost`, `127.0.0.1`, `*.vercel.app`, and `*.local` skip the domain bind. Handy for local dev and preview deploys, but means anyone with your key could test on `*.vercel.app`. Treat license keys as you would any per-domain credential.

## Comparison with `@skyemeta/skyegate` for WordPress

| | WordPress plugin | This SDK |
|---|---|---|
| Distribution | `downloads/skyegate-wordpress.zip` from skyemeta.com | npm |
| Stack | PHP + jQuery + minified vanilla JS | TypeScript / React |
| Wallet connect | Bundled (multi-wallet, EIP-6963, Phantom + MetaMask + Coinbase) | Bring your own (wagmi, RainbowKit, etc.) |
| License key | Same SKYE key | Same SKYE key |
| Conditions | All 4 types, up to 10 stacked | All 4 types, up to 10 stacked |
| Source | Closed (proprietary plugin) | Open (MIT) |

One license. Pick the channel that matches your stack.

## License

MIT
