# Changelog

## 0.5.0

Breaking: `validateContentToken` requires Skye Meta's receipt and the route's conditions.

A JWT with `pass: true` says a wallet meets the conditions, and anyone can request one for any
public wallet straight from InsumerAPI, without the Skye Meta proxy and without proving they
control that wallet. Before 0.5.0 such a JWT passed `validateContentToken`.

- The proxy now returns `receipt` beside the JWT when the call carried your license and an
  ownership proof for every wallet it named. It is signed by Skye Meta (keys at
  `https://skyemeta.com/.well-known/skyegate-jwks.json`), issued for your domain, names the JWT's
  wallet, and carries the hash of that exact JWT. It lives at most 5 minutes.
- `verifyConditions` returns `receipt`; `useSkyeGate` returns it; `<GatedContent onPass>` gets it
  as a third argument.
- `validateContentToken(jwt, options)` now requires `receipt` and `audience` (your domain), and
  `expectedConditions`. A missing or mismatched receipt is `pass: false` with the reason in
  `error`.
- Servers that prove the visitor's wallet themselves can pass `allowDirectAttestations: true`
  with `expectedWallet` instead of a receipt.

Upgrade: send `receipt` from the browser to your server with the JWT, and add `receipt`,
`audience` and `expectedConditions` to your `validateContentToken` call.

## 0.4.8

- `validateContentToken` takes `expectedWallet: { address, walletType? }`: the wallet your own
  server-side sign-in proved. The JWT must name that wallet as `sub`, and every signed result must
  be on its chain family, or `pass` is `false`. Strongly recommended: a JWT with `pass: true` can be
  requested for any public wallet directly from InsumerAPI, so without it a server cannot tell such
  a JWT from one its own visitor earned. Existing calls without the option behave as before.
- README and the Next.js example show the option with a session of your own.

## 0.4.7

- Documentation: `nft_ownership` checks ERC-721 and SPL NFT ownership. ERC-1155 is no longer listed.
  No code changes.

## 0.4.6

- `proveWalletOwnership` takes `walletType`: `'evm'` (default), `'solana'`, `'sui'` or `'tron'`. A
  non-EVM wallet signs the challenge through `signMessage`, which may return the wallet's own format:
  a `Uint8Array` or base64 string for Solana, the `signature` string for Sui, the hex string for Tron.
- Documentation: which wallets prove ownership, and that XRP Ledger, Bitcoin and Stellar wallets are
  refused by a licensed gate.

## 0.4.5

- `validateContentToken` matches `expectedConditions` against the whole signed result. The EAS
  `template` shorthand (`coinbase_verified_account`, `coinbase_verified_country`, `coinbase_one`,
  `gitcoin_passport_score`, `gitcoin_passport_active`) is checked through what it resolves to, and an
  unknown template never matches. `label` is compared with the signed label (NFC), `chainId` accepts a
  number or numeric string, addresses compare case-insensitively, and `decimals` is ignored because it
  is never signed. An `nft_ownership` expectation matches the signed "holds at least one". Conditions
  written exactly as documented now pass.
- The Gitcoin templates are told apart by their signed decoder method; a verdict that does not carry
  one does not match either template.
- The post-quantum companion loads under Next.js (webpack and Turbopack) and Vite: the optional
  `@noble/post-quantum` import is left to the runtime instead of being replaced by the bundler.
- The companion must be signed by the attestation key (`insumer-attest-pq1`); a companion under any
  other key is refuted. A malformed companion (a JSON `null` header, a non-string value) is reported
  as refuted instead of throwing.
- `verifyConditions` always returns `error` as a string, including the `{ code, message }` errors the
  API passes through. A response that carries no signed verdict is an error, never a "not met".
- `validateContentToken` accepts only InsumerAPI's attestation signing keys for the JWT (`insumer-attest-v1`,
  `insumer-attest-v2`; override with `allowedKids`), and reports an invalid `pqRequiredFrom` as an error on every
  call instead of throwing. A "pass" that arrives without a token is treated as no verdict.
- `walletType` adds `'xrpl'`, `'bitcoin'`, `'tron'`, `'stellar'` and `'sui'`.
- `<GatedContent>` takes an optional `errorFallback`, so an outage or license problem can look
  different from "not met". Without it, behaviour is unchanged.
- Documentation: leave `decimals` out; what `expectedConditions` checks; the chain families.
