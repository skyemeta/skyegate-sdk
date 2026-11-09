/**
 * React surface for @skyemeta/skyegate.
 *
 * Subpath import: `import { useSkyeGate, GatedContent } from '@skyemeta/skyegate/react'`.
 * React is a peer dependency — only import this entry point in a React app.
 */

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  verifyConditions,
  type Condition,
  type VerifyConditionsParams,
} from './index.js';

export type GateStatus = 'idle' | 'verifying' | 'pass' | 'fail' | 'error';

export interface UseSkyeGateOptions {
  /** Wallet address from your wallet stack (wagmi, RainbowKit, etc.). Null/undefined keeps the hook idle. */
  address: string | null | undefined;
  /** Conditions to verify — same shape as {@link Condition}. */
  conditions: Condition[];
  /** Your SKYE license key. Safe to expose as `NEXT_PUBLIC_SKYE_LICENSE_KEY` since the proxy enforces domain locking. */
  licenseKey: string;
  /** Wallet kind: `"evm"` (default), `"solana"`, `"xrpl"`, `"bitcoin"`, `"tron"`, `"stellar"` or `"sui"`. */
  walletType?: VerifyConditionsParams['walletType'];
  /** Override the verification endpoint. */
  endpoint?: string;
  /**
   * Wallet ownership proof token from `proveWalletOwnership` — proves the
   * visitor controls the address, not just that they supplied it. Required
   * for licensed EVM calls (the proxy rejects them without it).
   */
  walletProof?: string;
  /** Domain to claim for license-binding. Defaults to `window.location.hostname`. */
  domain?: string;
  /** When false, the hook stays idle and never calls the proxy. Default true. */
  enabled?: boolean;
}

export interface UseSkyeGateResult {
  status: GateStatus;
  pass: boolean;
  jwt: string | null;
  /** Post-quantum companion of `jwt` (compact JWS, ML-DSA-65), when the API returned one. Hand it to `validateContentToken` as `options.pqJwt`. */
  pqJwt: string | null;
  /** Skye Meta's receipt for `jwt`, when the proxy issued one. Send it to your server with the JWT. */
  receipt: string | null;
  error: string | null;
  /** Trigger a re-verification with the same parameters. */
  refetch: () => void;
}

/**
 * React hook that runs `verifyConditions` and tracks its lifecycle.
 *
 * Re-runs when `address`, `licenseKey`, `walletType`, `endpoint`, `domain`,
 * `walletProof`, `enabled`, or the serialized `conditions` change.
 */
export function useSkyeGate(options: UseSkyeGateOptions): UseSkyeGateResult {
  const [status, setStatus] = useState<GateStatus>('idle');
  const [jwt, setJwt] = useState<string | null>(null);
  const [pqJwt, setPqJwt] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const enabled = options.enabled !== false;
  const conditionsKey = useMemo(() => JSON.stringify(options.conditions), [options.conditions]);

  useEffect(() => {
    if (!enabled || !options.address) {
      setStatus('idle');
      setJwt(null);
      setPqJwt(null);
      setReceipt(null);
      setError(null);
      return;
    }

    let cancelled = false;
    setStatus('verifying');
    setJwt(null);
    setPqJwt(null);
    setError(null);

    verifyConditions({
      address: options.address,
      conditions: options.conditions,
      licenseKey: options.licenseKey,
      walletType: options.walletType,
      endpoint: options.endpoint,
      domain: options.domain,
      walletProof: options.walletProof,
    })
      .then((result) => {
        if (cancelled) return;
        setJwt(result.jwt);
        setPqJwt(result.pqJwt ?? null);
        setReceipt(result.receipt ?? null);
        if (result.pass) {
          setStatus('pass');
        } else if (result.error !== undefined) {
          // Any error, even one with no text, is "no verdict", never a "not met".
          setStatus('error');
          setError(result.error || 'Verification failed');
        } else {
          setStatus('fail');
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setStatus('error');
        setError(err instanceof Error ? err.message : 'Verification failed');
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    enabled,
    options.address,
    options.licenseKey,
    options.walletType,
    options.endpoint,
    options.domain,
    options.walletProof,
    conditionsKey,
    tick,
  ]);

  return {
    status,
    pass: status === 'pass',
    jwt,
    pqJwt,
    receipt,
    error,
    refetch: () => setTick((t) => t + 1),
  };
}

export interface GatedContentProps extends UseSkyeGateOptions {
  /** Rendered when the gate passes. */
  children: ReactNode;
  /** Rendered when the wallet does not meet the conditions (and, unless `errorFallback` is set, on an error). */
  fallback?: ReactNode;
  /**
   * Rendered when no verdict came back: the proxy or the API refused the request or could not be
   * reached, or the license was rejected. Pass a function to receive the error text. Defaults to
   * `fallback`, so an error and a "not met" look the same unless you set this.
   */
  errorFallback?: ReactNode | ((error: string) => ReactNode);
  /** Rendered while verifying. */
  loading?: ReactNode;
  /**
   * Called once when the gate first passes. POST `jwt`, `receipt` and `pqJwt` (the post-quantum
   * companion, when present) to your server and check them with `validateContentToken`.
   */
  onPass?: (jwt: string, pqJwt?: string, receipt?: string) => void;
}

/**
 * Declarative gate. Renders `children` only when the wallet meets the conditions.
 *
 * @example
 * ```tsx
 * import { GatedContent } from '@skyemeta/skyegate/react';
 * import { useAccount } from 'wagmi';
 *
 * export default function Page() {
 *   const { address } = useAccount();
 *   const { signMessageAsync } = useSignMessage();
 *   const [proof, setProof] = useState<string>();
 *   useEffect(() => {
 *     setProof(undefined);
 *     if (!address) return;
 *     proveWalletOwnership({ address, signMessage: (m) => signMessageAsync({ message: m }) })
 *       .then((r) => setProof(r.proofToken ?? undefined));
 *   }, [address, signMessageAsync]);
 *   return (
 *     <GatedContent
 *       address={address}
 *       walletProof={proof}
 *       enabled={!!proof}
 *       conditions={[{ type: 'farcaster_id' }]}
 *       licenseKey={process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!}
 *       loading={<p>Verifying...</p>}
 *       fallback={<p>Connect a Farcaster-linked wallet to see this.</p>}
 *     >
 *       <h2>Welcome, Farcaster user.</h2>
 *     </GatedContent>
 *   );
 * }
 * ```
 */
export function GatedContent(props: GatedContentProps) {
  const { children, fallback = null, errorFallback, loading = null, onPass, ...gateOptions } = props;
  const result = useSkyeGate(gateOptions);

  // Fire once per JWT, as documented. Inline `onPass` arrows get a new
  // identity every render; without the ref guard, a consumer that setStates
  // inside onPass re-renders, re-fires the effect, and loops.
  const firedForJwt = useRef<string | null>(null);
  useEffect(() => {
    if (result.status === 'pass' && result.jwt && onPass && firedForJwt.current !== result.jwt) {
      firedForJwt.current = result.jwt;
      onPass(result.jwt, result.pqJwt ?? undefined, result.receipt ?? undefined);
    }
  }, [result.status, result.jwt, result.pqJwt, result.receipt, onPass]);

  if (result.status === 'verifying') return <>{loading}</>;
  if (result.status === 'pass') return <>{children}</>;
  if (result.status === 'error' && errorFallback !== undefined) {
    return <>{typeof errorFallback === 'function' ? errorFallback(result.error ?? 'Verification failed') : errorFallback}</>;
  }
  return <>{fallback}</>;
}

export type { Condition };
