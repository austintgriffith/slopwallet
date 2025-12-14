import { WebAuthnAuth } from "~~/utils/passkey";

/**
 * A single call in a transaction (matches SmartWallet.Call struct)
 */
export interface TransactionCall {
  target: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
}

/**
 * Source of where a pending transaction came from
 */
export type TransactionSource = "impersonator" | "walletconnect" | "manual";

/**
 * Status of a pending transaction
 */
export type PendingTransactionStatus = "pending" | "signing" | "signed" | "relaying" | "confirmed" | "failed";

/**
 * Metadata about the transaction source
 */
export interface TransactionSourceMeta {
  /** Name of the dApp (for WalletConnect/Impersonator) */
  appName?: string;
  /** URL of the dApp */
  appUrl?: string;
  /** Icon URL */
  appIcon?: string;
  /** WalletConnect topic (for responding to requests) */
  wcTopic?: string;
  /** WalletConnect request ID */
  wcRequestId?: number;
  /** EIP-5792 batch ID */
  batchId?: string;
}

/**
 * A pending transaction waiting to be signed
 */
export interface PendingTransaction {
  /** Unique identifier */
  id: string;
  /** Source of the transaction */
  source: TransactionSource;
  /** The calls to execute (single tx has one call, batch has multiple) */
  calls: TransactionCall[];
  /** Whether this is a batch transaction */
  isBatch: boolean;
  /** Current status */
  status: PendingTransactionStatus;
  /** When the transaction was added to queue */
  timestamp: number;
  /** Metadata about the source */
  sourceMeta?: TransactionSourceMeta;
  /** Error message if failed */
  error?: string;
}

/**
 * A signed transaction ready to be relayed
 */
export interface SignedTransaction {
  /** Reference to the original pending transaction ID */
  pendingTxId: string;
  /** The calls to execute */
  calls: TransactionCall[];
  /** Whether this is a batch transaction */
  isBatch: boolean;
  /** Passkey public key x-coordinate */
  qx: `0x${string}`;
  /** Passkey public key y-coordinate */
  qy: `0x${string}`;
  /** Signature deadline (unix timestamp) */
  deadline: bigint;
  /** WebAuthn authentication data */
  auth: WebAuthnAuth;
  /** When the transaction was signed */
  signedAt: number;
  /** Source metadata (preserved from pending tx) */
  sourceMeta?: TransactionSourceMeta;
}

/**
 * Helper to create a new pending transaction
 */
export function createPendingTransaction(
  source: TransactionSource,
  calls: TransactionCall[],
  sourceMeta?: TransactionSourceMeta,
): PendingTransaction {
  return {
    id: `${source}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    source,
    calls,
    isBatch: calls.length > 1,
    status: "pending",
    timestamp: Date.now(),
    sourceMeta,
  };
}
