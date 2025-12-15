"use client";

import { useState } from "react";
import { Address } from "@scaffold-ui/components";
import { formatEther } from "viem";
import { useAccount, useChainId, useConfig, usePublicClient, useWriteContract } from "wagmi";
import { readContract } from "wagmi/actions";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import {
  PendingTransaction,
  PendingTransactionStatus,
  SignedTransaction,
  TransactionCall,
} from "~~/types/pendingTransaction";
import {
  StoredPasskey,
  WebAuthnAuth,
  buildBatchChallengeHash,
  buildChallengeHash,
  signWithPasskey,
} from "~~/utils/passkey";

// Facilitate API response type
interface FacilitateResponse {
  success?: boolean;
  txHash?: string;
  blockNumber?: string;
  gasUsed?: string;
  error?: string;
  details?: string;
}

interface PendingTransactionQueueProps {
  smartWalletAddress: string;
  pendingTransactions: PendingTransaction[];
  signedTransactions: SignedTransaction[];
  currentPasskey: StoredPasskey | null;
  isPasskeyRegistered: boolean;
  passkeyNonce: bigint | undefined;
  onUpdatePendingStatus: (id: string, status: PendingTransactionStatus, error?: string) => void;
  onRemovePending: (id: string) => void;
  onAddSigned: (signedTx: SignedTransaction) => void;
  onRemoveSigned: (pendingTxId: string) => void;
  refetchPasskeyNonce: () => Promise<void>;
}

export const PendingTransactionQueue = ({
  smartWalletAddress,
  pendingTransactions,
  signedTransactions,
  currentPasskey,
  isPasskeyRegistered,
  passkeyNonce,
  onUpdatePendingStatus,
  onRemovePending,
  onAddSigned,
  onRemoveSigned,
  refetchPasskeyNonce,
}: PendingTransactionQueueProps) => {
  const chainId = useChainId();
  const config = useConfig();
  const { address: connectedAddress } = useAccount();
  const publicClient = usePublicClient();
  const { writeContractAsync } = useWriteContract();

  // Track which transactions are being processed
  const [signingIds, setSigningIds] = useState<Set<string>>(new Set());
  const [relayingIds, setRelayingIds] = useState<Set<string>>(new Set());
  const [facilitatingIds, setFacilitatingIds] = useState<Set<string>>(new Set());
  const [confirmedTxHashes, setConfirmedTxHashes] = useState<Record<string, string>>({});

  const canSign = currentPasskey && isPasskeyRegistered && passkeyNonce !== undefined;

  // Submit signed transaction to facilitator API
  const submitToFacilitator = async (pendingTxId: string, signedTx: SignedTransaction): Promise<FacilitateResponse> => {
    const response = await fetch("/api/facilitate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        smartWalletAddress,
        chainId,
        isBatch: signedTx.isBatch,
        calls: signedTx.calls.map(c => ({
          target: c.target,
          value: c.value.toString(),
          data: c.data,
        })),
        qx: signedTx.qx,
        qy: signedTx.qy,
        deadline: signedTx.deadline.toString(),
        auth: {
          r: signedTx.auth.r,
          s: signedTx.auth.s,
          challengeIndex: signedTx.auth.challengeIndex.toString(),
          typeIndex: signedTx.auth.typeIndex.toString(),
          authenticatorData: signedTx.auth.authenticatorData,
          clientDataJSON: signedTx.auth.clientDataJSON,
        },
      }),
    });

    const data: FacilitateResponse = await response.json();
    return data;
  };

  // Sign a pending transaction with passkey and auto-submit to facilitator
  const handleSign = async (pendingTx: PendingTransaction) => {
    if (!currentPasskey) return;

    setSigningIds(prev => new Set(prev).add(pendingTx.id));
    onUpdatePendingStatus(pendingTx.id, "signing");

    try {
      // IMPORTANT: Always fetch fresh nonce directly from chain before signing
      // This prevents stale nonce issues when signing multiple transactions in sequence
      const freshNonce = await readContract(config, {
        address: smartWalletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "nonces",
        args: [currentPasskey.passkeyAddress],
      });

      console.log("Signing with fresh nonce:", freshNonce);

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

      let auth: WebAuthnAuth;

      if (pendingTx.isBatch) {
        // Build batch challenge hash
        const challengeHash = buildBatchChallengeHash(
          BigInt(chainId),
          smartWalletAddress as `0x${string}`,
          pendingTx.calls,
          freshNonce,
          deadline,
        );

        const challengeBytes = new Uint8Array(
          (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
        );

        const result = await signWithPasskey(currentPasskey.credentialId, challengeBytes);
        auth = result.auth;
      } else {
        // Build single transaction challenge hash
        const call = pendingTx.calls[0];
        const challengeHash = buildChallengeHash(
          BigInt(chainId),
          smartWalletAddress as `0x${string}`,
          call.target,
          call.value,
          call.data,
          freshNonce,
          deadline,
        );

        const challengeBytes = new Uint8Array(
          (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
        );

        const result = await signWithPasskey(currentPasskey.credentialId, challengeBytes);
        auth = result.auth;
      }

      // Create signed transaction
      const signedTx: SignedTransaction = {
        pendingTxId: pendingTx.id,
        calls: pendingTx.calls,
        isBatch: pendingTx.isBatch,
        qx: currentPasskey.qx,
        qy: currentPasskey.qy,
        deadline,
        auth,
        signedAt: Date.now(),
        sourceMeta: pendingTx.sourceMeta,
      };

      // Update status to signed
      setSigningIds(prev => {
        const next = new Set(prev);
        next.delete(pendingTx.id);
        return next;
      });

      // Auto-submit to facilitator API
      setFacilitatingIds(prev => new Set(prev).add(pendingTx.id));
      onUpdatePendingStatus(pendingTx.id, "relaying"); // Use "relaying" status for facilitator submission

      console.log("[Facilitate] Submitting signed transaction to API...");

      const facilitateResult = await submitToFacilitator(pendingTx.id, signedTx);

      if (facilitateResult.success && facilitateResult.txHash) {
        console.log("[Facilitate] Transaction confirmed:", facilitateResult.txHash);

        // Store the confirmed tx hash for display
        setConfirmedTxHashes(prev => ({
          ...prev,
          [pendingTx.id]: facilitateResult.txHash!,
        }));

        onUpdatePendingStatus(pendingTx.id, "confirmed");

        // Refetch nonce for next transaction
        await refetchPasskeyNonce();

        // Auto-remove after a short delay to show confirmation
        setTimeout(() => {
          onRemovePending(pendingTx.id);
          setConfirmedTxHashes(prev => {
            const next = { ...prev };
            delete next[pendingTx.id];
            return next;
          });
        }, 5000);
      } else {
        // Facilitator failed - show error but keep the signed tx for manual relay
        const errorMsg = facilitateResult.error || "Facilitator submission failed";
        console.error("[Facilitate] Failed:", errorMsg, facilitateResult.details);

        // Add to signed transactions so user can manually relay
        onUpdatePendingStatus(pendingTx.id, "signed");
        onAddSigned(signedTx);
      }
    } catch (error) {
      console.error("Failed to sign transaction:", error);
      onUpdatePendingStatus(pendingTx.id, "failed", error instanceof Error ? error.message : "Failed to sign");
    } finally {
      setSigningIds(prev => {
        const next = new Set(prev);
        next.delete(pendingTx.id);
        return next;
      });
      setFacilitatingIds(prev => {
        const next = new Set(prev);
        next.delete(pendingTx.id);
        return next;
      });
    }
  };

  // Relay a signed transaction
  const handleRelay = async (signedTx: SignedTransaction) => {
    setRelayingIds(prev => new Set(prev).add(signedTx.pendingTxId));
    onUpdatePendingStatus(signedTx.pendingTxId, "relaying");

    try {
      let txHash: string;

      if (signedTx.isBatch) {
        // Relay batch transaction via metaBatchExecPasskey
        // Map calls to ensure proper typing for the ABI
        const callsForAbi = signedTx.calls.map(c => ({
          target: c.target,
          value: c.value,
          data: c.data,
        }));

        txHash = await writeContractAsync({
          address: smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "metaBatchExecPasskey",
          args: [
            callsForAbi,
            signedTx.qx,
            signedTx.qy,
            signedTx.deadline,
            {
              r: signedTx.auth.r,
              s: signedTx.auth.s,
              challengeIndex: signedTx.auth.challengeIndex,
              typeIndex: signedTx.auth.typeIndex,
              authenticatorData: signedTx.auth.authenticatorData,
              clientDataJSON: signedTx.auth.clientDataJSON,
            },
          ],
        });
      } else {
        // Relay single transaction via metaExecPasskey
        const call = signedTx.calls[0];
        txHash = await writeContractAsync({
          address: smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "metaExecPasskey",
          args: [
            call.target,
            call.value,
            call.data,
            signedTx.qx,
            signedTx.qy,
            signedTx.deadline,
            {
              r: signedTx.auth.r,
              s: signedTx.auth.s,
              challengeIndex: signedTx.auth.challengeIndex,
              typeIndex: signedTx.auth.typeIndex,
              authenticatorData: signedTx.auth.authenticatorData,
              clientDataJSON: signedTx.auth.clientDataJSON,
            },
          ],
        });
      }

      console.log("Transaction relayed:", txHash);

      // Wait for confirmation
      if (publicClient) {
        await publicClient.waitForTransactionReceipt({
          hash: txHash as `0x${string}`,
        });
      }

      onUpdatePendingStatus(signedTx.pendingTxId, "confirmed");
      onRemoveSigned(signedTx.pendingTxId);
      onRemovePending(signedTx.pendingTxId);

      // Refetch nonce for next transaction
      await refetchPasskeyNonce();
    } catch (error) {
      console.error("Failed to relay transaction:", error);
      onUpdatePendingStatus(signedTx.pendingTxId, "failed", error instanceof Error ? error.message : "Failed to relay");
    } finally {
      setRelayingIds(prev => {
        const next = new Set(prev);
        next.delete(signedTx.pendingTxId);
        return next;
      });
    }
  };

  // Get signed transaction for a pending transaction
  const getSignedTx = (pendingTxId: string): SignedTransaction | undefined => {
    return signedTransactions.find(st => st.pendingTxId === pendingTxId);
  };

  // Get source label
  const getSourceLabel = (source: string): string => {
    switch (source) {
      case "impersonator":
        return "Impersonator";
      case "walletconnect":
        return "WalletConnect";
      case "manual":
        return "Manual";
      default:
        return source;
    }
  };

  // Get status badge
  const getStatusBadge = (status: PendingTransactionStatus) => {
    switch (status) {
      case "pending":
        return <span className="badge badge-warning">Pending</span>;
      case "signing":
        return <span className="badge badge-info">Signing...</span>;
      case "signed":
        return <span className="badge badge-success">Signed</span>;
      case "relaying":
        return <span className="badge badge-info">Relaying...</span>;
      case "confirmed":
        return <span className="badge badge-success">Confirmed</span>;
      case "failed":
        return <span className="badge badge-error">Failed</span>;
      default:
        return <span className="badge badge-ghost">{status}</span>;
    }
  };

  const hasPendingOrSigned = pendingTransactions.length > 0;

  if (!hasPendingOrSigned) {
    return null; // Don't render if no transactions
  }

  return (
    <div className="bg-base-200 rounded-3xl p-6 mb-8">
      <h2 className="text-2xl font-semibold mb-4">Pending Transactions</h2>
      <p className="text-sm opacity-60 mb-4">
        Transactions waiting to be signed with your passkey. Anyone can relay signed transactions.
      </p>

      {/* Passkey status warning */}
      {!canSign && (
        <div className="bg-warning/10 border border-warning rounded-xl p-4 mb-4">
          <p className="text-warning text-sm">
            {!currentPasskey
              ? "Login with a passkey to sign transactions"
              : !isPasskeyRegistered
                ? "Add your passkey to this wallet to sign transactions"
                : "Loading nonce..."}
          </p>
        </div>
      )}

      {/* Transaction List */}
      <div className="space-y-4">
        {pendingTransactions.map(pendingTx => {
          const signedTx = getSignedTx(pendingTx.id);
          const isSigning = signingIds.has(pendingTx.id);
          const isRelaying = relayingIds.has(pendingTx.id);
          const isFacilitating = facilitatingIds.has(pendingTx.id);
          const confirmedTxHash = confirmedTxHashes[pendingTx.id];

          return (
            <div key={pendingTx.id} className="bg-base-100 rounded-xl p-4 space-y-4">
              {/* Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="badge badge-outline">{getSourceLabel(pendingTx.source)}</span>
                  {pendingTx.sourceMeta?.appName && (
                    <span className="text-sm font-medium">{pendingTx.sourceMeta.appName}</span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {getStatusBadge(pendingTx.status)}
                  <button
                    className="btn btn-ghost btn-xs"
                    onClick={() => {
                      onRemoveSigned(pendingTx.id);
                      onRemovePending(pendingTx.id);
                    }}
                    disabled={isSigning || isRelaying || isFacilitating}
                  >
                    Dismiss
                  </button>
                </div>
              </div>

              {/* Error Display */}
              {pendingTx.error && (
                <div className="bg-error/10 border border-error rounded-lg p-3">
                  <p className="text-error text-sm">{pendingTx.error}</p>
                </div>
              )}

              {/* Transaction Details */}
              <div className="space-y-3">
                {pendingTx.isBatch ? (
                  // Batch transaction display
                  <>
                    <p className="text-sm opacity-60">{pendingTx.calls.length} calls in batch</p>
                    {pendingTx.calls.map((call, index) => (
                      <CallDetails key={index} call={call} index={index} isBatch={true} />
                    ))}
                  </>
                ) : (
                  // Single transaction display
                  <CallDetails call={pendingTx.calls[0]} index={0} isBatch={false} />
                )}
              </div>

              {/* Confirmed Transaction Display */}
              {pendingTx.status === "confirmed" && confirmedTxHash && (
                <div className="bg-success/10 border border-success rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-success text-lg">✓</span>
                    <span className="text-success font-medium">Transaction Confirmed!</span>
                  </div>
                  <div className="text-sm opacity-70">
                    <span>Tx: </span>
                    <a
                      href={`https://basescan.org/tx/${confirmedTxHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="link link-primary font-mono text-xs"
                    >
                      {confirmedTxHash.slice(0, 10)}...{confirmedTxHash.slice(-8)}
                    </a>
                  </div>
                </div>
              )}

              {/* Facilitating Status */}
              {isFacilitating && (
                <div className="bg-info/10 border border-info rounded-lg p-4">
                  <div className="flex items-center gap-3">
                    <span className="loading loading-spinner loading-md text-info"></span>
                    <div>
                      <p className="text-info font-medium">Transaction is being processed...</p>
                      <p className="text-xs opacity-70">Waiting for on-chain confirmation</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Actions */}
              {pendingTx.status === "pending" && !signedTx && !isFacilitating && (
                <button
                  className="btn btn-primary w-full"
                  onClick={() => handleSign(pendingTx)}
                  disabled={!canSign || isSigning || isFacilitating}
                >
                  {isSigning ? (
                    <>
                      <span className="loading loading-spinner loading-sm"></span>
                      Signing...
                    </>
                  ) : (
                    "Sign with Passkey"
                  )}
                </button>
              )}

              {/* Signed Transaction Ready for Relay (fallback if facilitator fails) */}
              {signedTx && pendingTx.status === "signed" && !isFacilitating && (
                <div className="space-y-3">
                  <div className="bg-warning/10 border border-warning rounded-lg p-3">
                    <p className="text-warning text-sm font-medium">Facilitator unavailable - Manual relay required</p>
                    <p className="text-xs opacity-70 mt-1">
                      Expires: {new Date(Number(signedTx.deadline) * 1000).toLocaleString()}
                    </p>
                  </div>

                  {/* Copy JSON */}
                  <details className="collapse collapse-arrow bg-base-200">
                    <summary className="collapse-title text-sm font-medium">View/Copy Signed Transaction</summary>
                    <div className="collapse-content">
                      <pre className="text-xs font-mono bg-base-300 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(
                          {
                            isBatch: signedTx.isBatch,
                            calls: signedTx.calls.map(c => ({
                              target: c.target,
                              value: c.value.toString(),
                              data: c.data,
                            })),
                            qx: signedTx.qx,
                            qy: signedTx.qy,
                            deadline: signedTx.deadline.toString(),
                            auth: {
                              r: signedTx.auth.r,
                              s: signedTx.auth.s,
                              challengeIndex: signedTx.auth.challengeIndex.toString(),
                              typeIndex: signedTx.auth.typeIndex.toString(),
                              authenticatorData: signedTx.auth.authenticatorData,
                              clientDataJSON: signedTx.auth.clientDataJSON,
                            },
                          },
                          null,
                          2,
                        )}
                      </pre>
                      <button
                        className="btn btn-xs btn-ghost mt-2"
                        onClick={() => {
                          navigator.clipboard.writeText(
                            JSON.stringify({
                              isBatch: signedTx.isBatch,
                              calls: signedTx.calls.map(c => ({
                                target: c.target,
                                value: c.value.toString(),
                                data: c.data,
                              })),
                              qx: signedTx.qx,
                              qy: signedTx.qy,
                              deadline: signedTx.deadline.toString(),
                              auth: {
                                r: signedTx.auth.r,
                                s: signedTx.auth.s,
                                challengeIndex: signedTx.auth.challengeIndex.toString(),
                                typeIndex: signedTx.auth.typeIndex.toString(),
                                authenticatorData: signedTx.auth.authenticatorData,
                                clientDataJSON: signedTx.auth.clientDataJSON,
                              },
                            }),
                          );
                        }}
                      >
                        Copy to clipboard
                      </button>
                    </div>
                  </details>

                  <div className="divider text-xs opacity-60 my-2">Anyone can relay</div>

                  <button
                    className="btn btn-secondary w-full"
                    onClick={() => handleRelay(signedTx)}
                    disabled={isRelaying || !connectedAddress}
                  >
                    {isRelaying ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Relaying...
                      </>
                    ) : connectedAddress ? (
                      "Relay Transaction (Pay Gas)"
                    ) : (
                      "Connect Wallet to Relay"
                    )}
                  </button>
                  <p className="text-xs text-center opacity-60">The relayer pays gas. The signer pays nothing.</p>
                </div>
              )}

              {/* Timestamp */}
              <p className="text-xs opacity-40">Added: {new Date(pendingTx.timestamp).toLocaleTimeString()}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Sub-component for displaying call details
const CallDetails = ({ call, index, isBatch }: { call: TransactionCall; index: number; isBatch: boolean }) => {
  const formatValue = (value: bigint): string => {
    if (value === 0n) return "0 ETH";
    return `${formatEther(value)} ETH`;
  };

  const getFunctionSelector = (data: string): string => {
    if (data.length >= 10) {
      return data.slice(0, 10);
    }
    return data;
  };

  return (
    <div className={`${isBatch ? "bg-base-200 rounded-lg p-3" : ""} space-y-2`}>
      {isBatch && <p className="text-xs font-medium opacity-60">Call {index + 1}</p>}

      {/* Target */}
      <div className="flex items-center gap-2">
        <span className="text-xs opacity-60 min-w-[50px]">To:</span>
        <Address address={call.target} />
      </div>

      {/* Value */}
      <div className="flex items-center gap-2">
        <span className="text-xs opacity-60 min-w-[50px]">Value:</span>
        <span className="font-mono text-sm">{formatValue(call.value)}</span>
      </div>

      {/* Function Selector */}
      {call.data && call.data !== "0x" && (
        <>
          <div className="flex items-center gap-2">
            <span className="text-xs opacity-60 min-w-[50px]">Selector:</span>
            <span className="font-mono text-sm">{getFunctionSelector(call.data)}</span>
          </div>

          {/* Calldata */}
          <div>
            <p className="text-xs opacity-60 mb-1">Data ({call.data.length} chars)</p>
            <div className="bg-base-300 rounded p-2 font-mono text-xs break-all max-h-24 overflow-y-auto">
              {call.data.length > 200 ? `${call.data.slice(0, 200)}...` : call.data}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
