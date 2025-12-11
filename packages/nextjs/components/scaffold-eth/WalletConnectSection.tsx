"use client";

import { useState } from "react";
import Image from "next/image";
import { Address } from "@scaffold-ui/components";
import { formatEther } from "viem";
import { useAccount, usePublicClient, useWalletClient, useWriteContract } from "wagmi";
import { QrScannerModal } from "~~/components/scaffold-eth/QrScannerModal";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import {
  ActiveSession,
  BatchCallStatus,
  SessionRequest,
  useWalletConnect,
} from "~~/hooks/scaffold-eth/useWalletConnect";

interface WalletConnectSectionProps {
  smartWalletAddress: string;
}

export const WalletConnectSection = ({ smartWalletAddress }: WalletConnectSectionProps) => {
  const [wcUri, setWcUri] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  // Get wallet client and owner address for signing
  const { address: ownerAddress } = useAccount();
  const { data: walletClient } = useWalletClient();

  const {
    status,
    error,
    pair,
    disconnect,
    disconnectAll,
    sessionRequests,
    activeSessions,
    clearRequest,
    approveRequest,
    rejectRequest,
    updateBatchStatus,
    isReady,
  } = useWalletConnect({
    smartWalletAddress,
    walletClient,
    ownerAddress,
    enabled: true,
  });

  const handlePaste = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setWcUri(value);

    // Auto-connect when a valid WC URI is pasted
    if (value.startsWith("wc:")) {
      await pair(value);
      setWcUri(""); // Clear input after pairing
    }
  };

  const handleConnect = async () => {
    if (wcUri.startsWith("wc:")) {
      await pair(wcUri);
      setWcUri("");
    }
  };

  const handleScan = async (scannedUri: string) => {
    setWcUri(scannedUri);
    // Auto-connect after scanning
    await pair(scannedUri);
    setWcUri("");
  };

  const getStatusBadge = () => {
    switch (status) {
      case "initializing":
        return <span className="badge badge-warning">Initializing...</span>;
      case "ready":
        return <span className="badge badge-info">Ready</span>;
      case "pairing":
        return <span className="badge badge-warning">Connecting...</span>;
      case "connected":
        return <span className="badge badge-success">Connected</span>;
      case "error":
        return <span className="badge badge-error">Error</span>;
      default:
        return <span className="badge badge-ghost">Idle</span>;
    }
  };

  return (
    <div className="bg-base-200 rounded-3xl p-6 mt-8">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-semibold">WalletConnect</h2>
        {getStatusBadge()}
      </div>
      <p className="text-sm opacity-60 mb-4">Connect to dApps using WalletConnect. Paste a WC URI to connect.</p>

      {/* Error Display */}
      {error && (
        <div className="alert alert-error mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* URI Input */}
      <div className="bg-base-100 rounded-xl p-4 mb-4">
        <p className="text-sm font-medium opacity-60 mb-2">WalletConnect URI</p>
        <div className="flex gap-2">
          <input
            type="text"
            className="input input-bordered flex-1"
            placeholder="wc:..."
            value={wcUri}
            onChange={handlePaste}
            disabled={!isReady}
          />
          <button className="btn btn-secondary" onClick={() => setIsScanning(true)} disabled={!isReady}>
            📷 Scan
          </button>
          <button className="btn btn-primary" onClick={handleConnect} disabled={!isReady || !wcUri.startsWith("wc:")}>
            {status === "pairing" ? <span className="loading loading-spinner loading-sm"></span> : "Connect"}
          </button>
        </div>
      </div>

      {/* QR Scanner Modal */}
      <QrScannerModal isOpen={isScanning} onClose={() => setIsScanning(false)} onScan={handleScan} />

      {/* Active Sessions */}
      {activeSessions.length > 0 && (
        <div className="bg-base-100 rounded-xl p-4 mb-4">
          <div className="flex items-center justify-between mb-3">
            <p className="text-sm font-medium opacity-60">Active Sessions</p>
            <button className="btn btn-ghost btn-xs text-error" onClick={disconnectAll}>
              Disconnect All
            </button>
          </div>
          <div className="space-y-2">
            {activeSessions.map(session => (
              <ActiveSessionCard key={session.topic} session={session} onDisconnect={() => disconnect(session.topic)} />
            ))}
          </div>
        </div>
      )}

      {/* Session Requests */}
      {sessionRequests.length > 0 && (
        <div className="bg-base-100 rounded-xl p-4">
          <p className="text-sm font-medium opacity-60 mb-3">Pending Requests ({sessionRequests.length})</p>
          <div className="space-y-4">
            {sessionRequests.map(request => (
              <SessionRequestCard
                key={request.id}
                request={request}
                smartWalletAddress={smartWalletAddress}
                onApprove={approveRequest}
                onReject={rejectRequest}
                onClear={() => clearRequest(request.id)}
                updateBatchStatus={updateBatchStatus}
              />
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {activeSessions.length === 0 && sessionRequests.length === 0 && isReady && (
        <div className="text-center opacity-60 py-4">
          <p>No active connections. Paste a WalletConnect URI to connect to a dApp.</p>
        </div>
      )}
    </div>
  );
};

// Active Session Card Component
const ActiveSessionCard = ({ session, onDisconnect }: { session: ActiveSession; onDisconnect: () => void }) => {
  return (
    <div className="flex items-center justify-between p-3 bg-base-200 rounded-lg">
      <div className="flex items-center gap-3">
        {session.peerMeta.icons?.[0] && (
          <Image
            src={session.peerMeta.icons[0]}
            alt={session.peerMeta.name}
            width={32}
            height={32}
            className="w-8 h-8 rounded-full"
            unoptimized
          />
        )}
        <div>
          <p className="font-medium">{session.peerMeta.name}</p>
          {session.peerMeta.url && <p className="text-xs opacity-60">{session.peerMeta.url}</p>}
        </div>
      </div>
      <button className="btn btn-ghost btn-sm text-error" onClick={onDisconnect}>
        Disconnect
      </button>
    </div>
  );
};

// Session Request Card Component
const SessionRequestCard = ({
  request,
  smartWalletAddress,
  onApprove,
  onReject,
  onClear,
  updateBatchStatus,
}: {
  request: SessionRequest;
  smartWalletAddress: string;
  onApprove: (requestId: number, topic: string, result: string) => Promise<void>;
  onReject: (requestId: number, topic: string) => Promise<void>;
  onClear: () => void;
  updateBatchStatus: (batchId: string, updates: Partial<BatchCallStatus>) => void;
}) => {
  const [isExecuting, setIsExecuting] = useState(false);
  const [txError, setTxError] = useState<string | null>(null);

  const { writeContractAsync } = useWriteContract();
  const publicClient = usePublicClient();

  const getMethodLabel = (method: string) => {
    switch (method) {
      case "eth_sendTransaction":
        return "Send Transaction";
      case "wallet_sendCalls":
        return "Batch Calls";
      default:
        return method;
    }
  };

  const formatValue = (value?: string) => {
    if (!value || value === "0x0" || value === "0x") return "0 ETH";
    try {
      return `${formatEther(BigInt(value))} ETH`;
    } catch {
      return value;
    }
  };

  const isTransaction = request.method === "eth_sendTransaction";
  const isBatchCall = request.method === "wallet_sendCalls";

  const handleExecute = async () => {
    if (!isTransaction && !isBatchCall) return;

    setIsExecuting(true);
    setTxError(null);

    try {
      let txHash: string;

      if (isBatchCall && request.calls && request.calls.length > 0) {
        // Handle wallet_sendCalls - use batchExec
        const calls = request.calls.map(call => ({
          target: (call.to || "0x0000000000000000000000000000000000000000") as `0x${string}`,
          value: call.value ? BigInt(call.value) : 0n,
          data: (call.data || "0x") as `0x${string}`,
        }));

        txHash = await writeContractAsync({
          address: smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "batchExec",
          args: [calls],
        });
      } else {
        // Handle single eth_sendTransaction - use exec
        const value = request.params.value ? BigInt(request.params.value) : 0n;
        const target = (request.params.to || "0x0000000000000000000000000000000000000000") as `0x${string}`;
        const data = (request.params.data || "0x") as `0x${string}`;

        txHash = await writeContractAsync({
          address: smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "exec",
          args: [target, value, data],
        });
      }

      console.log("Transaction sent:", txHash);

      // Handle EIP-5792 wallet_sendCalls differently
      if (isBatchCall && request.batchId) {
        if (!publicClient) {
          console.error("Public client not available, cannot fetch receipt");
          updateBatchStatus(request.batchId, {
            status: 500,
            txHash,
          });
          onClear();
          return;
        }

        try {
          const receipt = await publicClient.waitForTransactionReceipt({
            hash: txHash as `0x${string}`,
          });

          // Format receipt according to EIP-5792 spec
          const formattedReceipt = {
            logs: receipt.logs.map(log => ({
              address: log.address,
              data: log.data,
              topics: log.topics,
            })),
            status: receipt.status === "success" ? "0x1" : "0x0",
            blockHash: receipt.blockHash,
            blockNumber: `0x${receipt.blockNumber.toString(16)}`,
            gasUsed: `0x${receipt.gasUsed.toString(16)}`,
            transactionHash: receipt.transactionHash,
          };

          updateBatchStatus(request.batchId, {
            status: 200,
            txHash,
            receipts: [formattedReceipt],
          });

          console.log("✅ Batch transaction confirmed");
        } catch (receiptError) {
          console.error("Failed to get transaction receipt:", receiptError);
          updateBatchStatus(request.batchId, {
            status: 500,
            txHash,
          });
        }

        // Just remove the request from UI
        onClear();
      } else {
        // For regular eth_sendTransaction, send the transaction hash back to the dApp
        await onApprove(request.id, request.topic, txHash);
      }
    } catch (err) {
      console.error("Transaction failed:", err);
      setTxError(err instanceof Error ? err.message : "Transaction failed");

      // Update batch status to failed if this is a wallet_sendCalls request
      if (isBatchCall && request.batchId) {
        updateBatchStatus(request.batchId, {
          status: 500, // Chain rules failure
        });
      }
    } finally {
      setIsExecuting(false);
    }
  };

  const handleReject = async () => {
    setIsExecuting(true);
    try {
      // Handle EIP-5792 wallet_sendCalls rejection
      if (isBatchCall && request.batchId) {
        updateBatchStatus(request.batchId, {
          status: 400, // User rejected
        });
        onClear();
      } else {
        await onReject(request.id, request.topic);
      }
    } catch (err) {
      console.error("Failed to reject:", err);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="border border-base-300 rounded-lg p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {request.peerMeta?.icons?.[0] && (
            <Image
              src={request.peerMeta.icons[0]}
              alt={request.peerMeta.name}
              width={24}
              height={24}
              className="w-6 h-6 rounded-full"
              unoptimized
            />
          )}
          <span className="font-medium">{request.peerMeta?.name || "Unknown dApp"}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="badge badge-primary">{getMethodLabel(request.method)}</span>
          <button className="btn btn-ghost btn-xs" onClick={onClear} disabled={isExecuting}>
            Clear
          </button>
        </div>
      </div>

      {/* Chain ID */}
      <div className="text-xs opacity-60 mb-3">Chain: {request.chainId}</div>

      {/* Transaction Details */}
      {isTransaction && (
        <div className="space-y-2 text-sm">
          {/* To Address */}
          {request.params.to && (
            <div className="flex items-center gap-2">
              <span className="opacity-60 min-w-[60px]">To:</span>
              <Address address={request.params.to as `0x${string}`} />
            </div>
          )}

          {/* Value */}
          <div className="flex items-center gap-2">
            <span className="opacity-60 min-w-[60px]">Value:</span>
            <span className="font-mono">{formatValue(request.params.value)}</span>
          </div>

          {/* Calldata */}
          {request.params.data && request.params.data !== "0x" && (
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="opacity-60 min-w-[60px]">Data:</span>
                <span className="badge badge-ghost badge-sm">
                  {request.params.data.length > 10 ? `${(request.params.data.length - 2) / 2} bytes` : "empty"}
                </span>
              </div>
              <div className="bg-base-300 rounded p-2 font-mono text-xs break-all max-h-32 overflow-y-auto">
                {request.params.data}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Batch Calls Details (wallet_sendCalls) */}
      {isBatchCall && request.calls && (
        <div className="space-y-3">
          <div className="text-sm opacity-60">{request.calls.length} call(s) in batch</div>
          {request.batchId && (
            <div className="bg-base-200 rounded p-2">
              <div className="text-xs opacity-60 mb-1">Batch ID (EIP-5792):</div>
              <div className="font-mono text-xs break-all">{request.batchId}</div>
            </div>
          )}
          {request.calls.map((call, index) => (
            <div key={index} className="bg-base-300 rounded-lg p-3 space-y-2 text-sm">
              <div className="font-medium opacity-70">Call {index + 1}</div>
              {/* To Address */}
              {call.to && (
                <div className="flex items-center gap-2">
                  <span className="opacity-60 min-w-[60px]">To:</span>
                  <Address address={call.to as `0x${string}`} />
                </div>
              )}
              {/* Value */}
              <div className="flex items-center gap-2">
                <span className="opacity-60 min-w-[60px]">Value:</span>
                <span className="font-mono">{formatValue(call.value)}</span>
              </div>
              {/* Calldata */}
              {call.data && call.data !== "0x" && (
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="opacity-60 min-w-[60px]">Data:</span>
                    <span className="badge badge-ghost badge-sm">
                      {call.data.length > 10 ? `${(call.data.length - 2) / 2} bytes` : "empty"}
                    </span>
                  </div>
                  <div className="bg-base-200 rounded p-2 font-mono text-xs break-all max-h-24 overflow-y-auto">
                    {call.data}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* For unknown/unsupported methods, show the raw params */}
      {!isTransaction && !isBatchCall && (
        <div className="bg-base-300 rounded p-2 font-mono text-xs break-all max-h-32 overflow-y-auto">
          {JSON.stringify(request.params, null, 2)}
        </div>
      )}

      {/* Exec Parameters Display */}
      {isTransaction && (
        <div className="mt-4 pt-3 border-t border-base-300">
          <p className="text-xs font-medium opacity-60 mb-2">Parameters for exec() function:</p>
          <div className="bg-base-300 rounded p-3 font-mono text-xs space-y-1">
            <div>
              <span className="opacity-60">target:</span> {request.params.to || "0x0"}
            </div>
            <div>
              <span className="opacity-60">value:</span> {request.params.value || "0x0"}
            </div>
            <div>
              <span className="opacity-60">data:</span> {request.params.data || "0x"}
            </div>
          </div>
        </div>
      )}

      {/* BatchExec Parameters Display */}
      {isBatchCall && request.calls && (
        <div className="mt-4 pt-3 border-t border-base-300">
          <p className="text-xs font-medium opacity-60 mb-2">Parameters for batchExec() function:</p>
          <div className="bg-base-300 rounded p-3 font-mono text-xs space-y-2 max-h-48 overflow-y-auto">
            {request.calls.map((call, index) => (
              <div key={index} className="border-b border-base-200 pb-2 last:border-b-0 last:pb-0">
                <div className="opacity-60 mb-1">calls[{index}]:</div>
                <div className="pl-2 space-y-1">
                  <div>
                    <span className="opacity-60">target:</span> {call.to || "0x0"}
                  </div>
                  <div>
                    <span className="opacity-60">value:</span> {call.value || "0x0"}
                  </div>
                  <div>
                    <span className="opacity-60">data:</span> {call.data || "0x"}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error Display */}
      {txError && (
        <div className="alert alert-error mt-3 py-2">
          <span className="text-sm">{txError}</span>
        </div>
      )}

      {/* Action Buttons */}
      {(isTransaction || isBatchCall) && (
        <div className="flex gap-2 mt-4">
          <button className="btn btn-primary flex-1" onClick={handleExecute} disabled={isExecuting}>
            {isExecuting ? (
              <>
                <span className="loading loading-spinner loading-sm"></span>
                Executing...
              </>
            ) : isBatchCall ? (
              `Execute ${request.calls?.length || 0} Calls`
            ) : (
              "Execute Transaction"
            )}
          </button>
          <button className="btn btn-ghost" onClick={handleReject} disabled={isExecuting}>
            Reject
          </button>
        </div>
      )}

      {/* Timestamp */}
      <div className="text-xs opacity-40 mt-3">Received: {new Date(request.timestamp).toLocaleTimeString()}</div>
    </div>
  );
};
