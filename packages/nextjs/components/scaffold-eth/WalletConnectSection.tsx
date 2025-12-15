"use client";

import { useState } from "react";
import Image from "next/image";
import { Address } from "@scaffold-ui/components";
import { formatEther, toHex } from "viem";
import { useAccount, useChainId, useConfig, usePublicClient, useWalletClient, useWriteContract } from "wagmi";
import { readContract, simulateContract } from "wagmi/actions";
import { QrScannerModal } from "~~/components/scaffold-eth/QrScannerModal";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import {
  ActiveSession,
  BatchCallStatus,
  SessionRequest,
  useWalletConnect,
} from "~~/hooks/scaffold-eth/useWalletConnect";
import {
  StoredPasskey,
  WebAuthnAuth,
  buildBatchChallengeHash,
  buildChallengeHash,
  signWithPasskey,
} from "~~/utils/passkey";

interface WalletConnectSectionProps {
  smartWalletAddress: string;
  currentPasskey: StoredPasskey | null;
  isPasskeyOperator: boolean;
  passkeyNonce: bigint | undefined;
  refetchPasskeyNonce: () => Promise<void>;
}

export const WalletConnectSection = ({
  smartWalletAddress,
  currentPasskey,
  isPasskeyOperator,
  passkeyNonce,
  refetchPasskeyNonce,
}: WalletConnectSectionProps) => {
  const [wcUri, setWcUri] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  // Get wallet client and owner address for signing
  const { address: ownerAddress } = useAccount();
  const { data: walletClient } = useWalletClient();
  const chainId = useChainId();

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
                currentPasskey={currentPasskey}
                isPasskeyOperator={isPasskeyOperator}
                passkeyNonce={passkeyNonce}
                refetchPasskeyNonce={refetchPasskeyNonce}
                chainId={chainId}
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

// Signed meta transaction type
interface SignedMetaTx {
  isBatch: boolean;
  // For single tx
  target?: `0x${string}`;
  value?: bigint;
  data?: `0x${string}`;
  // For batch tx
  calls?: Array<{ target: `0x${string}`; value: bigint; data: `0x${string}` }>;
  // Common fields
  qx: `0x${string}`;
  qy: `0x${string}`;
  deadline: bigint;
  auth: WebAuthnAuth;
}

// Facilitate API response type
interface FacilitateResponse {
  success?: boolean;
  txHash?: string;
  blockNumber?: string;
  gasUsed?: string;
  error?: string;
  details?: string;
}

// Session Request Card Component
const SessionRequestCard = ({
  request,
  smartWalletAddress,
  onApprove,
  onReject,
  onClear,
  updateBatchStatus,
  currentPasskey,
  isPasskeyOperator,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  passkeyNonce, // Unused - we fetch fresh nonce before each signing
  refetchPasskeyNonce,
  chainId,
}: {
  request: SessionRequest;
  smartWalletAddress: string;
  onApprove: (requestId: number, topic: string, result: string) => Promise<void>;
  onReject: (requestId: number, topic: string) => Promise<void>;
  onClear: () => void;
  updateBatchStatus: (batchId: string, updates: Partial<BatchCallStatus>) => void;
  currentPasskey: StoredPasskey | null;
  isPasskeyOperator: boolean;
  passkeyNonce: bigint | undefined;
  refetchPasskeyNonce: () => Promise<void>;
  chainId: number;
}) => {
  const [isExecuting, setIsExecuting] = useState(false);
  const [txError, setTxError] = useState<string | null>(null);
  const [isSigningWithPasskey, setIsSigningWithPasskey] = useState(false);
  const [signedMetaTx, setSignedMetaTx] = useState<SignedMetaTx | null>(null);
  const [isRelaying, setIsRelaying] = useState(false);
  const [isFacilitating, setIsFacilitating] = useState(false);
  const [confirmedTxHash, setConfirmedTxHash] = useState<string | null>(null);

  const config = useConfig();
  const { writeContractAsync } = useWriteContract();
  const publicClient = usePublicClient();
  const { address: connectedAddress } = useAccount();

  // Submit signed transaction to facilitator API
  const submitToFacilitator = async (signedTx: SignedMetaTx, requestChainId: number): Promise<FacilitateResponse> => {
    const calls =
      signedTx.isBatch && signedTx.calls
        ? signedTx.calls.map(c => ({
            target: c.target,
            value: c.value.toString(),
            data: c.data,
          }))
        : [
            {
              target: signedTx.target!,
              value: signedTx.value!.toString(),
              data: signedTx.data!,
            },
          ];

    const response = await fetch("/api/facilitate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        smartWalletAddress,
        chainId: requestChainId,
        isBatch: signedTx.isBatch,
        calls,
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

  // Sign transaction with passkey
  const handleSignWithPasskey = async () => {
    if (!currentPasskey) {
      setTxError("Passkey not available");
      return;
    }

    setIsSigningWithPasskey(true);
    setTxError(null);
    setSignedMetaTx(null);

    try {
      // Generate unique signing ID to trace signing → relay
      const signingId = `sign-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      console.log("=== SIGNING STARTED ===", signingId);

      // Parse the actual chain ID from the WalletConnect request
      // Format is "eip155:8453" -> extract 8453
      let requestChainId = chainId; // fallback to wallet's chain
      if (request.chainId) {
        const chainIdMatch = request.chainId.match(/eip155:(\d+)/);
        if (chainIdMatch) {
          requestChainId = parseInt(chainIdMatch[1], 10);
        } else if (!isNaN(Number(request.chainId))) {
          requestChainId = Number(request.chainId);
        }
      }

      console.log("=== PASSKEY SIGNING DEBUG ===");
      console.log("Chain ID (from useChainId):", chainId);
      console.log("Request Chain ID (from WC request):", request.chainId);
      console.log("Parsed Request Chain ID:", requestChainId);
      console.log("Smart Wallet Address:", smartWalletAddress);
      console.log("Passkey Address:", currentPasskey.passkeyAddress);
      console.log("Is Batch?:", isBatchCall);

      // IMPORTANT: Always fetch fresh nonce directly from chain before signing
      // Use the REQUEST's chain ID, not the wallet's chain ID!
      const freshNonce = await readContract(config, {
        address: smartWalletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "nonces",
        args: [currentPasskey.passkeyAddress],
        chainId: requestChainId, // Explicitly specify the chain!
      });

      console.log("Fresh nonce from chain:", freshNonce);

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

      if (isBatchCall && request.calls && request.calls.length > 0) {
        // Handle batch transaction
        const calls = request.calls.map(call => ({
          target: (call.to || "0x0000000000000000000000000000000000000000") as `0x${string}`,
          value: call.value ? BigInt(call.value) : 0n,
          data: (call.data || "0x") as `0x${string}`,
        }));

        // Build the challenge hash for batch - use the REQUEST's chain ID!
        const challengeHash = buildBatchChallengeHash(
          BigInt(requestChainId),
          smartWalletAddress as `0x${string}`,
          calls,
          freshNonce,
          deadline,
        );

        // Convert hash to Uint8Array for WebAuthn
        const challengeBytes = new Uint8Array(
          (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
        );

        // Sign with passkey
        const { auth } = await signWithPasskey(currentPasskey.credentialId, challengeBytes);

        const signedTx: SignedMetaTx = {
          isBatch: true,
          calls,
          qx: currentPasskey.qx,
          qy: currentPasskey.qy,
          deadline,
          auth,
        };

        // Auto-submit to facilitator API
        setIsSigningWithPasskey(false);
        setIsFacilitating(true);

        console.log("[WC Facilitate] Submitting batch transaction to API...");
        const facilitateResult = await submitToFacilitator(signedTx, requestChainId);

        if (facilitateResult.success && facilitateResult.txHash) {
          console.log("[WC Facilitate] Transaction confirmed:", facilitateResult.txHash);
          setConfirmedTxHash(facilitateResult.txHash);

          // Handle EIP-5792 response
          if (request.batchId) {
            updateBatchStatus(request.batchId, {
              status: 200,
              txHash: facilitateResult.txHash,
            });
          }

          // Refetch nonce for next transaction
          await refetchPasskeyNonce();

          // Auto-clear after showing confirmation
          setTimeout(() => {
            onClear();
            setConfirmedTxHash(null);
          }, 3000);
        } else {
          // Facilitator failed - fall back to manual relay
          console.error("[WC Facilitate] Failed:", facilitateResult.error, facilitateResult.details);
          setSignedMetaTx(signedTx);
          setTxError(`Facilitator unavailable: ${facilitateResult.error}. You can relay manually.`);
        }

        setIsFacilitating(false);
        return; // Exit early since we handled everything
      } else {
        // Handle single transaction
        const target = (request.params.to || "0x0000000000000000000000000000000000000000") as `0x${string}`;
        const value = request.params.value ? BigInt(request.params.value) : 0n;
        const data = (request.params.data || "0x") as `0x${string}`;

        console.log("=== CHALLENGE HASH INPUTS ===");
        console.log("chainId:", requestChainId);
        console.log("walletAddress:", smartWalletAddress);
        console.log("target:", target);
        console.log("value:", value.toString());
        console.log("data length:", data.length);
        console.log(
          "data hash:",
          data
            ? `0x${Array.from(new TextEncoder().encode(data))
                .reduce((a, b) => a + b, 0)
                .toString(16)}`
            : "empty",
        );
        console.log("nonce:", freshNonce.toString());
        console.log("deadline:", deadline.toString());
        console.log("request.id:", request.id);
        console.log("request.timestamp:", request.timestamp);

        // Log hex values for debugging (matches contract's abi.encodePacked format)
        console.log("=== RAW CHALLENGE HEX INPUTS ===");
        console.log("chainId hex (32 bytes):", toHex(BigInt(requestChainId), { size: 32 }));
        console.log("wallet (20 bytes):", smartWalletAddress);
        console.log("target (20 bytes):", target);
        console.log("value hex (32 bytes):", toHex(value, { size: 32 }));
        console.log("data (raw):", data);
        console.log("nonce hex (32 bytes):", toHex(freshNonce, { size: 32 }));
        console.log("deadline hex (32 bytes):", toHex(deadline, { size: 32 }));

        // Build the challenge hash for single tx - use the REQUEST's chain ID!
        const challengeHash = buildChallengeHash(
          BigInt(requestChainId),
          smartWalletAddress as `0x${string}`,
          target,
          value,
          data,
          freshNonce,
          deadline,
        );

        console.log("Challenge hash:", challengeHash);

        // Convert hash to Uint8Array for WebAuthn
        const challengeBytes = new Uint8Array(
          (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
        );

        // Sign with passkey
        const { auth } = await signWithPasskey(currentPasskey.credentialId, challengeBytes);

        const signedTx: SignedMetaTx = {
          isBatch: false,
          target,
          value,
          data,
          qx: currentPasskey.qx,
          qy: currentPasskey.qy,
          deadline,
          auth,
        };

        // Auto-submit to facilitator API
        setIsSigningWithPasskey(false);
        setIsFacilitating(true);

        console.log("[WC Facilitate] Submitting single transaction to API...");
        const facilitateResult = await submitToFacilitator(signedTx, requestChainId);

        if (facilitateResult.success && facilitateResult.txHash) {
          console.log("[WC Facilitate] Transaction confirmed:", facilitateResult.txHash);
          setConfirmedTxHash(facilitateResult.txHash);

          // For regular eth_sendTransaction, send the transaction hash back to the dApp
          await onApprove(request.id, request.topic, facilitateResult.txHash);

          // Refetch nonce for next transaction
          await refetchPasskeyNonce();

          // Auto-clear after showing confirmation
          setTimeout(() => {
            setConfirmedTxHash(null);
          }, 3000);
        } else {
          // Facilitator failed - fall back to manual relay
          console.error("[WC Facilitate] Failed:", facilitateResult.error, facilitateResult.details);
          setSignedMetaTx(signedTx);
          setTxError(`Facilitator unavailable: ${facilitateResult.error}. You can relay manually.`);
        }

        setIsFacilitating(false);
      }
    } catch (err) {
      console.error("Failed to sign with passkey:", err);
      setTxError(err instanceof Error ? err.message : "Failed to sign with passkey");
      setIsFacilitating(false);
    } finally {
      setIsSigningWithPasskey(false);
    }
  };

  // Relay the signed meta transaction
  const handleRelayTransaction = async () => {
    if (!signedMetaTx) {
      setTxError("No signed transaction to relay");
      return;
    }

    setIsRelaying(true);
    setTxError(null);

    try {
      let txHash: string;

      if (signedMetaTx.isBatch && signedMetaTx.calls) {
        // Pre-relay simulation for batch transaction
        console.log("=== PRE-RELAY BATCH SIMULATION ===");
        try {
          await simulateContract(config, {
            address: smartWalletAddress as `0x${string}`,
            abi: SMART_WALLET_ABI,
            functionName: "metaBatchExecPasskey",
            args: [
              signedMetaTx.calls,
              signedMetaTx.qx,
              signedMetaTx.qy,
              signedMetaTx.deadline,
              {
                r: signedMetaTx.auth.r,
                s: signedMetaTx.auth.s,
                challengeIndex: signedMetaTx.auth.challengeIndex,
                typeIndex: signedMetaTx.auth.typeIndex,
                authenticatorData: signedMetaTx.auth.authenticatorData,
                clientDataJSON: signedMetaTx.auth.clientDataJSON,
              },
            ],
          });
          console.log("✅ Batch simulation PASSED - transaction should succeed");
        } catch (simError) {
          console.error("❌ BATCH SIMULATION FAILED - Actual revert reason:");
          const simErrorMsg = simError instanceof Error ? simError.message : String(simError);
          if (simErrorMsg.includes("InvalidSignature")) {
            console.error(">>> INVALID SIGNATURE - Challenge hash or WebAuthn verification failed!");
          } else if (simErrorMsg.includes("ExecutionFailed")) {
            console.error(">>> EXECUTION FAILED - One of the calls reverted!");
          } else if (simErrorMsg.includes("ExpiredSignature")) {
            console.error(">>> EXPIRED SIGNATURE - Our deadline passed!");
          } else if (simErrorMsg.includes("PasskeyNotRegistered")) {
            console.error(">>> PASSKEY NOT REGISTERED - The passkey is not registered on the wallet!");
          } else {
            console.error(">>> Unknown error:", simErrorMsg);
          }
        }

        // Relay batch transaction via metaBatchExecPasskey
        txHash = await writeContractAsync({
          address: smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "metaBatchExecPasskey",
          args: [
            signedMetaTx.calls,
            signedMetaTx.qx,
            signedMetaTx.qy,
            signedMetaTx.deadline,
            {
              r: signedMetaTx.auth.r,
              s: signedMetaTx.auth.s,
              challengeIndex: signedMetaTx.auth.challengeIndex,
              typeIndex: signedMetaTx.auth.typeIndex,
              authenticatorData: signedMetaTx.auth.authenticatorData,
              clientDataJSON: signedMetaTx.auth.clientDataJSON,
            },
          ],
        });
      } else {
        // Relay single transaction via metaExecPasskey
        console.log("=== RELAY DEBUG ===");
        console.log("request.id being relayed:", request.id);
        console.log("request.timestamp:", request.timestamp);
        console.log("target:", signedMetaTx.target);
        console.log("value:", signedMetaTx.value?.toString());
        console.log("data length:", signedMetaTx.data?.length);
        console.log(
          "data hash:",
          signedMetaTx.data
            ? `0x${Array.from(new TextEncoder().encode(signedMetaTx.data))
                .reduce((a, b) => a + b, 0)
                .toString(16)}`
            : "empty",
        );
        console.log("qx:", signedMetaTx.qx);
        console.log("qy:", signedMetaTx.qy);
        console.log("deadline:", signedMetaTx.deadline.toString());
        console.log("auth.r:", signedMetaTx.auth.r);
        console.log("auth.s:", signedMetaTx.auth.s);
        console.log("auth.challengeIndex:", signedMetaTx.auth.challengeIndex.toString());
        console.log("auth.typeIndex:", signedMetaTx.auth.typeIndex.toString());
        console.log("clientDataJSON challenge:", JSON.parse(signedMetaTx.auth.clientDataJSON).challenge);

        // Pre-relay simulation to get actual revert reason (not masked by wallet)
        console.log("=== PRE-RELAY SIMULATION ===");
        try {
          await simulateContract(config, {
            address: smartWalletAddress as `0x${string}`,
            abi: SMART_WALLET_ABI,
            functionName: "metaExecPasskey",
            args: [
              signedMetaTx.target!,
              signedMetaTx.value!,
              signedMetaTx.data!,
              signedMetaTx.qx,
              signedMetaTx.qy,
              signedMetaTx.deadline,
              {
                r: signedMetaTx.auth.r,
                s: signedMetaTx.auth.s,
                challengeIndex: signedMetaTx.auth.challengeIndex,
                typeIndex: signedMetaTx.auth.typeIndex,
                authenticatorData: signedMetaTx.auth.authenticatorData,
                clientDataJSON: signedMetaTx.auth.clientDataJSON,
              },
            ],
          });
          console.log("✅ Simulation PASSED - transaction should succeed");
        } catch (simError) {
          console.error("❌ SIMULATION FAILED - Actual revert reason:");
          const simErrorMsg = simError instanceof Error ? simError.message : String(simError);
          if (simErrorMsg.includes("InvalidSignature")) {
            console.error(">>> INVALID SIGNATURE - Challenge hash or WebAuthn verification failed!");
          } else if (simErrorMsg.includes("ExecutionFailed")) {
            console.error(">>> EXECUTION FAILED - The Uniswap swap reverted (price/slippage/deadline)!");
          } else if (simErrorMsg.includes("ExpiredSignature")) {
            console.error(">>> EXPIRED SIGNATURE - Our deadline passed!");
          } else if (simErrorMsg.includes("PasskeyNotRegistered")) {
            console.error(">>> PASSKEY NOT REGISTERED - The passkey is not registered on the wallet!");
          } else {
            console.error(">>> Unknown error:", simErrorMsg);
          }
          // Don't throw - let the actual writeContract handle the error for the UI
        }

        txHash = await writeContractAsync({
          address: smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "metaExecPasskey",
          args: [
            signedMetaTx.target!,
            signedMetaTx.value!,
            signedMetaTx.data!,
            signedMetaTx.qx,
            signedMetaTx.qy,
            signedMetaTx.deadline,
            {
              r: signedMetaTx.auth.r,
              s: signedMetaTx.auth.s,
              challengeIndex: signedMetaTx.auth.challengeIndex,
              typeIndex: signedMetaTx.auth.typeIndex,
              authenticatorData: signedMetaTx.auth.authenticatorData,
              clientDataJSON: signedMetaTx.auth.clientDataJSON,
            },
          ],
        });
      }

      console.log("Meta transaction relayed:", txHash);

      // Handle EIP-5792 wallet_sendCalls response
      if (isBatchCall && request.batchId) {
        if (!publicClient) {
          console.error("Public client not available, cannot fetch receipt");
          updateBatchStatus(request.batchId, {
            status: 500,
            txHash,
          });
          setSignedMetaTx(null);
          onClear();
          await refetchPasskeyNonce();
          return;
        }

        try {
          const receipt = await publicClient.waitForTransactionReceipt({
            hash: txHash as `0x${string}`,
          });

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

          console.log("✅ Batch meta transaction confirmed");
        } catch (receiptError) {
          console.error("Failed to get transaction receipt:", receiptError);
          updateBatchStatus(request.batchId, {
            status: 500,
            txHash,
          });
        }

        setSignedMetaTx(null);
        onClear();
      } else {
        // For regular eth_sendTransaction, wait for receipt THEN send response
        // This ensures nonce is incremented on-chain before we proceed
        if (publicClient) {
          console.log("Waiting for transaction receipt...");
          await publicClient.waitForTransactionReceipt({
            hash: txHash as `0x${string}`,
          });
          console.log("Transaction confirmed!");
        }

        await onApprove(request.id, request.topic, txHash);
        setSignedMetaTx(null);
      }

      // Refetch nonce for next transaction
      await refetchPasskeyNonce();
      console.log("Nonce refetched after successful relay");
    } catch (err) {
      console.error("=== RELAY FAILED ===");
      console.error("Error:", err);
      console.error("Error message:", err instanceof Error ? err.message : "Unknown error");

      // Try to extract revert reason if available
      const errorMessage = err instanceof Error ? err.message : String(err);
      const isInvalidSignature = errorMessage.includes("InvalidSignature");
      const isExecutionFailed = errorMessage.includes("ExecutionFailed");

      if (isInvalidSignature) {
        console.error(">>> INVALID SIGNATURE - Nonce or challenge hash mismatch!");
      } else if (isExecutionFailed) {
        console.error(">>> EXECUTION FAILED - The underlying call (e.g., Uniswap swap) reverted!");
        console.error(">>> This could be: slippage, deadline expired, insufficient balance, etc.");
      }

      setTxError(err instanceof Error ? err.message : "Failed to relay transaction");

      if (isBatchCall && request.batchId) {
        updateBatchStatus(request.batchId, {
          status: 500,
        });
      }
    } finally {
      setIsRelaying(false);
    }
  };

  // Clear signed meta transaction
  const handleClearSignedTx = () => {
    setSignedMetaTx(null);
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

      {/* Confirmed Transaction Display */}
      {confirmedTxHash && (
        <div className="bg-success/10 border border-success rounded-xl p-4 mt-4">
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
        <div className="bg-info/10 border border-info rounded-xl p-4 mt-4">
          <div className="flex items-center gap-3">
            <span className="loading loading-spinner loading-md text-info"></span>
            <div>
              <p className="text-info font-medium">Transaction is being processed...</p>
              <p className="text-xs opacity-70">Waiting for on-chain confirmation</p>
            </div>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      {(isTransaction || isBatchCall) && !signedMetaTx && !isFacilitating && !confirmedTxHash && (
        <div className="space-y-3 mt-4">
          {/* Primary Execute Button (Owner/Operator) */}
          <div className="flex gap-2">
            <button
              className="btn btn-primary flex-1"
              onClick={handleExecute}
              disabled={isExecuting || isSigningWithPasskey || isFacilitating}
            >
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
            <button
              className="btn btn-ghost"
              onClick={handleReject}
              disabled={isExecuting || isSigningWithPasskey || isFacilitating}
            >
              Reject
            </button>
          </div>

          {/* Passkey Signing Option */}
          {isPasskeyOperator && currentPasskey && (
            <>
              <div className="divider text-xs opacity-60 my-2">OR sign with passkey (gasless)</div>
              <button
                className="btn btn-secondary w-full"
                onClick={handleSignWithPasskey}
                disabled={isSigningWithPasskey || isExecuting || isFacilitating}
              >
                {isSigningWithPasskey ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Signing...
                  </>
                ) : (
                  "Sign with Passkey"
                )}
              </button>
              <p className="text-xs text-center opacity-60">Transaction will be submitted automatically</p>
            </>
          )}
        </div>
      )}

      {/* Signed Meta Transaction Display (fallback when facilitator fails) */}
      {signedMetaTx && !isFacilitating && !confirmedTxHash && (
        <div className="bg-warning/10 border border-warning rounded-xl p-4 mt-4 space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-warning">Facilitator unavailable - Manual relay required</p>
            <button className="btn btn-xs btn-ghost" onClick={handleClearSignedTx}>
              Clear
            </button>
          </div>

          {/* Transaction Summary */}
          <div className="space-y-2 text-sm">
            {signedMetaTx.isBatch ? (
              <div className="flex justify-between">
                <span className="opacity-60">Batch:</span>
                <span>{signedMetaTx.calls?.length || 0} call(s)</span>
              </div>
            ) : (
              <>
                <div className="flex justify-between">
                  <span className="opacity-60">To:</span>
                  <Address address={signedMetaTx.target!} />
                </div>
                <div className="flex justify-between">
                  <span className="opacity-60">Value:</span>
                  <span>{formatEther(signedMetaTx.value!)} ETH</span>
                </div>
              </>
            )}
            <div className="flex justify-between">
              <span className="opacity-60">Deadline:</span>
              <span>{new Date(Number(signedMetaTx.deadline) * 1000).toLocaleString()}</span>
            </div>
          </div>

          {/* Copy JSON Button */}
          <details className="collapse collapse-arrow bg-base-200">
            <summary className="collapse-title text-sm font-medium">View/Copy Transaction JSON</summary>
            <div className="collapse-content">
              <pre className="text-xs font-mono bg-base-300 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
                {JSON.stringify(
                  {
                    isBatch: signedMetaTx.isBatch,
                    ...(signedMetaTx.isBatch
                      ? {
                          calls: signedMetaTx.calls?.map(c => ({
                            target: c.target,
                            value: c.value.toString(),
                            data: c.data,
                          })),
                        }
                      : {
                          target: signedMetaTx.target,
                          value: signedMetaTx.value?.toString(),
                          data: signedMetaTx.data,
                        }),
                    qx: signedMetaTx.qx,
                    qy: signedMetaTx.qy,
                    deadline: signedMetaTx.deadline.toString(),
                    auth: {
                      r: signedMetaTx.auth.r,
                      s: signedMetaTx.auth.s,
                      challengeIndex: signedMetaTx.auth.challengeIndex.toString(),
                      typeIndex: signedMetaTx.auth.typeIndex.toString(),
                      authenticatorData: signedMetaTx.auth.authenticatorData,
                      clientDataJSON: signedMetaTx.auth.clientDataJSON,
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
                      isBatch: signedMetaTx.isBatch,
                      ...(signedMetaTx.isBatch
                        ? {
                            calls: signedMetaTx.calls?.map(c => ({
                              target: c.target,
                              value: c.value.toString(),
                              data: c.data,
                            })),
                          }
                        : {
                            target: signedMetaTx.target,
                            value: signedMetaTx.value?.toString(),
                            data: signedMetaTx.data,
                          }),
                      qx: signedMetaTx.qx,
                      qy: signedMetaTx.qy,
                      deadline: signedMetaTx.deadline.toString(),
                      auth: {
                        r: signedMetaTx.auth.r,
                        s: signedMetaTx.auth.s,
                        challengeIndex: signedMetaTx.auth.challengeIndex.toString(),
                        typeIndex: signedMetaTx.auth.typeIndex.toString(),
                        authenticatorData: signedMetaTx.auth.authenticatorData,
                        clientDataJSON: signedMetaTx.auth.clientDataJSON,
                      },
                    }),
                  );
                }}
              >
                Copy to clipboard
              </button>
            </div>
          </details>

          {/* Relay Button */}
          <div className="divider text-xs opacity-60">Anyone can relay this transaction</div>
          <button className="btn btn-primary w-full" onClick={handleRelayTransaction} disabled={isRelaying}>
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
          <p className="text-xs text-center opacity-60">The relayer pays gas. The passkey holder pays nothing.</p>

          {/* Cancel/Reject option */}
          <button className="btn btn-ghost btn-sm w-full" onClick={handleReject} disabled={isRelaying}>
            Reject Request
          </button>
        </div>
      )}

      {/* Timestamp */}
      <div className="text-xs opacity-40 mt-3">Received: {new Date(request.timestamp).toLocaleTimeString()}</div>
    </div>
  );
};
