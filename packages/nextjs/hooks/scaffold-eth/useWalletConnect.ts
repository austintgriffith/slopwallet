"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { WalletKit, WalletKitTypes } from "@reown/walletkit";
import { Core } from "@walletconnect/core";
import { buildApprovedNamespaces, getSdkError } from "@walletconnect/utils";
import type { WalletClient } from "viem";
import scaffoldConfig from "~~/scaffold.config";

// Type for WalletKit instance
type WalletKitInstance = Awaited<ReturnType<typeof WalletKit.init>>;

// Supported chains for WalletConnect
const SUPPORTED_CHAIN_IDS = [
  1, // Ethereum Mainnet
  137, // Polygon
  8453, // Base
  42161, // Arbitrum One
  10, // Optimism
  31337, // Foundry/Local
];

// Supported methods for WalletConnect
// wallet_getCapabilities is required for dApps to discover we support wallet_sendCalls (EIP-5792)
const SUPPORTED_METHODS = [
  "eth_sendTransaction",
  "wallet_sendCalls",
  "wallet_getCapabilities",
  "wallet_getCallsStatus",
  "wallet_showCallsStatus",
  // Compatibility - return wallet address
  "eth_accounts",
  "eth_requestAccounts",
  // Signing methods - required for dApps like CoW Swap
  "personal_sign",
  "eth_sign",
  "eth_signTypedData",
  "eth_signTypedData_v4",
];

// Supported events
const SUPPORTED_EVENTS = ["accountsChanged", "chainChanged"];

export interface CallParams {
  from?: string;
  to?: string;
  value?: string;
  data?: string;
  gas?: string;
  gasPrice?: string;
}

export interface SessionRequest {
  id: number;
  topic: string;
  method: string;
  chainId: string;
  params: CallParams;
  // For wallet_sendCalls (EIP-5792) - array of calls
  calls?: CallParams[];
  // Batch ID for wallet_sendCalls (EIP-5792)
  batchId?: string;
  timestamp: number;
  peerMeta?: {
    name: string;
    description?: string;
    url?: string;
    icons?: string[];
  };
}

// EIP-5792 Batch Call Status
export interface BatchCallStatus {
  batchId: string;
  chainId: string;
  status: number; // 100=pending, 200=confirmed, 400=failed, 500=reverted, 600=partial
  atomic: boolean;
  txHash?: string;
  receipts?: {
    logs: {
      address: string;
      data: string;
      topics: string[];
    }[];
    status: string;
    blockHash: string;
    blockNumber: string;
    gasUsed: string;
    transactionHash: string;
  }[];
}

export interface ActiveSession {
  topic: string;
  peerMeta: {
    name: string;
    description?: string;
    url?: string;
    icons?: string[];
  };
  expiry: number;
}

type ConnectionStatus = "idle" | "initializing" | "ready" | "pairing" | "connected" | "error";

interface UseWalletConnectOptions {
  smartWalletAddress: string;
  walletClient?: WalletClient;
  ownerAddress?: string;
  enabled?: boolean;
}

export const useWalletConnect = ({
  smartWalletAddress,
  walletClient,
  ownerAddress,
  enabled = true,
}: UseWalletConnectOptions) => {
  const [walletKit, setWalletKit] = useState<WalletKitInstance | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [sessionRequests, setSessionRequests] = useState<SessionRequest[]>([]);
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);

  const initializingRef = useRef(false);
  const walletKitRef = useRef<WalletKitInstance | null>(null);
  // EIP-5792: Track batch call statuses - use Ref to persist across renders
  const batchStatusesRef = useRef<Map<string, BatchCallStatus>>(new Map());

  // Initialize WalletKit
  useEffect(() => {
    if (!enabled || !smartWalletAddress || initializingRef.current) return;

    const initWalletKit = async () => {
      initializingRef.current = true;
      setStatus("initializing");
      setError(null);

      try {
        const core = new Core({
          projectId: scaffoldConfig.walletConnectProjectId,
        });

        const kit = await WalletKit.init({
          core,
          metadata: {
            name: "Smart Wallet",
            description: "Smart Contract Wallet with WalletConnect",
            url: typeof window !== "undefined" ? window.location.origin : "https://localhost:3000",
            icons: [],
          },
        });

        walletKitRef.current = kit;
        setWalletKit(kit);
        setStatus("ready");

        // Load existing sessions
        const sessions = kit.getActiveSessions();
        const activeSessionsList: ActiveSession[] = Object.values(sessions).map(session => ({
          topic: session.topic,
          peerMeta: session.peer.metadata,
          expiry: session.expiry,
        }));
        setActiveSessions(activeSessionsList);

        if (activeSessionsList.length > 0) {
          setStatus("connected");
        }
      } catch (err) {
        console.error("Failed to initialize WalletKit:", err);
        setError(err instanceof Error ? err.message : "Failed to initialize WalletConnect");
        setStatus("error");
      } finally {
        initializingRef.current = false;
      }
    };

    initWalletKit();

    return () => {
      // Cleanup - disconnect all sessions on unmount
      // Note: We don't disconnect here to preserve sessions across page navigation
    };
  }, [enabled, smartWalletAddress]);

  // Set up event listeners
  useEffect(() => {
    if (!walletKit || !smartWalletAddress) return;

    // Handle session proposals - auto approve
    const handleSessionProposal = async (proposal: WalletKitTypes.SessionProposal) => {
      const { id, params } = proposal;

      console.log("WalletConnect session proposal from:", params.proposer?.metadata?.name || "Unknown");

      try {
        const ourSupportedNamespaces = {
          eip155: {
            chains: SUPPORTED_CHAIN_IDS.map(chainId => `eip155:${chainId}`),
            methods: SUPPORTED_METHODS,
            events: SUPPORTED_EVENTS,
            accounts: SUPPORTED_CHAIN_IDS.map(chainId => `eip155:${chainId}:${smartWalletAddress}`),
          },
        };
        const approvedNamespaces = buildApprovedNamespaces({
          proposal: params,
          supportedNamespaces: ourSupportedNamespaces,
        });

        const session = await walletKit.approveSession({
          id,
          namespaces: approvedNamespaces,
        });

        console.log("✅ WalletConnect session approved:", session.topic);

        // Update active sessions
        setActiveSessions(prev => [
          ...prev,
          {
            topic: session.topic,
            peerMeta: session.peer.metadata,
            expiry: session.expiry,
          },
        ]);
        setStatus("connected");
      } catch (err) {
        console.error("Failed to approve session:", err);

        // Reject the session if we can't approve it
        try {
          await walletKit.rejectSession({
            id,
            reason: getSdkError("USER_REJECTED"),
          });
        } catch (rejectErr) {
          console.error("Failed to reject session:", rejectErr);
        }

        setError(err instanceof Error ? err.message : "Failed to approve session");
      }
    };

    // Handle session requests
    const handleSessionRequest = async (event: WalletKitTypes.SessionRequest) => {
      const { id, topic, params } = event;
      const { request, chainId } = params;

      console.log(`WalletConnect request: ${request.method}`);

      // Handle wallet_getCapabilities - auto-respond with our capabilities (EIP-5792)
      if (request.method === "wallet_getCapabilities") {
        // Build capabilities for all supported chains
        const capabilities: Record<string, Record<string, any>> = {};
        for (const supportedChainId of SUPPORTED_CHAIN_IDS) {
          const hexChainId = `0x${supportedChainId.toString(16)}`;
          capabilities[hexChainId] = {
            atomic: {
              status: "supported",
            },
          };
        }

        try {
          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: capabilities, jsonrpc: "2.0" as const },
          });
        } catch (err) {
          console.error("Failed to send wallet_getCapabilities response:", err);
        }
        return;
      }

      // Handle wallet_getCallsStatus - return status of a batch call (EIP-5792)
      if (request.method === "wallet_getCallsStatus") {
        const batchId = request.params?.[0];
        const batchStatus = batchStatusesRef.current.get(batchId);

        if (!batchStatus) {
          console.error("Batch ID not found:", batchId);
          try {
            await walletKit.respondSessionRequest({
              topic,
              response: {
                id,
                jsonrpc: "2.0" as const,
                error: {
                  code: 5730, // Unknown bundle id (per EIP-5792)
                  message: "Unknown batch id",
                },
              },
            });
          } catch (err) {
            console.error("Failed to send error response:", err);
          }
          return;
        }

        // Build EIP-5792 compliant response
        const statusResponse = {
          version: "2.0.0",
          id: batchStatus.batchId,
          chainId: batchStatus.chainId,
          status: batchStatus.status,
          atomic: batchStatus.atomic,
          ...(batchStatus.receipts && { receipts: batchStatus.receipts }),
        };

        try {
          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: statusResponse, jsonrpc: "2.0" as const },
          });
        } catch (err) {
          console.error("Failed to send wallet_getCallsStatus response:", err);
        }
        return;
      }

      // Handle wallet_showCallsStatus - show UI for batch status (EIP-5792)
      if (request.method === "wallet_showCallsStatus") {
        const batchId = request.params?.[0];
        const batchStatus = batchStatusesRef.current.get(batchId);

        if (!batchStatus) {
          console.error("Batch ID not found:", batchId);
          try {
            await walletKit.respondSessionRequest({
              topic,
              response: {
                id,
                jsonrpc: "2.0" as const,
                error: {
                  code: 5730,
                  message: "Unknown batch id",
                },
              },
            });
          } catch (err) {
            console.error("Failed to send error response:", err);
          }
          return;
        }

        try {
          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: null, jsonrpc: "2.0" as const },
          });
        } catch (err) {
          console.error("Failed to send wallet_showCallsStatus response:", err);
        }
        return;
      }

      // Handle eth_accounts and eth_requestAccounts - return the smart wallet address
      if (request.method === "eth_accounts" || request.method === "eth_requestAccounts") {
        const accounts = [smartWalletAddress];

        try {
          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: accounts, jsonrpc: "2.0" as const },
          });
        } catch (err) {
          console.error(`Failed to send ${request.method} response:`, err);
        }
        return;
      }

      // Handle signing methods - use owner's EOA to sign (ERC-1271 support)
      if (["personal_sign", "eth_sign", "eth_signTypedData", "eth_signTypedData_v4"].includes(request.method)) {
        if (!walletClient || !ownerAddress) {
          console.error("No wallet client or owner address available for signing");
          try {
            await walletKit.respondSessionRequest({
              topic,
              response: {
                id,
                jsonrpc: "2.0" as const,
                error: {
                  code: 4100,
                  message: "Owner wallet not connected. Connect the owner's wallet to sign messages.",
                },
              },
            });
          } catch (err) {
            console.error("Failed to send error response:", err);
          }
          return;
        }

        try {
          let signature: string;

          if (request.method === "personal_sign") {
            const [message] = request.params;
            signature = await walletClient.signMessage({
              account: ownerAddress as `0x${string}`,
              message: typeof message === "string" ? message : { raw: message },
            });
          } else if (request.method === "eth_sign") {
            const [, data] = request.params;
            signature = await walletClient.signMessage({
              account: ownerAddress as `0x${string}`,
              message: { raw: data as `0x${string}` },
            });
          } else if (request.method === "eth_signTypedData" || request.method === "eth_signTypedData_v4") {
            const [, typedData] = request.params;
            const parsedTypedData = typeof typedData === "string" ? JSON.parse(typedData) : typedData;

            signature = await walletClient.signTypedData({
              account: ownerAddress as `0x${string}`,
              domain: parsedTypedData.domain,
              types: parsedTypedData.types,
              primaryType: parsedTypedData.primaryType,
              message: parsedTypedData.message,
            });
          } else {
            throw new Error("Unsupported signing method");
          }

          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: signature, jsonrpc: "2.0" as const },
          });
        } catch (err) {
          console.error(`Failed to sign with ${request.method}:`, err);

          // Send error response
          try {
            await walletKit.respondSessionRequest({
              topic,
              response: {
                id,
                jsonrpc: "2.0" as const,
                error: {
                  code: 4001,
                  message: err instanceof Error ? err.message : "User rejected signature request",
                },
              },
            });
          } catch (responseErr) {
            console.error("Failed to send error response:", responseErr);
          }
        }
        return;
      }

      // Log any unhandled wallet_* methods
      if (
        request.method.startsWith("wallet_") &&
        !["wallet_sendCalls", "wallet_getCapabilities", "wallet_getCallsStatus", "wallet_showCallsStatus"].includes(
          request.method,
        )
      ) {
        console.warn("Unhandled wallet method:", request.method);
      }

      // Get peer metadata
      const sessions = walletKit.getActiveSessions();
      const session = sessions[topic];
      const peerMeta = session?.peer?.metadata;

      // Parse request params based on method
      let requestParams = request.params;
      if (Array.isArray(requestParams)) {
        requestParams = requestParams[0] || {};
      }

      // Handle wallet_sendCalls (EIP-5792) differently
      if (request.method === "wallet_sendCalls") {
        const calls: CallParams[] = (requestParams?.calls || []).map(
          (call: { to?: string; value?: string; data?: string }) => ({
            to: call.to,
            value: call.value,
            data: call.data,
          }),
        );

        // Generate unique batch ID (EIP-5792 requirement)
        const batchId = `0x${Date.now().toString(16).padStart(16, "0")}${Math.random().toString(16).slice(2).padStart(48, "0")}`;
        const requestChainId = requestParams?.chainId || chainId;

        // Create session request with batch ID
        const sessionRequest: SessionRequest = {
          id,
          topic,
          method: request.method,
          chainId: requestChainId,
          params: {
            from: requestParams?.from,
          },
          calls,
          batchId,
          timestamp: Date.now(),
          peerMeta,
        };

        // Initialize batch status as pending
        const initialStatus: BatchCallStatus = {
          batchId,
          chainId: requestChainId,
          status: 100, // Pending
          atomic: true,
        };

        batchStatusesRef.current.set(batchId, initialStatus);
        console.log("wallet_sendCalls batch created:", batchId);

        // Queue the request for user approval
        setSessionRequests(prev => [...prev, sessionRequest]);

        // Respond immediately with batch ID (EIP-5792 requirement)
        try {
          await walletKit.respondSessionRequest({
            topic,
            response: {
              id,
              result: { id: batchId },
              jsonrpc: "2.0" as const,
            },
          });
        } catch (err) {
          console.error("Failed to send wallet_sendCalls response:", err);
        }

        return;
      }

      // Standard eth_sendTransaction handling
      const sessionRequest: SessionRequest = {
        id,
        topic,
        method: request.method,
        chainId,
        params: {
          from: requestParams?.from,
          to: requestParams?.to,
          value: requestParams?.value,
          data: requestParams?.data,
          gas: requestParams?.gas || requestParams?.gasLimit,
          gasPrice: requestParams?.gasPrice,
        },
        timestamp: Date.now(),
        peerMeta,
      };

      setSessionRequests(prev => [...prev, sessionRequest]);
    };

    // Handle session deletions
    const handleSessionDelete = (event: { topic: string }) => {
      console.log("Session deleted:", event);
      setActiveSessions(prev => prev.filter(s => s.topic !== event.topic));
      setSessionRequests(prev => prev.filter(r => r.topic !== event.topic));

      // Check if any sessions remain
      const sessions = walletKit.getActiveSessions();
      if (Object.keys(sessions).length === 0) {
        setStatus("ready");
      }
    };

    // Register event listeners
    walletKit.on("session_proposal", handleSessionProposal);
    walletKit.on("session_request", handleSessionRequest);
    walletKit.on("session_delete", handleSessionDelete);

    return () => {
      walletKit.off("session_proposal", handleSessionProposal);
      walletKit.off("session_request", handleSessionRequest);
      walletKit.off("session_delete", handleSessionDelete);
    };
  }, [walletKit, smartWalletAddress, walletClient, ownerAddress]);

  // Pair with a dApp using WC URI
  const pair = useCallback(
    async (uri: string) => {
      if (!walletKit) {
        setError("WalletConnect not initialized");
        return;
      }

      // Validate URI format
      if (!uri.startsWith("wc:")) {
        setError("Invalid WalletConnect URI");
        return;
      }

      setStatus("pairing");
      setError(null);

      try {
        await walletKit.pair({ uri });
        // Status will be updated to "connected" when session_proposal is approved
      } catch (err) {
        console.error("Failed to pair:", err);
        setError(err instanceof Error ? err.message : "Failed to connect");
        setStatus(activeSessions.length > 0 ? "connected" : "ready");
      }
    },
    [walletKit, activeSessions.length],
  );

  // Disconnect a session
  const disconnect = useCallback(
    async (topic: string) => {
      if (!walletKit) return;

      try {
        await walletKit.disconnectSession({
          topic,
          reason: getSdkError("USER_DISCONNECTED"),
        });

        setActiveSessions(prev => prev.filter(s => s.topic !== topic));
        setSessionRequests(prev => prev.filter(r => r.topic !== topic));

        const sessions = walletKit.getActiveSessions();
        if (Object.keys(sessions).length === 0) {
          setStatus("ready");
        }
      } catch (err) {
        console.error("Failed to disconnect:", err);
      }
    },
    [walletKit],
  );

  // Disconnect all sessions
  const disconnectAll = useCallback(async () => {
    if (!walletKit) return;

    const sessions = walletKit.getActiveSessions();
    for (const topic of Object.keys(sessions)) {
      try {
        await walletKit.disconnectSession({
          topic,
          reason: getSdkError("USER_DISCONNECTED"),
        });
      } catch (err) {
        console.error("Failed to disconnect session:", topic, err);
      }
    }

    setActiveSessions([]);
    setSessionRequests([]);
    setStatus("ready");
  }, [walletKit]);

  // Clear a session request (after handling it)
  const clearRequest = useCallback((requestId: number) => {
    setSessionRequests(prev => prev.filter(r => r.id !== requestId));
  }, []);

  // Approve a request with a result (e.g., tx hash)
  const approveRequest = useCallback(
    async (requestId: number, topic: string, result: string) => {
      if (!walletKit) return;

      try {
        const response = { id: requestId, result, jsonrpc: "2.0" as const };
        await walletKit.respondSessionRequest({ topic, response });
        console.log("Request approved, response sent:", result);

        // Remove the request from the list
        setSessionRequests(prev => prev.filter(r => r.id !== requestId));
      } catch (err) {
        console.error("Failed to send approval response:", err);
        throw err;
      }
    },
    [walletKit],
  );

  // Reject a request
  const rejectRequest = useCallback(
    async (requestId: number, topic: string) => {
      if (!walletKit) return;

      try {
        const response = {
          id: requestId,
          jsonrpc: "2.0" as const,
          error: { code: 5000, message: "User rejected." },
        };
        await walletKit.respondSessionRequest({ topic, response });
        console.log("Request rejected");

        // Remove the request from the list
        setSessionRequests(prev => prev.filter(r => r.id !== requestId));
      } catch (err) {
        console.error("Failed to send rejection response:", err);
        throw err;
      }
    },
    [walletKit],
  );

  // Update batch status (for EIP-5792)
  const updateBatchStatus = useCallback((batchId: string, updates: Partial<BatchCallStatus>) => {
    const current = batchStatusesRef.current.get(batchId);
    if (!current) {
      console.error("Cannot update batch status - batch ID not found:", batchId);
      return;
    }

    const updated = { ...current, ...updates };
    batchStatusesRef.current.set(batchId, updated);

    if (current.status !== updated.status) {
      console.log(`Batch status updated: ${current.status} → ${updated.status}`);
    }
  }, []);

  return {
    status,
    error,
    pair,
    disconnect,
    disconnectAll,
    sessionRequests,
    activeSessions,
    batchStatuses: batchStatusesRef.current,
    clearRequest,
    approveRequest,
    rejectRequest,
    updateBatchStatus,
    isReady: status === "ready" || status === "connected",
    isConnected: status === "connected",
  };
};
