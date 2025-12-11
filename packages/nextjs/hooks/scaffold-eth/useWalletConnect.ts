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
  // Compatibility - return wallet address
  "eth_accounts",
  "eth_requestAccounts",
  // Signing methods - now supported via ERC-1271
  // Owner's EOA signs off-chain, signature can be verified on-chain via isValidSignature
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
  timestamp: number;
  peerMeta?: {
    name: string;
    description?: string;
    url?: string;
    icons?: string[];
  };
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
      console.log("Session proposal received:", proposal);

      const { id, params } = proposal;

      // Debug: Log what the dApp is requesting
      console.log("=== WalletConnect Session Debug ===");
      console.log("dApp requested namespaces:", JSON.stringify(params.requiredNamespaces, null, 2));
      console.log("dApp optional namespaces:", JSON.stringify(params.optionalNamespaces, null, 2));
      console.log("Our SUPPORTED_METHODS:", SUPPORTED_METHODS);

      try {
        const ourSupportedNamespaces = {
          eip155: {
            chains: SUPPORTED_CHAIN_IDS.map(chainId => `eip155:${chainId}`),
            methods: SUPPORTED_METHODS,
            events: SUPPORTED_EVENTS,
            accounts: SUPPORTED_CHAIN_IDS.map(chainId => `eip155:${chainId}:${smartWalletAddress}`),
          },
        };
        console.log("Our supported namespaces:", JSON.stringify(ourSupportedNamespaces, null, 2));

        const approvedNamespaces = buildApprovedNamespaces({
          proposal: params,
          supportedNamespaces: ourSupportedNamespaces,
        });

        // Debug: Log what actually gets approved
        console.log("=== APPROVED NAMESPACES (sent to dApp) ===");
        console.log(JSON.stringify(approvedNamespaces, null, 2));
        console.log("Approved methods:", approvedNamespaces.eip155?.methods);
        console.log("wallet_sendCalls included?", approvedNamespaces.eip155?.methods?.includes("wallet_sendCalls"));
        console.log(
          "wallet_getCapabilities included?",
          approvedNamespaces.eip155?.methods?.includes("wallet_getCapabilities"),
        );

        // Check if dApp requested these methods
        const dAppRequestedMethods = [
          ...(params.requiredNamespaces?.eip155?.methods || []),
          ...(params.optionalNamespaces?.eip155?.methods || []),
        ];
        console.log("=== dApp REQUESTED these methods ===");
        console.log("wallet_sendCalls requested?", dAppRequestedMethods.includes("wallet_sendCalls"));
        console.log("wallet_getCapabilities requested?", dAppRequestedMethods.includes("wallet_getCapabilities"));
        console.log("All requested methods:", dAppRequestedMethods);

        const session = await walletKit.approveSession({
          id,
          namespaces: approvedNamespaces,
        });

        console.log("✅ Session approved successfully!");
        console.log("Session topic:", session.topic);
        console.log("Session namespaces:", JSON.stringify(session.namespaces, null, 2));
        console.log("=== SESSION READY - dApp should now call wallet_getCapabilities ===");

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
      console.log("Session request received:", event);

      const { id, topic, params } = event;
      const { request, chainId } = params;

      // Debug: Log what method the dApp is calling
      console.log("=== Incoming Request Debug ===");
      console.log("Method:", request.method);
      console.log("Chain:", chainId);
      console.log("Raw params:", JSON.stringify(request.params, null, 2));
      console.log("Full request object:", JSON.stringify(request, null, 2));

      // Handle wallet_getCapabilities - auto-respond with our capabilities (EIP-5792)
      if (request.method === "wallet_getCapabilities") {
        console.log("=== Responding to wallet_getCapabilities ===");
        console.log("Requested for address:", request.params?.[0] || "no address specified");

        // Build capabilities for all supported chains
        // Format based on Base/Coinbase docs: atomic.supported = "supported" (string, not boolean!)
        // See: https://docs.base.org/base-account/reference/provider/methods/wallet_getCapabilities
        const capabilities: Record<string, Record<string, { supported: string | boolean }>> = {};
        for (const supportedChainId of SUPPORTED_CHAIN_IDS) {
          // Hex chain ID format required by EIP-5792: "0x2105" for Base, etc.
          const hexChainId = `0x${supportedChainId.toString(16)}`;
          capabilities[hexChainId] = {
            // "atomic" is the capability name used by Base/Coinbase/Uniswap
            // value should be string "supported" according to their docs
            atomic: { supported: "supported" },
            // Also include atomicBatch for EIP-5792 standard compliance
            atomicBatch: { supported: true },
            // ERC-1271 signature validation support
            // Smart wallet can validate signatures on-chain via isValidSignature
            erc1271: { supported: true },
          };
        }

        console.log("=== CAPABILITIES RESPONSE ===");
        console.log("Capabilities object:", capabilities);
        console.log("JSON stringified:", JSON.stringify(capabilities, null, 2));
        console.log("NOTE: Using 'atomic' with string 'supported' per Base/Coinbase docs");

        // Respond directly without user interaction
        const response = { id, result: capabilities, jsonrpc: "2.0" as const };
        console.log("Full WalletConnect response:", JSON.stringify(response, null, 2));

        try {
          await walletKit.respondSessionRequest({ topic, response });
          console.log("✅ wallet_getCapabilities response sent successfully!");
        } catch (err) {
          console.error("❌ Failed to send wallet_getCapabilities response:", err);
        }
        return;
      }

      // Handle eth_accounts and eth_requestAccounts - return the smart wallet address
      if (request.method === "eth_accounts" || request.method === "eth_requestAccounts") {
        console.log(`=== Responding to ${request.method} ===`);
        const accounts = [smartWalletAddress];
        console.log("Returning accounts:", accounts);

        try {
          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: accounts, jsonrpc: "2.0" as const },
          });
          console.log(`✅ ${request.method} response sent successfully!`);
        } catch (err) {
          console.error(`❌ Failed to send ${request.method} response:`, err);
        }
        return;
      }

      // Handle signing methods - use owner's EOA to sign (ERC-1271 support)
      if (["personal_sign", "eth_sign", "eth_signTypedData", "eth_signTypedData_v4"].includes(request.method)) {
        console.log(`=== Received signing request: ${request.method} ===`);
        console.log("Params:", request.params);

        // Check if we have a wallet client to sign with
        if (!walletClient || !ownerAddress) {
          console.log("❌ No wallet client or owner address available for signing");
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
            // personal_sign: params are [message, address]
            const [message] = request.params;
            console.log("Signing message with personal_sign:", message);

            signature = await walletClient.signMessage({
              account: ownerAddress as `0x${string}`,
              message: typeof message === "string" ? message : { raw: message },
            });
          } else if (request.method === "eth_sign") {
            // eth_sign: params are [address, data]
            const [, data] = request.params;
            console.log("Signing data with eth_sign:", data);

            signature = await walletClient.signMessage({
              account: ownerAddress as `0x${string}`,
              message: { raw: data as `0x${string}` },
            });
          } else if (request.method === "eth_signTypedData" || request.method === "eth_signTypedData_v4") {
            // eth_signTypedData: params are [address, typedData]
            const [, typedData] = request.params;
            console.log("Signing typed data:", typedData);

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

          console.log("✅ Signature created:", signature);
          console.log("Note: This signature can be verified on-chain via ERC-1271 isValidSignature");

          // Send signature back to dApp
          await walletKit.respondSessionRequest({
            topic,
            response: { id, result: signature, jsonrpc: "2.0" as const },
          });

          console.log(`✅ ${request.method} signature response sent successfully!`);
        } catch (err) {
          console.error(`❌ Failed to sign with ${request.method}:`, err);

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

      // Log if we receive wallet_sendCalls
      if (request.method === "wallet_sendCalls") {
        console.log("🎉🎉🎉 RECEIVED wallet_sendCalls! 🎉🎉🎉");
        console.log("This means batching is working!");
      }

      // Log any other wallet_* methods we might not be handling
      if (
        request.method.startsWith("wallet_") &&
        !["wallet_sendCalls", "wallet_getCapabilities"].includes(request.method)
      ) {
        console.log("⚠️ Received unhandled wallet method:", request.method);
        console.log("We may need to implement this for full EIP-5792 support");
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
        // wallet_sendCalls format: { version, chainId, from, calls: [{ to, value, data }, ...] }
        const calls: CallParams[] = (requestParams?.calls || []).map(
          (call: { to?: string; value?: string; data?: string }) => ({
            to: call.to,
            value: call.value,
            data: call.data,
          }),
        );

        const sessionRequest: SessionRequest = {
          id,
          topic,
          method: request.method,
          chainId: requestParams?.chainId || chainId,
          params: {
            from: requestParams?.from,
          },
          calls,
          timestamp: Date.now(),
          peerMeta,
        };

        setSessionRequests(prev => [...prev, sessionRequest]);
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

  return {
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
    isReady: status === "ready" || status === "connected",
    isConnected: status === "connected",
  };
};
