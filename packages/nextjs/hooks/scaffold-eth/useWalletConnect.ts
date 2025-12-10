"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { WalletKit, WalletKitTypes } from "@reown/walletkit";
import { Core } from "@walletconnect/core";
import { buildApprovedNamespaces, getSdkError } from "@walletconnect/utils";
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

// Supported methods
const SUPPORTED_METHODS = [
  "eth_sendTransaction",
  "eth_signTransaction",
  "eth_sign",
  "personal_sign",
  "eth_signTypedData",
  "eth_signTypedData_v4",
];

// Supported events
const SUPPORTED_EVENTS = ["accountsChanged", "chainChanged"];

export interface SessionRequest {
  id: number;
  topic: string;
  method: string;
  chainId: string;
  params: {
    from?: string;
    to?: string;
    value?: string;
    data?: string;
    gas?: string;
    gasPrice?: string;
  };
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
  enabled?: boolean;
}

export const useWalletConnect = ({ smartWalletAddress, enabled = true }: UseWalletConnectOptions) => {
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

      try {
        const approvedNamespaces = buildApprovedNamespaces({
          proposal: params,
          supportedNamespaces: {
            eip155: {
              chains: SUPPORTED_CHAIN_IDS.map(chainId => `eip155:${chainId}`),
              methods: SUPPORTED_METHODS,
              events: SUPPORTED_EVENTS,
              accounts: SUPPORTED_CHAIN_IDS.map(chainId => `eip155:${chainId}:${smartWalletAddress}`),
            },
          },
        });

        const session = await walletKit.approveSession({
          id,
          namespaces: approvedNamespaces,
        });

        console.log("Session approved:", session);

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

      // Get peer metadata
      const sessions = walletKit.getActiveSessions();
      const session = sessions[topic];
      const peerMeta = session?.peer?.metadata;

      // Parse request params
      let requestParams = request.params;
      if (Array.isArray(requestParams)) {
        requestParams = requestParams[0] || {};
      }

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
  }, [walletKit, smartWalletAddress]);

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
