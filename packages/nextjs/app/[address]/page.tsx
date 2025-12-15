"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ImpersonatorIframe, ImpersonatorIframeProvider } from "@impersonator/iframe";
import { Address, AddressInput, Balance } from "@scaffold-ui/components";
import { QRCodeSVG } from "qrcode.react";
import { useDebounceValue } from "usehooks-ts";
import { encodeFunctionData, formatEther, formatUnits, isAddress, isHex, parseEther, parseUnits } from "viem";
import { base, hardhat } from "viem/chains";
import { normalize } from "viem/ens";
import { useAccount, useBalance, useChainId, useConfig, useEnsAddress, useReadContract, useWriteContract } from "wagmi";
import { readContract } from "wagmi/actions";
import { QrCodeIcon } from "@heroicons/react/24/outline";
import { PendingTransactionQueue, WalletConnectSection } from "~~/components/scaffold-eth";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import { useTargetNetwork } from "~~/hooks/scaffold-eth";
import scaffoldConfig from "~~/scaffold.config";
import {
  PendingTransaction,
  PendingTransactionStatus,
  SignedTransaction,
  createPendingTransaction,
} from "~~/types/pendingTransaction";
import {
  StoredPasskey,
  WebAuthnAuth,
  buildChallengeHash,
  clearPasskeyFromStorage,
  createPasskey,
  getCredentialIdHash,
  getPasskeyFromStorage,
  isWebAuthnSupported,
  loginWithPasskey,
  savePasskeyToStorage,
  signWithPasskey,
} from "~~/utils/passkey";

// USDC on Base
const USDC_ADDRESS_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const USDC_DECIMALS = 6;

// ZORA on Base
const ZORA_ADDRESS_BASE = "0x1111111111166b7FE7bd91427724B487980aFc69" as const;
const ZORA_DECIMALS = 18;

// WETH on Base
const WETH_ADDRESS_BASE = "0x4200000000000000000000000000000000000006" as const;

// Uniswap V3 SwapRouter02 on Base
const SWAP_ROUTER_ADDRESS = "0x2626664c2603336E57B271c5C0b26F421741e481" as const;

// Get RPC URL for Impersonator based on target network
const getImpersonatorRpcUrl = (chainId: number) => {
  // Base (8453) - use Alchemy
  if (chainId === 8453) {
    return `https://base-mainnet.g.alchemy.com/v2/${scaffoldConfig.alchemyApiKey}`;
  }
  // Mainnet (1) - use BuidlGuidl RPC
  if (chainId === 1) {
    return "https://mainnet.rpc.buidlguidl.com";
  }
  // Fallback to Base Alchemy
  return `https://base-mainnet.g.alchemy.com/v2/${scaffoldConfig.alchemyApiKey}`;
};

const ERC20_ABI = [
  {
    inputs: [{ name: "account", type: "address" }],
    name: "balanceOf",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    name: "transfer",
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    name: "approve",
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

// Uniswap V3 SwapRouter02 ABI (only the functions we need)
const SWAP_ROUTER_ABI = [
  {
    inputs: [
      {
        components: [
          { name: "tokenIn", type: "address" },
          { name: "tokenOut", type: "address" },
          { name: "fee", type: "uint24" },
          { name: "recipient", type: "address" },
          { name: "amountIn", type: "uint256" },
          { name: "amountOutMinimum", type: "uint256" },
          { name: "sqrtPriceLimitX96", type: "uint160" },
        ],
        name: "params",
        type: "tuple",
      },
    ],
    name: "exactInputSingle",
    outputs: [{ name: "amountOut", type: "uint256" }],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      { name: "amountMinimum", type: "uint256" },
      { name: "recipient", type: "address" },
    ],
    name: "unwrapWETH9",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
] as const;

const WalletPage = () => {
  const params = useParams();
  const walletAddress = params.address as string;
  const { address: connectedAddress } = useAccount();

  // Transfer ETH state
  const [recipientAddress, setRecipientAddress] = useState("");
  const [ethAmount, setEthAmount] = useState("");

  // Transfer USDC state
  const [usdcRecipientAddress, setUsdcRecipientAddress] = useState("");
  const [usdcAmount, setUsdcAmount] = useState("");

  // Transfer ZORA state
  const [zoraRecipientAddress, setZoraRecipientAddress] = useState("");
  const [zoraAmount, setZoraAmount] = useState("");

  // Check passkey state
  const [checkPasskeyAddress, setCheckPasskeyAddress] = useState("");
  const [passkeyCheckTriggered, setPasskeyCheckTriggered] = useState(false);

  // Raw TX state
  const [rawTxJson, setRawTxJson] = useState("");
  const [parsedTx, setParsedTx] = useState<{
    isBatch: boolean;
    calls: Array<{ target: string; value: bigint; data: `0x${string}` }>;
  } | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  // Impersonator state
  const [appUrl, setAppUrl] = useState("");
  const [debouncedAppUrl] = useDebounceValue(appUrl, 500);

  // AI Agent state
  const [agentPrompt, setAgentPrompt] = useState("");
  const [agentResponse, setAgentResponse] = useState<string | null>(null);
  const [isAgentLoading, setIsAgentLoading] = useState(false);
  const [agentError, setAgentError] = useState<string | null>(null);

  // Pending transaction queue state (unified queue for Impersonator, WalletConnect, etc.)
  const [pendingTransactions, setPendingTransactions] = useState<PendingTransaction[]>([]);
  const [signedTransactions, setSignedTransactions] = useState<SignedTransaction[]>([]);

  // Passkey state
  const [currentPasskey, setCurrentPasskey] = useState<StoredPasskey | null>(null);
  const [isGeneratingPasskey, setIsGeneratingPasskey] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isAddingPasskey, setIsAddingPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState(false); // Track client-side mount for hydration
  const [showQRModal, setShowQRModal] = useState(false);

  // Passkey Send ETH state
  const [passkeyRecipient, setPasskeyRecipient] = useState("");
  const [passkeyAmount, setPasskeyAmount] = useState("");
  const [isSigningWithPasskey, setIsSigningWithPasskey] = useState(false);
  const [isRelaying, setIsRelaying] = useState(false);
  const [signedMetaTx, setSignedMetaTx] = useState<{
    target: `0x${string}`;
    value: bigint;
    data: `0x${string}`;
    qx: `0x${string}`;
    qy: `0x${string}`;
    deadline: bigint;
    auth: WebAuthnAuth;
  } | null>(null);

  // Quick Transfer state (API-based passkey transfer)
  const [quickTransferRecipient, setQuickTransferRecipient] = useState("");
  const [quickTransferAmount, setQuickTransferAmount] = useState("");
  const [quickTransferAsset, setQuickTransferAsset] = useState<"ETH" | "USDC">("ETH");
  const [isQuickTransferring, setIsQuickTransferring] = useState(false);
  const [quickTransferStatus, setQuickTransferStatus] = useState<string | null>(null);
  const [quickTransferTxHash, setQuickTransferTxHash] = useState<string | null>(null);
  const [quickTransferError, setQuickTransferError] = useState<string | null>(null);

  // Quick Swap state (API-based passkey swap)
  const [swapDirection, setSwapDirection] = useState<"USDC_TO_ETH" | "ETH_TO_USDC">("USDC_TO_ETH");
  const [swapAmountIn, setSwapAmountIn] = useState("");
  const [debouncedSwapAmount] = useDebounceValue(swapAmountIn, 500);
  const [swapQuote, setSwapQuote] = useState<{
    amountOut: string;
    amountOutRaw: string;
    pricePerToken: string;
  } | null>(null);
  const [isLoadingQuote, setIsLoadingQuote] = useState(false);
  const [isQuickSwapping, setIsQuickSwapping] = useState(false);
  const [swapStatus, setSwapStatus] = useState<string | null>(null);
  const [swapTxHash, setSwapTxHash] = useState<string | null>(null);
  const [swapError, setSwapError] = useState<string | null>(null);

  // Resolve ENS name if needed
  const isEnsName = recipientAddress.endsWith(".eth");
  const { data: resolvedEnsAddress } = useEnsAddress({
    name: isEnsName ? normalize(recipientAddress) : undefined,
    chainId: 1, // ENS resolution on mainnet
  });

  // Get the final address to use (resolved ENS or direct address)
  const finalRecipientAddress = isEnsName ? resolvedEnsAddress : recipientAddress;

  // Resolve ENS for USDC recipient
  const isUsdcRecipientEns = usdcRecipientAddress.endsWith(".eth");
  const { data: resolvedUsdcRecipientAddress } = useEnsAddress({
    name: isUsdcRecipientEns ? normalize(usdcRecipientAddress) : undefined,
    chainId: 1,
  });
  const finalUsdcRecipientAddress = isUsdcRecipientEns ? resolvedUsdcRecipientAddress : usdcRecipientAddress;

  // Resolve ENS for ZORA recipient
  const isZoraRecipientEns = zoraRecipientAddress.endsWith(".eth");
  const { data: resolvedZoraRecipientAddress } = useEnsAddress({
    name: isZoraRecipientEns ? normalize(zoraRecipientAddress) : undefined,
    chainId: 1,
  });
  const finalZoraRecipientAddress = isZoraRecipientEns ? resolvedZoraRecipientAddress : zoraRecipientAddress;

  // Resolve ENS for passkey recipient
  const isPasskeyRecipientEns = passkeyRecipient.endsWith(".eth");
  const { data: resolvedPasskeyRecipient } = useEnsAddress({
    name: isPasskeyRecipientEns ? normalize(passkeyRecipient) : undefined,
    chainId: 1,
  });
  const finalPasskeyRecipient = isPasskeyRecipientEns ? resolvedPasskeyRecipient : passkeyRecipient;

  // Resolve ENS for check passkey
  const isCheckPasskeyEns = checkPasskeyAddress.endsWith(".eth");
  const { data: resolvedCheckPasskeyAddress } = useEnsAddress({
    name: isCheckPasskeyEns ? normalize(checkPasskeyAddress) : undefined,
    chainId: 1,
  });
  const finalCheckPasskeyAddress = isCheckPasskeyEns ? resolvedCheckPasskeyAddress : checkPasskeyAddress;

  // Validate address format
  const isValidAddress = walletAddress && isAddress(walletAddress);

  // Read owner from the SmartWallet
  const { data: owner, isLoading: ownerLoading } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "owner",
    query: {
      enabled: !!isValidAddress,
    },
  });

  // Check if connected address is a passkey (Note: connected EOA wallets aren't passkeys, only owner can exec directly)
  const { isLoading: passkeyCheckLoading } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "isPasskey",
    args: connectedAddress ? [connectedAddress] : undefined,
    query: {
      enabled: !!isValidAddress && !!connectedAddress,
    },
  });

  // Check if a specific address is a passkey (user-triggered)
  const { data: checkedAddressIsPasskey, isLoading: checkingPasskey } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "isPasskey",
    args:
      finalCheckPasskeyAddress && isAddress(finalCheckPasskeyAddress)
        ? [finalCheckPasskeyAddress as `0x${string}`]
        : undefined,
    query: {
      enabled:
        !!isValidAddress && !!finalCheckPasskeyAddress && isAddress(finalCheckPasskeyAddress) && passkeyCheckTriggered,
    },
  });

  // Read ETH balance
  const { data: ethBalance } = useBalance({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    query: {
      enabled: !!isValidAddress,
    },
  });

  // Read USDC balance on Base
  const { data: usdcBalance, isLoading: usdcLoading } = useReadContract({
    address: USDC_ADDRESS_BASE,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: isValidAddress ? [walletAddress as `0x${string}`] : undefined,
    chainId: base.id,
    query: {
      enabled: !!isValidAddress,
    },
  });

  // Read ZORA balance on Base
  const { data: zoraBalance, isLoading: zoraLoading } = useReadContract({
    address: ZORA_ADDRESS_BASE,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: isValidAddress ? [walletAddress as `0x${string}`] : undefined,
    chainId: base.id,
    query: {
      enabled: !!isValidAddress,
    },
  });

  // Get current chain ID for meta transaction signing
  const chainId = useChainId();

  // Get wagmi config for contract reads in callbacks
  const config = useConfig();

  // Get target network for Address component links
  const { targetNetwork } = useTargetNetwork();

  // Check if current passkey is registered
  const { data: isPasskeyRegistered, refetch: refetchPasskeyRegistered } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "isPasskey",
    args: currentPasskey ? [currentPasskey.passkeyAddress] : undefined,
    query: {
      enabled: !!isValidAddress && !!currentPasskey,
    },
  });

  // Get nonce for passkey meta transactions
  const { data: passkeyNonce, refetch: refetchPasskeyNonce } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "nonces",
    args: currentPasskey ? [currentPasskey.passkeyAddress] : undefined,
    query: {
      enabled: !!isValidAddress && !!currentPasskey,
    },
  });

  // Check if any passkey has been created (controls adaptive CTA)
  const { data: passkeyCreatedOnChain, refetch: refetchPasskeyCreated } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "passkeyCreated",
    query: {
      enabled: !!isValidAddress,
    },
  });

  // Track client-side mount for hydration safety
  useEffect(() => {
    setIsMounted(true);
  }, []);

  // Load passkey from localStorage on mount
  useEffect(() => {
    if (isValidAddress && typeof window !== "undefined") {
      const stored = getPasskeyFromStorage(walletAddress);
      if (stored) {
        setCurrentPasskey(stored);
      }
    }
  }, [walletAddress, isValidAddress]);

  // Determine role (only owner can exec directly, passkeys use meta transactions)
  const isOwner = connectedAddress && owner && connectedAddress.toLowerCase() === owner.toLowerCase();
  const isLoading = ownerLoading || passkeyCheckLoading;
  const hasPermissions = isOwner;

  // Write contract hooks
  const { writeContractAsync: writeExec, isPending: isTransferPending } = useWriteContract();
  const { writeContractAsync: writeAddPasskey } = useWriteContract();
  const { writeContractAsync: writeBatchExec, isPending: isSwapping } = useWriteContract();

  const handleTransferETH = async () => {
    if (!recipientAddress || !ethAmount) {
      console.log("Missing recipient or amount");
      return;
    }

    // Use resolved ENS address or direct address
    const targetAddress = finalRecipientAddress;

    if (!targetAddress || !isAddress(targetAddress)) {
      console.log("Invalid or unresolved address:", recipientAddress, "->", targetAddress);
      return;
    }

    try {
      console.log("Calling exec with:", {
        walletAddress,
        target: targetAddress,
        value: parseEther(ethAmount).toString(),
        data: "0x",
      });

      await writeExec({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "exec",
        args: [targetAddress as `0x${string}`, parseEther(ethAmount), "0x"],
      });

      setRecipientAddress("");
      setEthAmount("");
    } catch (error) {
      console.error("Transfer failed:", error);
    }
  };

  const handleTransferUSDC = async () => {
    if (!usdcRecipientAddress || !usdcAmount) {
      console.log("Missing recipient or amount");
      return;
    }

    // Use resolved ENS address or direct address
    const targetAddress = finalUsdcRecipientAddress;

    if (!targetAddress || !isAddress(targetAddress)) {
      console.log("Invalid or unresolved address:", usdcRecipientAddress, "->", targetAddress);
      return;
    }

    try {
      // Encode the ERC20 transfer call
      const transferData = encodeFunctionData({
        abi: ERC20_ABI,
        functionName: "transfer",
        args: [targetAddress as `0x${string}`, parseUnits(usdcAmount, USDC_DECIMALS)],
      });

      console.log("Calling exec with USDC transfer:", {
        walletAddress,
        target: USDC_ADDRESS_BASE,
        value: "0",
        data: transferData,
      });

      await writeExec({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "exec",
        args: [USDC_ADDRESS_BASE, 0n, transferData],
      });

      setUsdcRecipientAddress("");
      setUsdcAmount("");
    } catch (error) {
      console.error("USDC transfer failed:", error);
    }
  };

  const handleMaxETH = () => {
    if (ethBalance) {
      setEthAmount(formatUnits(ethBalance.value, 18));
    }
  };

  const handleMaxUSDC = () => {
    if (usdcBalance) {
      setUsdcAmount(formatUnits(usdcBalance, USDC_DECIMALS));
    }
  };

  const handleTransferZORA = async () => {
    if (!zoraRecipientAddress || !zoraAmount) {
      console.log("Missing recipient or amount");
      return;
    }

    // Use resolved ENS address or direct address
    const targetAddress = finalZoraRecipientAddress;

    if (!targetAddress || !isAddress(targetAddress)) {
      console.log("Invalid or unresolved address:", zoraRecipientAddress, "->", targetAddress);
      return;
    }

    try {
      // Encode the ERC20 transfer call
      const transferData = encodeFunctionData({
        abi: ERC20_ABI,
        functionName: "transfer",
        args: [targetAddress as `0x${string}`, parseUnits(zoraAmount, ZORA_DECIMALS)],
      });

      console.log("Calling exec with ZORA transfer:", {
        walletAddress,
        target: ZORA_ADDRESS_BASE,
        value: "0",
        data: transferData,
      });

      await writeExec({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "exec",
        args: [ZORA_ADDRESS_BASE, 0n, transferData],
      });

      setZoraRecipientAddress("");
      setZoraAmount("");
    } catch (error) {
      console.error("ZORA transfer failed:", error);
    }
  };

  const handleMaxZORA = () => {
    if (zoraBalance) {
      setZoraAmount(formatUnits(zoraBalance, ZORA_DECIMALS));
    }
  };

  // Passkey handlers

  // Generate a NEW passkey and register it in one flow
  const handleGeneratePasskey = async () => {
    if (!isWebAuthnSupported()) {
      setPasskeyError("WebAuthn is not supported in this browser");
      return;
    }

    setIsGeneratingPasskey(true);
    setPasskeyError(null);

    try {
      // Create a new passkey - this returns qx, qy, credentialId
      const result = await createPasskey();
      const stored: StoredPasskey = {
        credentialId: result.credentialId,
        qx: result.qx,
        qy: result.qy,
        passkeyAddress: result.passkeyAddress,
      };

      // Save to localStorage for convenience
      savePasskeyToStorage(walletAddress, stored);
      setCurrentPasskey(stored);
    } catch (error) {
      console.error("Failed to generate passkey:", error);
      setPasskeyError(error instanceof Error ? error.message : "Failed to generate passkey");
    } finally {
      setIsGeneratingPasskey(false);
    }
  };

  // Login with existing passkey - recovers qx/qy from signature
  // Optimized: if passkey is already registered on-chain, only needs 1 Touch ID
  const handleLoginWithPasskey = async () => {
    if (!isWebAuthnSupported()) {
      setPasskeyError("WebAuthn is not supported in this browser");
      return;
    }

    setIsLoggingIn(true);
    setPasskeyError(null);

    try {
      // Callback to check if a candidate passkey address is registered
      // This enables single-signature login for registered passkeys
      const checkIsPasskey = async (passkeyAddress: `0x${string}`): Promise<boolean> => {
        const result = await readContract(config, {
          address: walletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "isPasskey",
          args: [passkeyAddress],
        });
        return result as boolean;
      };

      // Call get() and recover public key from signature
      // If passkey is registered, only needs 1 Touch ID; otherwise needs 2
      const { credentialId, qx, qy, passkeyAddress } = await loginWithPasskey(checkIsPasskey);

      // Build the stored passkey object with recovered public key
      const stored: StoredPasskey = {
        credentialId,
        qx,
        qy,
        passkeyAddress,
      };

      // Save to localStorage for convenience
      savePasskeyToStorage(walletAddress, stored);
      setCurrentPasskey(stored);

      // Refetch registration status for this passkey
      await refetchPasskeyRegistered();
    } catch (error) {
      console.error("Failed to login with passkey:", error);
      setPasskeyError(error instanceof Error ? error.message : "Failed to login with passkey");
    } finally {
      setIsLoggingIn(false);
    }
  };

  // Add passkey - includes credentialIdHash for on-chain lookup
  const handleAddPasskey = async () => {
    if (!currentPasskey) {
      setPasskeyError("No passkey available to add");
      return;
    }

    setIsAddingPasskey(true);
    setPasskeyError(null);

    try {
      // Compute the credentialIdHash for on-chain storage
      const credentialIdHash = getCredentialIdHash(currentPasskey.credentialId);

      await writeAddPasskey({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "addPasskey",
        args: [currentPasskey.qx, currentPasskey.qy, credentialIdHash],
      });

      // Refetch registration status and passkeyCreated flag after adding
      await Promise.all([refetchPasskeyRegistered(), refetchPasskeyCreated()]);
    } catch (error) {
      console.error("Failed to add passkey:", error);
      setPasskeyError(error instanceof Error ? error.message : "Failed to add passkey");
    } finally {
      setIsAddingPasskey(false);
    }
  };

  const handleClearPasskey = () => {
    clearPasskeyFromStorage(walletAddress);
    setCurrentPasskey(null);
    setPasskeyError(null);
  };

  // Sign ETH transfer with passkey
  const handleSignWithPasskey = async () => {
    if (!currentPasskey || !finalPasskeyRecipient || !passkeyAmount) {
      setPasskeyError("Missing passkey, recipient, or amount");
      return;
    }

    if (!isAddress(finalPasskeyRecipient)) {
      setPasskeyError("Invalid recipient address");
      return;
    }

    setIsSigningWithPasskey(true);
    setPasskeyError(null);
    setSignedMetaTx(null);

    try {
      // IMPORTANT: Always fetch fresh nonce directly from chain before signing
      // This prevents stale nonce issues when signing multiple transactions in sequence
      const freshNonce = await readContract(config, {
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "nonces",
        args: [currentPasskey.passkeyAddress],
      });

      console.log("Signing with fresh nonce:", freshNonce);

      const target = finalPasskeyRecipient as `0x${string}`;
      const value = parseEther(passkeyAmount);
      const data = "0x" as `0x${string}`; // Empty data for ETH transfer
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

      // Build the challenge hash
      const challengeHash = buildChallengeHash(
        BigInt(chainId),
        walletAddress as `0x${string}`,
        target,
        value,
        data,
        freshNonce,
        deadline,
      );

      // Convert hash to Uint8Array for WebAuthn
      const challengeBytes = new Uint8Array(
        (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
      );

      // Sign with passkey
      const { auth } = await signWithPasskey(currentPasskey.credentialId, challengeBytes);

      setSignedMetaTx({
        target,
        value,
        data,
        qx: currentPasskey.qx,
        qy: currentPasskey.qy,
        deadline,
        auth,
      });
    } catch (error) {
      console.error("Failed to sign with passkey:", error);
      setPasskeyError(error instanceof Error ? error.message : "Failed to sign with passkey");
    } finally {
      setIsSigningWithPasskey(false);
    }
  };

  // Relay the signed meta transaction
  const handleRelayTransaction = async () => {
    if (!signedMetaTx) {
      setPasskeyError("No signed transaction to relay");
      return;
    }

    setIsRelaying(true);
    setPasskeyError(null);

    try {
      await writeExec({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "metaExecPasskey",
        args: [
          signedMetaTx.target,
          signedMetaTx.value,
          signedMetaTx.data,
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

      // Clear the form and signed tx on success
      setPasskeyRecipient("");
      setPasskeyAmount("");
      setSignedMetaTx(null);
      // Refetch nonce for next transaction
      await refetchPasskeyNonce();
    } catch (error) {
      console.error("Failed to relay transaction:", error);
      setPasskeyError(error instanceof Error ? error.message : "Failed to relay transaction");
    } finally {
      setIsRelaying(false);
    }
  };

  // Clear signed meta transaction
  const handleClearSignedTx = () => {
    setSignedMetaTx(null);
  };

  // Resolve ENS for quick transfer recipient
  const isQuickTransferRecipientEns = quickTransferRecipient.endsWith(".eth");
  const { data: resolvedQuickTransferRecipient } = useEnsAddress({
    name: isQuickTransferRecipientEns ? normalize(quickTransferRecipient) : undefined,
    chainId: 1,
  });
  const finalQuickTransferRecipient = isQuickTransferRecipientEns
    ? resolvedQuickTransferRecipient
    : quickTransferRecipient;

  // Quick Transfer: Get calldata from API, sign with passkey, submit to facilitator
  const handleQuickTransfer = async () => {
    if (!currentPasskey) {
      setQuickTransferError("Please log in with a passkey first");
      return;
    }

    if (!finalQuickTransferRecipient || !isAddress(finalQuickTransferRecipient)) {
      setQuickTransferError("Invalid recipient address");
      return;
    }

    if (!quickTransferAmount || parseFloat(quickTransferAmount) <= 0) {
      setQuickTransferError("Invalid amount");
      return;
    }

    setIsQuickTransferring(true);
    setQuickTransferError(null);
    setQuickTransferTxHash(null);
    setQuickTransferStatus("Getting transfer data...");

    try {
      // Step 1: Get calldata from the transfer API
      const transferResponse = await fetch("/api/transfer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          asset: quickTransferAsset,
          amount: quickTransferAmount,
          to: finalQuickTransferRecipient,
        }),
      });

      const transferData = await transferResponse.json();
      if (!transferData.success) {
        throw new Error(transferData.error || "Failed to get transfer calldata");
      }

      setQuickTransferStatus("Please sign with passkey...");

      // Step 2: Get fresh nonce and sign with passkey
      const freshNonce = await readContract(config, {
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "nonces",
        args: [currentPasskey.passkeyAddress],
        chainId: base.id,
      });

      const target = transferData.call.target as `0x${string}`;
      const value = BigInt(transferData.call.value);
      const data = transferData.call.data as `0x${string}`;
      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour

      // Build challenge hash for Base chain
      const challengeHash = buildChallengeHash(
        BigInt(base.id),
        walletAddress as `0x${string}`,
        target,
        value,
        data,
        freshNonce,
        deadline,
      );

      // Convert to bytes for WebAuthn
      const challengeBytes = new Uint8Array(
        (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
      );

      // Sign with passkey
      const { auth } = await signWithPasskey(currentPasskey.credentialId, challengeBytes);

      setQuickTransferStatus("Submitting transaction...");

      // Step 3: Submit to facilitator API
      const facilitateResponse = await fetch("/api/facilitate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          smartWalletAddress: walletAddress,
          chainId: base.id,
          isBatch: false,
          calls: [
            {
              target,
              value: value.toString(),
              data,
            },
          ],
          qx: currentPasskey.qx,
          qy: currentPasskey.qy,
          deadline: deadline.toString(),
          auth: {
            r: auth.r,
            s: auth.s,
            challengeIndex: auth.challengeIndex.toString(),
            typeIndex: auth.typeIndex.toString(),
            authenticatorData: auth.authenticatorData,
            clientDataJSON: auth.clientDataJSON,
          },
        }),
      });

      const facilitateData = await facilitateResponse.json();

      if (facilitateData.success && facilitateData.txHash) {
        setQuickTransferTxHash(facilitateData.txHash);
        setQuickTransferStatus("Transaction confirmed!");
        // Clear the form
        setQuickTransferRecipient("");
        setQuickTransferAmount("");
        // Refetch nonce
        await refetchPasskeyNonce();
      } else {
        throw new Error(facilitateData.error || "Transaction failed");
      }
    } catch (error) {
      console.error("[Quick Transfer] Error:", error);
      setQuickTransferError(error instanceof Error ? error.message : "Transfer failed");
      setQuickTransferStatus(null);
    } finally {
      setIsQuickTransferring(false);
    }
  };

  // ===========================================
  // Quick Swap Functions
  // ===========================================

  // Fetch swap quote when amount changes
  useEffect(() => {
    const fetchQuote = async () => {
      if (!debouncedSwapAmount || parseFloat(debouncedSwapAmount) <= 0) {
        setSwapQuote(null);
        return;
      }

      setIsLoadingQuote(true);
      setSwapError(null);

      try {
        const from = swapDirection === "USDC_TO_ETH" ? "USDC" : "ETH";
        const to = swapDirection === "USDC_TO_ETH" ? "ETH" : "USDC";

        const response = await fetch(`/api/swap/quote?from=${from}&to=${to}&amountIn=${debouncedSwapAmount}`);
        const data = await response.json();

        if (data.error) {
          setSwapError(data.error);
          setSwapQuote(null);
        } else {
          setSwapQuote({
            amountOut: data.amountOut,
            amountOutRaw: data.amountOutRaw,
            pricePerToken: data.pricePerToken,
          });
        }
      } catch (error) {
        console.error("[Swap Quote] Error:", error);
        setSwapError("Failed to fetch quote");
        setSwapQuote(null);
      } finally {
        setIsLoadingQuote(false);
      }
    };

    fetchQuote();
  }, [debouncedSwapAmount, swapDirection]);

  // Execute swap: get calldata, sign with passkey, submit to facilitator
  const handleQuickSwap = async () => {
    if (!currentPasskey) {
      setSwapError("Please log in with a passkey first");
      return;
    }

    if (!swapAmountIn || parseFloat(swapAmountIn) <= 0) {
      setSwapError("Invalid amount");
      return;
    }

    if (!swapQuote) {
      setSwapError("Please wait for quote");
      return;
    }

    setIsQuickSwapping(true);
    setSwapError(null);
    setSwapTxHash(null);
    setSwapStatus("Getting swap data...");

    try {
      const from = swapDirection === "USDC_TO_ETH" ? "USDC" : "ETH";
      const to = swapDirection === "USDC_TO_ETH" ? "ETH" : "USDC";

      // Apply 0.5% slippage tolerance
      const amountOutNum = parseFloat(swapQuote.amountOut);
      const amountOutMinimum = (amountOutNum * 0.995).toString();

      // Step 1: Get swap calldata from API
      const swapResponse = await fetch("/api/swap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from,
          to,
          amountIn: swapAmountIn,
          amountOutMinimum,
          recipient: walletAddress,
        }),
      });

      const swapData = await swapResponse.json();
      if (!swapData.success) {
        throw new Error(swapData.error || "Failed to get swap calldata");
      }

      setSwapStatus("Please sign with passkey...");

      // Step 2: Get fresh nonce and build challenge hash for batch
      const freshNonce = await readContract(config, {
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "nonces",
        args: [currentPasskey.passkeyAddress],
        chainId: base.id,
      });

      const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour

      // Convert calls from API response to proper format
      const calls = swapData.calls.map((call: { target: string; value: string; data: string }) => ({
        target: call.target as `0x${string}`,
        value: BigInt(call.value),
        data: call.data as `0x${string}`,
      }));

      // Build challenge hash - use batch format for multiple calls, single format for one call
      let challengeHash: `0x${string}`;
      if (calls.length > 1) {
        // Import buildBatchChallengeHash for multi-call transactions
        const { buildBatchChallengeHash } = await import("~~/utils/passkey");
        challengeHash = buildBatchChallengeHash(
          BigInt(base.id),
          walletAddress as `0x${string}`,
          calls,
          freshNonce,
          deadline,
        );
      } else {
        // Single call - use single tx challenge hash
        const call = calls[0];
        challengeHash = buildChallengeHash(
          BigInt(base.id),
          walletAddress as `0x${string}`,
          call.target,
          call.value,
          call.data,
          freshNonce,
          deadline,
        );
      }

      // Convert to bytes for WebAuthn
      const challengeBytes = new Uint8Array(
        (challengeHash.slice(2).match(/.{2}/g) || []).map(byte => parseInt(byte, 16)),
      );

      // Sign with passkey
      const { auth } = await signWithPasskey(currentPasskey.credentialId, challengeBytes);

      setSwapStatus("Submitting transaction...");

      // Step 3: Submit to facilitator API
      const facilitateResponse = await fetch("/api/facilitate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          smartWalletAddress: walletAddress,
          chainId: base.id,
          isBatch: calls.length > 1,
          calls: calls.map((c: { target: string; value: bigint; data: string }) => ({
            target: c.target,
            value: c.value.toString(),
            data: c.data,
          })),
          qx: currentPasskey.qx,
          qy: currentPasskey.qy,
          deadline: deadline.toString(),
          auth: {
            r: auth.r,
            s: auth.s,
            challengeIndex: auth.challengeIndex.toString(),
            typeIndex: auth.typeIndex.toString(),
            authenticatorData: auth.authenticatorData,
            clientDataJSON: auth.clientDataJSON,
          },
        }),
      });

      const facilitateData = await facilitateResponse.json();

      if (facilitateData.success && facilitateData.txHash) {
        setSwapTxHash(facilitateData.txHash);
        setSwapStatus("Swap completed!");
        // Clear the form
        setSwapAmountIn("");
        setSwapQuote(null);
        // Refetch nonce
        await refetchPasskeyNonce();
      } else {
        throw new Error(facilitateData.error || "Swap failed");
      }
    } catch (error) {
      console.error("[Quick Swap] Error:", error);
      setSwapError(error instanceof Error ? error.message : "Swap failed");
      setSwapStatus(null);
    } finally {
      setIsQuickSwapping(false);
    }
  };

  // ===========================================
  // Pending Transaction Queue Handlers
  // ===========================================

  // Add a transaction to the pending queue (called by Impersonator, WalletConnect, etc.)
  const addPendingTransaction = (pendingTx: PendingTransaction) => {
    setPendingTransactions(prev => [...prev, pendingTx]);
  };

  // Update the status of a pending transaction
  const updatePendingStatus = (id: string, status: PendingTransactionStatus, error?: string) => {
    setPendingTransactions(prev => prev.map(tx => (tx.id === id ? { ...tx, status, error: error || tx.error } : tx)));
  };

  // Remove a pending transaction
  const removePendingTransaction = (id: string) => {
    setPendingTransactions(prev => prev.filter(tx => tx.id !== id));
  };

  // Add a signed transaction
  const addSignedTransaction = (signedTx: SignedTransaction) => {
    setSignedTransactions(prev => [...prev, signedTx]);
  };

  // Remove a signed transaction
  const removeSignedTransaction = (pendingTxId: string) => {
    setSignedTransactions(prev => prev.filter(tx => tx.pendingTxId !== pendingTxId));
  };

  // Handler for Impersonator sendTransaction - adds to queue instead of executing
  const handleImpersonatorTransaction = (tx: {
    to?: string;
    value?: string | bigint;
    data?: string;
  }): Promise<string> => {
    return new Promise((resolve, reject) => {
      try {
        const pendingTx = createPendingTransaction(
          "impersonator",
          [
            {
              target: (tx.to || "0x0000000000000000000000000000000000000000") as `0x${string}`,
              value: BigInt(tx.value?.toString() || "0"),
              data: (tx.data || "0x") as `0x${string}`,
            },
          ],
          {
            appName: "Impersonator dApp",
            appUrl: debouncedAppUrl,
          },
        );

        addPendingTransaction(pendingTx);

        // Return a placeholder hash - the actual tx will be relayed after signing
        // This allows the dApp to continue its flow
        resolve(`0x${"0".repeat(64)}` as `0x${string}`);
      } catch (error) {
        reject(error);
      }
    });
  };

  const handleSwapUSDCtoETH = async () => {
    try {
      // Amount: 0.01 USDC = 10000 (6 decimals)
      const swapAmount = 10000n;

      // 1. Encode USDC approve call
      const approveData = encodeFunctionData({
        abi: ERC20_ABI,
        functionName: "approve",
        args: [SWAP_ROUTER_ADDRESS, swapAmount],
      });

      // 2. Encode exactInputSingle call (USDC -> WETH, recipient = SwapRouter)
      const swapData = encodeFunctionData({
        abi: SWAP_ROUTER_ABI,
        functionName: "exactInputSingle",
        args: [
          {
            tokenIn: USDC_ADDRESS_BASE,
            tokenOut: WETH_ADDRESS_BASE,
            fee: 500, // 0.05% fee tier
            recipient: SWAP_ROUTER_ADDRESS, // WETH goes to router temporarily
            amountIn: swapAmount,
            amountOutMinimum: 0n, // No slippage protection for demo
            sqrtPriceLimitX96: 0n,
          },
        ],
      });

      // 3. Encode unwrapWETH9 call (unwrap WETH to ETH, send to wallet)
      const unwrapData = encodeFunctionData({
        abi: SWAP_ROUTER_ABI,
        functionName: "unwrapWETH9",
        args: [0n, walletAddress as `0x${string}`],
      });

      console.log("Executing swap batch:", {
        approve: { target: USDC_ADDRESS_BASE, data: approveData },
        swap: { target: SWAP_ROUTER_ADDRESS, data: swapData },
        unwrap: { target: SWAP_ROUTER_ADDRESS, data: unwrapData },
      });

      // Execute all 3 calls atomically via batchExec
      await writeBatchExec({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "batchExec",
        args: [
          [
            { target: USDC_ADDRESS_BASE, value: 0n, data: approveData },
            { target: SWAP_ROUTER_ADDRESS, value: 0n, data: swapData },
            { target: SWAP_ROUTER_ADDRESS, value: 0n, data: unwrapData },
          ],
        ],
      });

      console.log("Swap completed successfully!");
    } catch (error) {
      console.error("Swap failed:", error);
    }
  };

  // Parse value string to bigint (supports both ETH notation like "0.1" and raw wei)
  const parseValueString = (value: string): bigint => {
    // If it's a very large number string (likely wei), parse directly
    if (/^\d{10,}$/.test(value)) {
      return BigInt(value);
    }
    // Otherwise treat as ETH amount
    return parseEther(value || "0");
  };

  // Parse and validate raw transaction JSON
  const handleParseRawTx = () => {
    setParseError(null);
    setParsedTx(null);

    if (!rawTxJson.trim()) {
      setParseError("Please enter transaction JSON");
      return;
    }

    try {
      const parsed = JSON.parse(rawTxJson);

      // Check if it's a batch transaction
      if (parsed.calls && Array.isArray(parsed.calls)) {
        const calls = parsed.calls.map((call: { target: string; value: string; data: string }, index: number) => {
          if (!call.target || !isAddress(call.target)) {
            throw new Error(`Invalid target address in call ${index + 1}`);
          }
          if (!call.data || !isHex(call.data)) {
            throw new Error(`Invalid data in call ${index + 1} (must be hex string starting with 0x)`);
          }
          return {
            target: call.target,
            value: parseValueString(call.value || "0"),
            data: call.data as `0x${string}`,
          };
        });

        setParsedTx({ isBatch: true, calls });
      }
      // Single transaction
      else if (parsed.target) {
        if (!isAddress(parsed.target)) {
          throw new Error("Invalid target address");
        }
        if (!parsed.data || !isHex(parsed.data)) {
          throw new Error("Invalid data (must be hex string starting with 0x)");
        }

        setParsedTx({
          isBatch: false,
          calls: [
            {
              target: parsed.target,
              value: parseValueString(parsed.value || "0"),
              data: parsed.data as `0x${string}`,
            },
          ],
        });
      } else {
        throw new Error("Invalid format. Expected { target, value, data } or { calls: [...] }");
      }
    } catch (error) {
      if (error instanceof SyntaxError) {
        setParseError("Invalid JSON syntax");
      } else if (error instanceof Error) {
        setParseError(error.message);
      } else {
        setParseError("Failed to parse transaction");
      }
    }
  };

  // Add the parsed raw transaction to the pending queue for passkey signing
  const handleAddRawTxToQueue = () => {
    if (!parsedTx) return;

    const pendingTx = createPendingTransaction(
      "manual",
      parsedTx.calls.map(c => ({
        target: c.target as `0x${string}`,
        value: c.value,
        data: c.data,
      })),
      {
        appName: "Raw Transaction",
      },
    );

    addPendingTransaction(pendingTx);

    // Clear the form after adding to queue
    setRawTxJson("");
    setParsedTx(null);
    console.log("Raw transaction added to queue for passkey signing");
  };

  // Clear the raw tx form
  const handleClearRawTx = () => {
    setRawTxJson("");
    setParsedTx(null);
    setParseError(null);
  };

  // Get function selector (first 4 bytes) from calldata
  const getFunctionSelector = (data: string): string => {
    if (data.length >= 10) {
      return data.slice(0, 10);
    }
    return data;
  };

  // AI Agent handler
  const handleAgentSubmit = async () => {
    if (!agentPrompt.trim()) return;

    setIsAgentLoading(true);
    setAgentError(null);
    setAgentResponse(null);

    try {
      const res = await fetch("/api/agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: agentPrompt, walletAddress }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Agent request failed");
      }

      if (data.response) {
        // Text response - display it
        setAgentResponse(data.response);
      } else if (data.calls && Array.isArray(data.calls)) {
        // Transaction batch - parse and add to pending queue
        const calls = data.calls.map((call: { target: string; value: string; data: string }) => ({
          target: call.target as `0x${string}`,
          value: BigInt(call.value || "0"),
          data: call.data as `0x${string}`,
        }));

        const pendingTx = createPendingTransaction("manual", calls, { appName: "AI Agent" });
        addPendingTransaction(pendingTx);

        // Clear prompt on success
        setAgentPrompt("");
        setAgentResponse("Transaction added to queue. Sign with your passkey below.");
      } else {
        // Unexpected format
        setAgentResponse(JSON.stringify(data, null, 2));
      }
    } catch (error) {
      console.error("Agent error:", error);
      setAgentError(error instanceof Error ? error.message : "Failed to get agent response");
    } finally {
      setIsAgentLoading(false);
    }
  };

  if (!isValidAddress) {
    return (
      <div className="flex flex-col items-center pt-10 px-4">
        <div className="max-w-2xl w-full text-center">
          <h1 className="text-4xl font-bold mb-4">Invalid Address</h1>
          <p className="opacity-70">The address provided is not a valid Ethereum address.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center pt-10 px-4">
      <div className="max-w-2xl w-full">
        <h1 className="text-4xl font-bold text-center mb-2">
          Smart Wallet {passkeyCreatedOnChain ? "(w/ passkey)" : "(needs passkey)"}
        </h1>
        <p className="text-center text-lg opacity-70 mb-8">View wallet details and permissions</p>

        {/* Wallet Info Card */}
        <div className="bg-base-200 rounded-3xl p-6 mb-8">
          <h2 className="text-2xl font-semibold mb-4">Wallet Details</h2>

          <div className="space-y-4">
            {/* Wallet Address */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">Wallet Address</p>
              <div className="flex items-center gap-2">
                <Address
                  address={walletAddress as `0x${string}`}
                  format="long"
                  chain={targetNetwork}
                  blockExplorerAddressLink={
                    targetNetwork.id === hardhat.id ? `/blockexplorer/address/${walletAddress}` : undefined
                  }
                />
                <button
                  className="btn btn-ghost btn-sm btn-circle"
                  onClick={() => setShowQRModal(true)}
                  title="Show QR Code"
                >
                  <QrCodeIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* QR Code Modal */}
            {showQRModal && (
              <div className="modal modal-open" onClick={() => setShowQRModal(false)}>
                <div className="modal-box relative" onClick={e => e.stopPropagation()}>
                  <button
                    className="btn btn-ghost btn-sm btn-circle absolute right-3 top-3"
                    onClick={() => setShowQRModal(false)}
                  >
                    ✕
                  </button>
                  <h3 className="font-bold text-lg mb-4">Wallet QR Code</h3>
                  <div className="flex flex-col items-center gap-4 py-4">
                    <QRCodeSVG value={walletAddress} size={256} />
                    <Address
                      address={walletAddress as `0x${string}`}
                      format="long"
                      disableAddressLink
                      chain={targetNetwork}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Balance */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">Balance</p>
              <div className="text-xl font-semibold">
                <Balance address={walletAddress as `0x${string}`} />
              </div>
            </div>

            {/* USDC Balance on Base */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">USDC Balance (Base)</p>
              <div className="text-xl font-semibold">
                {usdcLoading ? (
                  <span className="loading loading-spinner loading-sm"></span>
                ) : usdcBalance !== undefined ? (
                  <span>
                    {parseFloat(formatUnits(usdcBalance, 6)).toLocaleString(undefined, {
                      minimumFractionDigits: 2,
                      maximumFractionDigits: 2,
                    })}{" "}
                    USDC
                  </span>
                ) : (
                  <span className="opacity-60">Unable to load</span>
                )}
              </div>
            </div>

            {/* ZORA Balance on Base */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">ZORA Balance (Base)</p>
              <div className="text-xl font-semibold">
                {zoraLoading ? (
                  <span className="loading loading-spinner loading-sm"></span>
                ) : zoraBalance !== undefined ? (
                  <span>
                    {parseFloat(formatUnits(zoraBalance, 18)).toLocaleString(undefined, {
                      minimumFractionDigits: 2,
                      maximumFractionDigits: 6,
                    })}{" "}
                    ZORA
                  </span>
                ) : (
                  <span className="opacity-60">Unable to load</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Quick Transfer Section */}
        {currentPasskey && isPasskeyRegistered && (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Quick Transfer (Gasless)</h2>
            <p className="text-sm opacity-70 mb-4">Transfer ETH or USDC instantly with your passkey - no gas fees!</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              {/* Asset Selection */}
              <div>
                <label className="label">
                  <span className="label-text">Asset</span>
                </label>
                <select
                  className="select select-bordered w-full"
                  value={quickTransferAsset}
                  onChange={e => setQuickTransferAsset(e.target.value as "ETH" | "USDC")}
                  disabled={isQuickTransferring}
                >
                  <option value="ETH">
                    ETH ({ethBalance ? parseFloat(formatEther(ethBalance.value)).toFixed(4) : "0"})
                  </option>
                  <option value="USDC">
                    USDC (
                    {usdcBalance !== undefined
                      ? parseFloat(formatUnits(usdcBalance, 6)).toLocaleString(undefined, { maximumFractionDigits: 2 })
                      : "0"}
                    )
                  </option>
                </select>
              </div>

              {/* Amount Input */}
              <div>
                <label className="label">
                  <span className="label-text">Amount</span>
                  <span
                    className="label-text-alt cursor-pointer hover:underline"
                    onClick={() => {
                      if (quickTransferAsset === "ETH" && ethBalance) {
                        setQuickTransferAmount(formatEther(ethBalance.value));
                      } else if (quickTransferAsset === "USDC" && usdcBalance !== undefined) {
                        setQuickTransferAmount(formatUnits(usdcBalance, 6));
                      }
                    }}
                  >
                    Max
                  </span>
                </label>
                <input
                  type="number"
                  placeholder="0.0"
                  className="input input-bordered w-full"
                  value={quickTransferAmount}
                  onChange={e => setQuickTransferAmount(e.target.value)}
                  disabled={isQuickTransferring}
                  step="any"
                  min="0"
                />
              </div>
            </div>

            {/* Recipient Input */}
            <div className="mb-4">
              <label className="label">
                <span className="label-text">Recipient Address</span>
              </label>
              <AddressInput
                value={quickTransferRecipient}
                onChange={setQuickTransferRecipient}
                placeholder="0x... or ENS name"
                disabled={isQuickTransferring}
              />
              {isQuickTransferRecipientEns && resolvedQuickTransferRecipient && (
                <p className="text-xs mt-1 opacity-70">
                  Resolved: <Address address={resolvedQuickTransferRecipient} format="short" />
                </p>
              )}
            </div>

            {/* Status Display */}
            {quickTransferStatus && (
              <div className="bg-info/10 border border-info rounded-xl p-4 mb-4">
                <div className="flex items-center gap-3">
                  {isQuickTransferring && <span className="loading loading-spinner loading-md text-info"></span>}
                  <span className={isQuickTransferring ? "text-info" : "text-success"}>{quickTransferStatus}</span>
                </div>
              </div>
            )}

            {/* Success Display */}
            {quickTransferTxHash && (
              <div className="bg-success/10 border border-success rounded-xl p-4 mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-success text-lg">✓</span>
                  <span className="text-success font-medium">Transfer Complete!</span>
                </div>
                <a
                  href={`https://basescan.org/tx/${quickTransferTxHash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="link link-primary text-sm"
                >
                  View on Basescan →
                </a>
              </div>
            )}

            {/* Error Display */}
            {quickTransferError && (
              <div className="alert alert-error mb-4">
                <span>{quickTransferError}</span>
              </div>
            )}

            {/* Transfer Button */}
            <button
              className="btn btn-primary w-full"
              onClick={handleQuickTransfer}
              disabled={
                isQuickTransferring ||
                !quickTransferRecipient ||
                !quickTransferAmount ||
                parseFloat(quickTransferAmount) <= 0
              }
            >
              {isQuickTransferring ? (
                <>
                  <span className="loading loading-spinner loading-sm"></span>
                  Processing...
                </>
              ) : (
                `Transfer ${quickTransferAmount || "0"} ${quickTransferAsset}`
              )}
            </button>
          </div>
        )}

        {/* Quick Swap Section */}
        {currentPasskey && isPasskeyRegistered && (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Quick Swap (Gasless)</h2>
            <p className="text-sm opacity-70 mb-4">
              Swap between ETH and USDC instantly with your passkey - no gas fees!
            </p>

            {/* Direction Toggle */}
            <div className="mb-4">
              <label className="label">
                <span className="label-text">Swap Direction</span>
              </label>
              <div className="btn-group w-full">
                <button
                  className={`btn flex-1 ${swapDirection === "USDC_TO_ETH" ? "btn-primary" : "btn-ghost"}`}
                  onClick={() => {
                    setSwapDirection("USDC_TO_ETH");
                    setSwapAmountIn("");
                    setSwapQuote(null);
                    setSwapError(null);
                  }}
                  disabled={isQuickSwapping}
                >
                  USDC → ETH
                </button>
                <button
                  className={`btn flex-1 ${swapDirection === "ETH_TO_USDC" ? "btn-primary" : "btn-ghost"}`}
                  onClick={() => {
                    setSwapDirection("ETH_TO_USDC");
                    setSwapAmountIn("");
                    setSwapQuote(null);
                    setSwapError(null);
                  }}
                  disabled={isQuickSwapping}
                >
                  ETH → USDC
                </button>
              </div>
            </div>

            {/* Amount Input */}
            <div className="mb-4">
              <label className="label">
                <span className="label-text">Amount ({swapDirection === "USDC_TO_ETH" ? "USDC" : "ETH"})</span>
                <span
                  className="label-text-alt cursor-pointer hover:underline"
                  onClick={() => {
                    if (swapDirection === "USDC_TO_ETH" && usdcBalance !== undefined) {
                      setSwapAmountIn(formatUnits(usdcBalance, 6));
                    } else if (swapDirection === "ETH_TO_USDC" && ethBalance) {
                      setSwapAmountIn(formatEther(ethBalance.value));
                    }
                  }}
                >
                  Max:{" "}
                  {swapDirection === "USDC_TO_ETH"
                    ? usdcBalance !== undefined
                      ? parseFloat(formatUnits(usdcBalance, 6)).toLocaleString(undefined, { maximumFractionDigits: 2 })
                      : "0"
                    : ethBalance
                      ? parseFloat(formatEther(ethBalance.value)).toFixed(4)
                      : "0"}
                </span>
              </label>
              <input
                type="number"
                placeholder="0.0"
                className="input input-bordered w-full"
                value={swapAmountIn}
                onChange={e => setSwapAmountIn(e.target.value)}
                disabled={isQuickSwapping}
                step="any"
                min="0"
              />
            </div>

            {/* Quote Display */}
            {(isLoadingQuote || swapQuote) && (
              <div className="bg-base-100 rounded-xl p-4 mb-4">
                <p className="text-sm font-medium opacity-60 mb-2">You will receive</p>
                {isLoadingQuote ? (
                  <div className="flex items-center gap-2">
                    <span className="loading loading-spinner loading-sm"></span>
                    <span className="opacity-60">Getting quote...</span>
                  </div>
                ) : swapQuote ? (
                  <div>
                    <p className="text-xl font-semibold">
                      {parseFloat(swapQuote.amountOut).toLocaleString(undefined, {
                        minimumFractionDigits: swapDirection === "USDC_TO_ETH" ? 6 : 2,
                        maximumFractionDigits: swapDirection === "USDC_TO_ETH" ? 6 : 2,
                      })}{" "}
                      {swapDirection === "USDC_TO_ETH" ? "ETH" : "USDC"}
                    </p>
                    <p className="text-xs opacity-60 mt-1">
                      Rate: 1 {swapDirection === "USDC_TO_ETH" ? "USDC" : "ETH"} = {swapQuote.pricePerToken}{" "}
                      {swapDirection === "USDC_TO_ETH" ? "ETH" : "USDC"}
                    </p>
                    <p className="text-xs opacity-60">Fee: 0.05% • Slippage: 0.5%</p>
                  </div>
                ) : null}
              </div>
            )}

            {/* Status Display */}
            {swapStatus && (
              <div className="bg-info/10 border border-info rounded-xl p-4 mb-4">
                <div className="flex items-center gap-3">
                  {isQuickSwapping && <span className="loading loading-spinner loading-md text-info"></span>}
                  <span className={isQuickSwapping ? "text-info" : "text-success"}>{swapStatus}</span>
                </div>
              </div>
            )}

            {/* Success Display */}
            {swapTxHash && (
              <div className="bg-success/10 border border-success rounded-xl p-4 mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-success text-lg">✓</span>
                  <span className="text-success font-medium">Swap Complete!</span>
                </div>
                <a
                  href={`https://basescan.org/tx/${swapTxHash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="link link-primary text-sm"
                >
                  View on Basescan →
                </a>
              </div>
            )}

            {/* Error Display */}
            {swapError && (
              <div className="alert alert-error mb-4">
                <span>{swapError}</span>
              </div>
            )}

            {/* Swap Button */}
            <button
              className="btn btn-primary w-full"
              onClick={handleQuickSwap}
              disabled={
                isQuickSwapping || !swapAmountIn || parseFloat(swapAmountIn) <= 0 || !swapQuote || isLoadingQuote
              }
            >
              {isQuickSwapping ? (
                <>
                  <span className="loading loading-spinner loading-sm"></span>
                  Processing...
                </>
              ) : (
                `Swap ${swapAmountIn || "0"} ${swapDirection === "USDC_TO_ETH" ? "USDC" : "ETH"} → ${
                  swapQuote ? parseFloat(swapQuote.amountOut).toFixed(swapDirection === "USDC_TO_ETH" ? 6 : 2) : "?"
                } ${swapDirection === "USDC_TO_ETH" ? "ETH" : "USDC"}`
              )}
            </button>
          </div>
        )}

        <div className="bg-base-200 rounded-3xl p-6 mb-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Owner */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">Owner</p>
              {ownerLoading ? (
                <span className="loading loading-spinner loading-sm"></span>
              ) : owner ? (
                <Address
                  address={owner}
                  chain={targetNetwork}
                  blockExplorerAddressLink={
                    targetNetwork.id === hardhat.id ? `/blockexplorer/address/${owner}` : undefined
                  }
                />
              ) : (
                <span className="opacity-60">Unable to read owner</span>
              )}
            </div>
          </div>
        </div>

        {/* Connected User Role */}
        {connectedAddress ? (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Your Permissions</h2>

            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-2">Connected Address</p>
              <Address
                address={connectedAddress}
                chain={targetNetwork}
                blockExplorerAddressLink={
                  targetNetwork.id === hardhat.id ? `/blockexplorer/address/${connectedAddress}` : undefined
                }
              />

              <div className="mt-4">
                <p className="text-sm font-medium opacity-60 mb-2">Role</p>
                {isLoading ? (
                  <span className="loading loading-spinner loading-sm"></span>
                ) : (
                  <div className="flex gap-2">
                    {isOwner ? (
                      <span className="badge badge-primary badge-lg">Owner</span>
                    ) : (
                      <span className="badge badge-ghost badge-lg">Viewer</span>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-base-200 rounded-3xl p-6 text-center mb-8">
            <p className="opacity-70">Connect your wallet to see your permissions</p>
          </div>
        )}

        {/* Check Passkey Status Section */}
        <div className="bg-base-200 rounded-3xl p-6 mb-8">
          <h2 className="text-2xl font-semibold mb-4">Check Passkey Status</h2>
          <p className="text-sm opacity-60 mb-4">Check if an address is a registered passkey for this wallet</p>

          <div className="space-y-4">
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-2">Address to Check</p>
              <AddressInput
                value={checkPasskeyAddress}
                onChange={value => {
                  setCheckPasskeyAddress(value);
                  setPasskeyCheckTriggered(false);
                }}
                placeholder="Enter address or ENS"
              />
            </div>

            <button
              className="btn btn-secondary w-full"
              onClick={() => setPasskeyCheckTriggered(true)}
              disabled={
                !checkPasskeyAddress ||
                !finalCheckPasskeyAddress ||
                !isAddress(finalCheckPasskeyAddress) ||
                checkingPasskey
              }
            >
              {checkingPasskey ? (
                <>
                  <span className="loading loading-spinner loading-sm"></span>
                  Checking...
                </>
              ) : (
                "Check Passkey"
              )}
            </button>

            {/* Result Display */}
            {passkeyCheckTriggered &&
              finalCheckPasskeyAddress &&
              isAddress(finalCheckPasskeyAddress) &&
              !checkingPasskey && (
                <div
                  className={`rounded-xl p-4 ${checkedAddressIsPasskey ? "bg-success/10 border border-success" : "bg-error/10 border border-error"}`}
                >
                  <div className="flex items-center gap-2">
                    <Address
                      address={finalCheckPasskeyAddress as `0x${string}`}
                      chain={targetNetwork}
                      blockExplorerAddressLink={
                        targetNetwork.id === hardhat.id
                          ? `/blockexplorer/address/${finalCheckPasskeyAddress}`
                          : undefined
                      }
                    />
                    <span className={`badge ${checkedAddressIsPasskey ? "badge-success" : "badge-error"}`}>
                      {checkedAddressIsPasskey ? "Registered Passkey" : "Not a Passkey"}
                    </span>
                  </div>
                </div>
              )}
          </div>
        </div>

        {/* Passkey Authentication Section */}
        <div className="bg-base-200 rounded-3xl p-6 mb-8">
          <h2 className="text-2xl font-semibold mb-4">Passkey Authentication</h2>
          <p className="text-sm opacity-60 mb-4">
            Use a passkey (Touch ID, Face ID, Windows Hello) to sign transactions without needing gas
          </p>

          {/* Error Display */}
          {passkeyError && (
            <div className="bg-error/10 border border-error rounded-xl p-4 mb-4">
              <p className="text-error text-sm">{passkeyError}</p>
              <button className="btn btn-xs btn-ghost mt-2" onClick={() => setPasskeyError(null)}>
                Dismiss
              </button>
            </div>
          )}

          {/* Current Passkey Status */}
          {currentPasskey ? (
            <div className="space-y-4">
              {/* Passkey Info */}
              <div className="bg-base-100 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm font-medium opacity-60">Passkey Status</p>
                  {isPasskeyRegistered ? (
                    <span className="badge badge-success">Registered</span>
                  ) : (
                    <span className="badge badge-warning">Not Registered</span>
                  )}
                </div>
                <div className="space-y-2">
                  <div>
                    <p className="text-xs opacity-60">Passkey Address</p>
                    <Address
                      address={currentPasskey.passkeyAddress}
                      chain={targetNetwork}
                      blockExplorerAddressLink={
                        targetNetwork.id === hardhat.id
                          ? `/blockexplorer/address/${currentPasskey.passkeyAddress}`
                          : undefined
                      }
                    />
                  </div>
                  <div>
                    <p className="text-xs opacity-60">Credential ID</p>
                    <p className="font-mono text-xs truncate">{currentPasskey.credentialId}</p>
                  </div>
                </div>
              </div>

              {/* Actions based on status */}
              <div className="space-y-2">
                {/* Add Passkey button - only for owner, only if not already registered */}
                {isOwner && !isPasskeyRegistered && (
                  <button className="btn btn-primary w-full" onClick={handleAddPasskey} disabled={isAddingPasskey}>
                    {isAddingPasskey ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Adding Passkey...
                      </>
                    ) : (
                      "Add Passkey"
                    )}
                  </button>
                )}

                {/* If passkey is registered, show ready message */}
                {isPasskeyRegistered && (
                  <div className="bg-success/10 border border-success rounded-xl p-4 text-center">
                    <p className="text-success font-medium">Passkey is ready to sign transactions</p>
                    <p className="text-xs opacity-70 mt-1">Use the &quot;Send ETH with Passkey&quot; section below</p>
                  </div>
                )}

                {/* Clear passkey button */}
                <button className="btn btn-ghost btn-sm w-full" onClick={handleClearPasskey}>
                  Clear Passkey
                </button>
              </div>
            </div>
          ) : (
            /* No passkey connected - show adaptive CTAs based on passkeyCreatedOnChain */
            <div className="space-y-4">
              {/* Wait for client mount to check WebAuthn support */}
              {!isMounted ? (
                <div className="flex justify-center p-4">
                  <span className="loading loading-spinner loading-md"></span>
                </div>
              ) : !isWebAuthnSupported() ? (
                <div className="bg-warning/10 border border-warning rounded-xl p-4 text-center">
                  <p className="text-warning font-medium">WebAuthn not supported</p>
                  <p className="text-xs opacity-70 mt-1">
                    Your browser doesn&apos;t support passkeys. Try Chrome, Safari, or Edge.
                  </p>
                </div>
              ) : passkeyCreatedOnChain ? (
                /* Passkey exists on-chain - show Login as PRIMARY */
                <>
                  <button
                    className="btn btn-primary w-full btn-lg"
                    onClick={handleLoginWithPasskey}
                    disabled={isLoggingIn || isGeneratingPasskey}
                  >
                    {isLoggingIn ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Logging in...
                      </>
                    ) : (
                      "Login with Passkey"
                    )}
                  </button>
                  <p className="text-xs text-center opacity-60">Use your existing registered passkey</p>

                  {/* Secondary: Add New Passkey */}
                  <div className="divider text-xs opacity-60">OR</div>
                  <button
                    className="btn btn-ghost btn-sm w-full"
                    onClick={handleGeneratePasskey}
                    disabled={isGeneratingPasskey || isLoggingIn}
                  >
                    {isGeneratingPasskey ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Generating...
                      </>
                    ) : (
                      "Add New Passkey"
                    )}
                  </button>
                  <p className="text-xs text-center opacity-60">Generate a new passkey on this device</p>
                </>
              ) : (
                /* No passkey on-chain yet - show Generate as PRIMARY, Login as SECONDARY */
                <>
                  <button
                    className="btn btn-primary w-full btn-lg"
                    onClick={handleGeneratePasskey}
                    disabled={isGeneratingPasskey || isLoggingIn}
                  >
                    {isGeneratingPasskey ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Generating...
                      </>
                    ) : (
                      "Generate New Passkey"
                    )}
                  </button>
                  <p className="text-xs text-center opacity-60">
                    Create your first passkey to enable gasless transactions
                  </p>
                  <div className="divider text-xs opacity-60">OR</div>
                  <button
                    className="btn btn-ghost btn-sm w-full"
                    onClick={handleLoginWithPasskey}
                    disabled={isGeneratingPasskey || isLoggingIn}
                  >
                    {isLoggingIn ? (
                      <>
                        <span className="loading loading-spinner loading-xs"></span>
                        Authenticating...
                      </>
                    ) : (
                      "Login with Existing Passkey"
                    )}
                  </button>
                  <p className="text-xs text-center opacity-60">Use a passkey you already have on this device</p>
                </>
              )}
            </div>
          )}
        </div>

        {/* Pending Transaction Queue - Shows transactions from Impersonator, WalletConnect, etc. */}
        {pendingTransactions.length > 0 && (
          <PendingTransactionQueue
            smartWalletAddress={walletAddress}
            pendingTransactions={pendingTransactions}
            signedTransactions={signedTransactions}
            currentPasskey={currentPasskey}
            isPasskeyRegistered={!!isPasskeyRegistered}
            passkeyNonce={passkeyNonce}
            onUpdatePendingStatus={updatePendingStatus}
            onRemovePending={removePendingTransaction}
            onAddSigned={addSignedTransaction}
            onRemoveSigned={removeSignedTransaction}
            refetchPasskeyNonce={async () => {
              await refetchPasskeyNonce();
            }}
          />
        )}

        {/* Send ETH with Passkey Section - Only when passkey is registered */}
        {currentPasskey && isPasskeyRegistered && (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Send ETH with Passkey</h2>
            <p className="text-sm opacity-60 mb-4">
              Sign a transaction with your passkey. Anyone can then relay it to the network and pay the gas.
            </p>

            <div className="space-y-4">
              {/* Recipient Address */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Recipient Address</p>
                <AddressInput
                  value={passkeyRecipient}
                  onChange={setPasskeyRecipient}
                  placeholder="Enter recipient address or ENS"
                />
              </div>

              {/* Amount */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Amount (ETH)</p>
                <input
                  type="text"
                  placeholder="0.0"
                  value={passkeyAmount}
                  onChange={e => setPasskeyAmount(e.target.value)}
                  className="input input-bordered w-full"
                />
              </div>

              {/* Sign Button */}
              <button
                className="btn btn-primary w-full"
                onClick={handleSignWithPasskey}
                disabled={
                  isSigningWithPasskey ||
                  !passkeyRecipient ||
                  !passkeyAmount ||
                  !finalPasskeyRecipient ||
                  !isAddress(finalPasskeyRecipient)
                }
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

              {/* Signed Transaction Display */}
              {signedMetaTx && (
                <div className="bg-base-100 rounded-xl p-4 space-y-4">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-success">Transaction Signed!</p>
                    <button className="btn btn-xs btn-ghost" onClick={handleClearSignedTx}>
                      Clear
                    </button>
                  </div>

                  {/* Transaction Summary */}
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="opacity-60">To:</span>
                      <Address
                        address={signedMetaTx.target}
                        chain={targetNetwork}
                        blockExplorerAddressLink={
                          targetNetwork.id === hardhat.id ? `/blockexplorer/address/${signedMetaTx.target}` : undefined
                        }
                      />
                    </div>
                    <div className="flex justify-between">
                      <span className="opacity-60">Amount:</span>
                      <span>{formatEther(signedMetaTx.value)} ETH</span>
                    </div>
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
                            target: signedMetaTx.target,
                            value: signedMetaTx.value.toString(),
                            data: signedMetaTx.data,
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
                              target: signedMetaTx.target,
                              value: signedMetaTx.value.toString(),
                              data: signedMetaTx.data,
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
                  <button className="btn btn-secondary w-full" onClick={handleRelayTransaction} disabled={isRelaying}>
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
                  <p className="text-xs text-center opacity-60">
                    The relayer pays gas. The passkey holder pays nothing.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Transfer ETH Section - Only for owners */}
        {connectedAddress && hasPermissions && !isLoading && (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Transfer ETH</h2>
            <p className="text-sm opacity-60 mb-4">Send ETH from this smart wallet to any address</p>

            <div className="space-y-4">
              {/* Recipient Address */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Recipient Address</p>
                <AddressInput
                  value={recipientAddress}
                  onChange={setRecipientAddress}
                  placeholder="Enter recipient address"
                />
              </div>

              {/* Amount */}
              <div className="bg-base-100 rounded-xl p-4">
                <div className="flex justify-between items-center mb-2">
                  <p className="text-sm font-medium opacity-60">Amount (ETH)</p>
                  <button onClick={handleMaxETH} className="btn btn-xs btn-ghost" disabled={!ethBalance}>
                    [max]
                  </button>
                </div>
                <input
                  type="text"
                  placeholder="0.0"
                  value={ethAmount}
                  onChange={e => setEthAmount(e.target.value)}
                  className="input input-bordered w-full"
                />
              </div>

              {/* Transfer Button */}
              <button
                className="btn btn-primary w-full"
                onClick={handleTransferETH}
                disabled={
                  isTransferPending ||
                  !recipientAddress ||
                  !ethAmount ||
                  !finalRecipientAddress ||
                  !isAddress(finalRecipientAddress)
                }
              >
                {isTransferPending ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Transferring...
                  </>
                ) : (
                  "Transfer ETH"
                )}
              </button>
            </div>
          </div>
        )}

        {/* Transfer USDC Section - Only for owners */}
        {connectedAddress && hasPermissions && !isLoading && (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-2xl font-semibold mb-4">Transfer USDC</h2>
            <p className="text-sm opacity-60 mb-4">Send USDC from this smart wallet to any address (Base network)</p>

            <div className="space-y-4">
              {/* Recipient Address */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Recipient Address</p>
                <AddressInput
                  value={usdcRecipientAddress}
                  onChange={setUsdcRecipientAddress}
                  placeholder="Enter recipient address"
                />
              </div>

              {/* Amount */}
              <div className="bg-base-100 rounded-xl p-4">
                <div className="flex justify-between items-center mb-2">
                  <p className="text-sm font-medium opacity-60">Amount (USDC)</p>
                  <button onClick={handleMaxUSDC} className="btn btn-xs btn-ghost" disabled={!usdcBalance}>
                    [max]
                  </button>
                </div>
                <input
                  type="text"
                  placeholder="0.00"
                  value={usdcAmount}
                  onChange={e => setUsdcAmount(e.target.value)}
                  className="input input-bordered w-full"
                />
              </div>

              {/* Transfer Button */}
              <button
                className="btn btn-primary w-full"
                onClick={handleTransferUSDC}
                disabled={
                  isTransferPending ||
                  !usdcRecipientAddress ||
                  !usdcAmount ||
                  !finalUsdcRecipientAddress ||
                  !isAddress(finalUsdcRecipientAddress)
                }
              >
                {isTransferPending ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Transferring...
                  </>
                ) : (
                  "Transfer USDC"
                )}
              </button>
            </div>
          </div>
        )}

        {/* Transfer ZORA Section - Only for owners */}
        {connectedAddress && hasPermissions && !isLoading && (
          <div className="bg-base-200 rounded-3xl p-6">
            <h2 className="text-2xl font-semibold mb-4">Transfer ZORA</h2>
            <p className="text-sm opacity-60 mb-4">Send ZORA from this smart wallet to any address (Base network)</p>

            <div className="space-y-4">
              {/* Recipient Address */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Recipient Address</p>
                <AddressInput
                  value={zoraRecipientAddress}
                  onChange={setZoraRecipientAddress}
                  placeholder="Enter recipient address"
                />
              </div>

              {/* Amount */}
              <div className="bg-base-100 rounded-xl p-4">
                <div className="flex justify-between items-center mb-2">
                  <p className="text-sm font-medium opacity-60">Amount (ZORA)</p>
                  <button onClick={handleMaxZORA} className="btn btn-xs btn-ghost" disabled={!zoraBalance}>
                    [max]
                  </button>
                </div>
                <input
                  type="text"
                  placeholder="0.0"
                  value={zoraAmount}
                  onChange={e => setZoraAmount(e.target.value)}
                  className="input input-bordered w-full"
                />
              </div>

              {/* Transfer Button */}
              <button
                className="btn btn-primary w-full"
                onClick={handleTransferZORA}
                disabled={
                  isTransferPending ||
                  !zoraRecipientAddress ||
                  !zoraAmount ||
                  !finalZoraRecipientAddress ||
                  !isAddress(finalZoraRecipientAddress)
                }
              >
                {isTransferPending ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Transferring...
                  </>
                ) : (
                  "Transfer ZORA"
                )}
              </button>
            </div>
          </div>
        )}

        {/* Swap USDC to ETH Section - Only for owners */}
        {connectedAddress && hasPermissions && !isLoading && (
          <div className="bg-base-200 rounded-3xl p-6 mt-8">
            <h2 className="text-2xl font-semibold mb-4">Swap</h2>
            <p className="text-sm opacity-60 mb-4">Swap USDC to ETH using Uniswap V3 on Base (0.05% fee tier)</p>

            <div className="bg-base-100 rounded-xl p-4">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium opacity-60">You pay</p>
                  <p className="text-xl font-semibold">0.01 USDC</p>
                </div>
                <div className="text-2xl">→</div>
                <div className="text-right">
                  <p className="text-sm font-medium opacity-60">You receive</p>
                  <p className="text-xl font-semibold">~ETH</p>
                </div>
              </div>

              <button
                className="btn btn-secondary w-full"
                onClick={handleSwapUSDCtoETH}
                disabled={isSwapping || !usdcBalance || usdcBalance < 10000n}
              >
                {isSwapping ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Swapping...
                  </>
                ) : (
                  "Swap 0.01 USDC to ETH"
                )}
              </button>

              {usdcBalance !== undefined && usdcBalance < 10000n && (
                <p className="text-xs text-error mt-2 text-center">
                  Insufficient USDC balance (need at least 0.01 USDC)
                </p>
              )}
            </div>
          </div>
        )}

        {/* AI Agent Section - For passkey holders */}
        {currentPasskey && isPasskeyRegistered && (
          <div className="bg-base-200 rounded-3xl p-6 mt-8">
            <h2 className="text-2xl font-semibold mb-4">AI Agent</h2>
            <p className="text-sm opacity-60 mb-4">
              Describe what you want to do in plain English. The AI will generate the transaction for you.
            </p>

            <div className="space-y-4">
              {/* Prompt Input */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">What do you want to do?</p>
                <textarea
                  className="textarea textarea-bordered w-full"
                  rows={3}
                  placeholder="e.g., Send all my USDC to 0x1234... or How much ETH do I have?"
                  value={agentPrompt}
                  onChange={e => {
                    setAgentPrompt(e.target.value);
                    setAgentResponse(null);
                    setAgentError(null);
                  }}
                  onKeyDown={e => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      handleAgentSubmit();
                    }
                  }}
                />
              </div>

              {/* Error Display */}
              {agentError && (
                <div className="bg-error/10 border border-error rounded-xl p-4">
                  <p className="text-error text-sm">{agentError}</p>
                </div>
              )}

              {/* Response Display */}
              {agentResponse && (
                <div className="bg-success/10 border border-success rounded-xl p-4">
                  <p className="text-sm">{agentResponse}</p>
                </div>
              )}

              {/* Submit Button */}
              <button
                className="btn btn-primary w-full"
                onClick={handleAgentSubmit}
                disabled={isAgentLoading || !agentPrompt.trim()}
              >
                {isAgentLoading ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Thinking...
                  </>
                ) : (
                  "Ask AI Agent"
                )}
              </button>
            </div>
          </div>
        )}

        {/* Raw Transaction Section - For passkey holders */}
        {currentPasskey && isPasskeyRegistered && (
          <div className="bg-base-200 rounded-3xl p-6 mt-8">
            <h2 className="text-2xl font-semibold mb-4">Raw Transaction</h2>
            <p className="text-sm opacity-60 mb-4">
              Paste transaction JSON from GPT or other sources. Sign with your passkey, then anyone can relay it.
            </p>

            {/* Example for AI prompt */}
            <details className="mb-4">
              <summary className="cursor-pointer text-sm font-medium opacity-70 hover:opacity-100">
                📋 Copy example prompt for AI
              </summary>
              <div className="mt-2 bg-base-100 rounded-xl p-4">
                <p className="text-xs opacity-60 mb-2">Copy this to GPT/Claude and describe what you want to do:</p>
                <pre className="text-xs font-mono bg-base-300 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
                  {`Generate a transaction JSON for my smart wallet.

My wallet address: ${walletAddress}

Format for single transaction:
{
  "target": "0xContractAddress",
  "value": "0",
  "data": "0xEncodedCalldata"
}

Format for batch transactions:
{
  "calls": [
    { "target": "0x...", "value": "0", "data": "0x..." },
    { "target": "0x...", "value": "0", "data": "0x..." }
  ]
}

Notes:
- "value" is ETH to send (use "0" for no ETH)
- "data" is the ABI-encoded function call
- Use viem/ethers encodeFunctionData format

Example batch (approve + swap):
{
  "calls": [
    {
      "target": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "value": "0",
      "data": "0x095ea7b30000000000000000000000002626664c2603336e57b271c5c0b26f421741e4810000000000000000000000000000000000000000000000000000000000002710"
    },
    {
      "target": "0x2626664c2603336E57B271c5C0b26F421741e481",
      "value": "0",
      "data": "0x..."
    }
  ]
}

What I want to do: [DESCRIBE YOUR TRANSACTION HERE]`}
                </pre>
                <button
                  className="btn btn-xs btn-ghost mt-2"
                  onClick={() => {
                    navigator.clipboard.writeText(`Generate a transaction JSON for my smart wallet.

My wallet address: ${walletAddress}

Format for single transaction:
{
  "target": "0xContractAddress",
  "value": "0",
  "data": "0xEncodedCalldata"
}

Format for batch transactions:
{
  "calls": [
    { "target": "0x...", "value": "0", "data": "0x..." },
    { "target": "0x...", "value": "0", "data": "0x..." }
  ]
}

Notes:
- "value" is ETH to send (use "0" for no ETH)
- "data" is the ABI-encoded function call
- Use viem/ethers encodeFunctionData format

Example batch (approve + swap):
{
  "calls": [
    {
      "target": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "value": "0",
      "data": "0x095ea7b30000000000000000000000002626664c2603336e57b271c5c0b26f421741e4810000000000000000000000000000000000000000000000000000000000002710"
    },
    {
      "target": "0x2626664c2603336E57B271c5C0b26F421741e481",
      "value": "0",
      "data": "0x..."
    }
  ]
}

What I want to do: `);
                  }}
                >
                  Copy to clipboard
                </button>
              </div>
            </details>

            <div className="space-y-4">
              {/* JSON Input */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Transaction JSON</p>
                <textarea
                  className="textarea textarea-bordered w-full font-mono text-sm"
                  rows={8}
                  placeholder={`{
  "target": "0x...",
  "value": "0",
  "data": "0x..."
}

// Or for batch:
{
  "calls": [
    { "target": "0x...", "value": "0", "data": "0x..." }
  ]
}`}
                  value={rawTxJson}
                  onChange={e => {
                    setRawTxJson(e.target.value);
                    setParsedTx(null);
                    setParseError(null);
                  }}
                />
              </div>

              {/* Parse Error */}
              {parseError && (
                <div className="bg-error/10 border border-error rounded-xl p-4">
                  <p className="text-error text-sm font-medium">{parseError}</p>
                </div>
              )}

              {/* Parse/Clear Buttons */}
              <div className="flex gap-2">
                <button className="btn btn-secondary flex-1" onClick={handleParseRawTx} disabled={!rawTxJson.trim()}>
                  Parse Transaction
                </button>
                <button className="btn btn-ghost" onClick={handleClearRawTx} disabled={!rawTxJson && !parsedTx}>
                  Clear
                </button>
              </div>

              {/* Parsed Transaction Preview */}
              {parsedTx && (
                <div className="bg-base-100 rounded-xl p-4 space-y-4">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium">
                      {parsedTx.isBatch ? `Batch Transaction (${parsedTx.calls.length} calls)` : "Single Transaction"}
                    </p>
                    <span className="badge badge-info">{parsedTx.isBatch ? "batchExec" : "exec"}</span>
                  </div>

                  {/* Call Details */}
                  {parsedTx.calls.map((call, index) => (
                    <div
                      key={index}
                      className={`p-3 rounded-lg ${parsedTx.isBatch ? "bg-base-200" : ""} ${
                        parsedTx.isBatch && index > 0 ? "mt-2" : ""
                      }`}
                    >
                      {parsedTx.isBatch && <p className="text-xs font-medium opacity-60 mb-2">Call {index + 1}</p>}

                      <div className="space-y-2">
                        {/* Target */}
                        <div>
                          <p className="text-xs opacity-60">Target</p>
                          <Address
                            address={call.target as `0x${string}`}
                            chain={targetNetwork}
                            blockExplorerAddressLink={
                              targetNetwork.id === hardhat.id ? `/blockexplorer/address/${call.target}` : undefined
                            }
                          />
                        </div>

                        {/* Value */}
                        <div>
                          <p className="text-xs opacity-60">Value</p>
                          <p className="font-mono">{call.value > 0n ? `${formatEther(call.value)} ETH` : "0 ETH"}</p>
                        </div>

                        {/* Function Selector */}
                        <div>
                          <p className="text-xs opacity-60">Function Selector</p>
                          <p className="font-mono text-sm">{getFunctionSelector(call.data)}</p>
                        </div>

                        {/* Data */}
                        <div>
                          <p className="text-xs opacity-60">Calldata ({call.data.length} chars)</p>
                          <p className="font-mono text-xs break-all opacity-70">
                            {call.data.length > 100 ? `${call.data.slice(0, 100)}...` : call.data}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}

                  {/* Add to Queue Button */}
                  <button className="btn btn-primary w-full" onClick={handleAddRawTxToQueue}>
                    Add to Pending Queue (Sign with Passkey)
                  </button>
                  <p className="text-xs text-center opacity-60">
                    Sign with your passkey, then anyone can relay the transaction
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* WalletConnect Section - Always visible */}
        <WalletConnectSection
          smartWalletAddress={walletAddress}
          currentPasskey={currentPasskey}
          isPasskeyOperator={!!isPasskeyRegistered}
          passkeyNonce={passkeyNonce}
          refetchPasskeyNonce={async () => {
            await refetchPasskeyNonce();
          }}
        />
      </div>

      {/* Impersonator Section - Available when passkey is registered (full width) */}
      {isValidAddress && (
        <div className="w-full max-w-7xl px-4 mt-8">
          <div className="bg-base-200 rounded-3xl p-6">
            <h2 className="text-2xl font-semibold mb-4">Impersonate at dApp</h2>
            <p className="text-sm opacity-60 mb-4">
              Enter a dApp URL to interact with it as this smart wallet on Base network. Transactions will be queued for
              passkey signing.
            </p>

            {/* Passkey requirement notice */}
            {!currentPasskey && (
              <div className="bg-warning/10 border border-warning rounded-xl p-4 mb-4">
                <p className="text-warning text-sm">Login with a passkey above to sign transactions from dApps</p>
              </div>
            )}

            {!isPasskeyRegistered && currentPasskey && (
              <div className="bg-warning/10 border border-warning rounded-xl p-4 mb-4">
                <p className="text-warning text-sm">Add your passkey to this wallet above to sign transactions</p>
              </div>
            )}

            <div className="space-y-4">
              {/* URL Input */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">dApp URL</p>
                <input
                  type="text"
                  className="input input-bordered w-full"
                  placeholder="https://app.uniswap.org"
                  value={appUrl}
                  onChange={e => setAppUrl(e.target.value)}
                />
              </div>

              {/* Iframe */}
              {debouncedAppUrl && walletAddress && (
                <div className="border-2 border-base-300 rounded-xl overflow-hidden">
                  <ImpersonatorIframeProvider
                    address={walletAddress}
                    rpcUrl={getImpersonatorRpcUrl(targetNetwork.id)}
                    sendTransaction={handleImpersonatorTransaction}
                  >
                    <ImpersonatorIframe
                      key={debouncedAppUrl + walletAddress + targetNetwork.id}
                      src={debouncedAppUrl}
                      address={walletAddress}
                      rpcUrl={getImpersonatorRpcUrl(targetNetwork.id)}
                      width="100%"
                      height="1200px"
                    />
                  </ImpersonatorIframeProvider>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WalletPage;
