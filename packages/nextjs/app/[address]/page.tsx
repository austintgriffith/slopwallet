"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { ImpersonatorIframe, ImpersonatorIframeProvider } from "@impersonator/iframe";
import { Address, AddressInput, Balance } from "@scaffold-ui/components";
import { useDebounceValue } from "usehooks-ts";
import { encodeFunctionData, formatEther, formatUnits, isAddress, isHex, parseEther, parseUnits } from "viem";
import { base } from "viem/chains";
import { normalize } from "viem/ens";
import { useAccount, useBalance, useEnsAddress, useReadContract, useWriteContract } from "wagmi";
import { WalletConnectSection } from "~~/components/scaffold-eth";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import scaffoldConfig from "~~/scaffold.config";

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

// Base RPC URL for Impersonator
const BASE_RPC_URL =
  scaffoldConfig.alchemyApiKey && scaffoldConfig.alchemyApiKey !== "oKxs-03sij-U_N0iOlrSsZFr29-IqbuF"
    ? `https://base-mainnet.g.alchemy.com/v2/${scaffoldConfig.alchemyApiKey}`
    : "https://mainnet.base.org";

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

  // Operator management state
  const [newOperatorAddress, setNewOperatorAddress] = useState("");
  const [removeOperatorAddress, setRemoveOperatorAddress] = useState("");

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

  // Resolve ENS name if needed
  const isEnsName = recipientAddress.endsWith(".eth");
  const { data: resolvedEnsAddress } = useEnsAddress({
    name: isEnsName ? normalize(recipientAddress) : undefined,
    chainId: 1, // ENS resolution on mainnet
  });

  // Get the final address to use (resolved ENS or direct address)
  const finalRecipientAddress = isEnsName ? resolvedEnsAddress : recipientAddress;

  // Resolve ENS for new operator
  const isNewOperatorEns = newOperatorAddress.endsWith(".eth");
  const { data: resolvedNewOperatorAddress } = useEnsAddress({
    name: isNewOperatorEns ? normalize(newOperatorAddress) : undefined,
    chainId: 1,
  });
  const finalNewOperatorAddress = isNewOperatorEns ? resolvedNewOperatorAddress : newOperatorAddress;

  // Resolve ENS for remove operator
  const isRemoveOperatorEns = removeOperatorAddress.endsWith(".eth");
  const { data: resolvedRemoveOperatorAddress } = useEnsAddress({
    name: isRemoveOperatorEns ? normalize(removeOperatorAddress) : undefined,
    chainId: 1,
  });
  const finalRemoveOperatorAddress = isRemoveOperatorEns ? resolvedRemoveOperatorAddress : removeOperatorAddress;

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

  // Check if connected address is an operator
  const { data: isOperator, isLoading: operatorLoading } = useReadContract({
    address: isValidAddress ? (walletAddress as `0x${string}`) : undefined,
    abi: SMART_WALLET_ABI,
    functionName: "operators",
    args: connectedAddress ? [connectedAddress] : undefined,
    query: {
      enabled: !!isValidAddress && !!connectedAddress,
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

  // Determine role
  const isOwner = connectedAddress && owner && connectedAddress.toLowerCase() === owner.toLowerCase();
  const isLoading = ownerLoading || operatorLoading;
  const hasPermissions = isOwner || isOperator;

  // Write contract hooks
  const { writeContractAsync: writeExec, isPending: isTransferPending } = useWriteContract();
  const { writeContractAsync: writeAddOperator, isPending: isAddingOperator } = useWriteContract();
  const { writeContractAsync: writeRemoveOperator, isPending: isRemovingOperator } = useWriteContract();
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

  const handleAddOperator = async () => {
    if (!finalNewOperatorAddress || !isAddress(finalNewOperatorAddress)) {
      console.log("Invalid operator address:", newOperatorAddress, "->", finalNewOperatorAddress);
      return;
    }

    try {
      await writeAddOperator({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "addOperator",
        args: [finalNewOperatorAddress as `0x${string}`],
      });
      setNewOperatorAddress("");
    } catch (error) {
      console.error("Add operator failed:", error);
    }
  };

  const handleRemoveOperator = async () => {
    if (!finalRemoveOperatorAddress || !isAddress(finalRemoveOperatorAddress)) {
      console.log("Invalid operator address:", removeOperatorAddress, "->", finalRemoveOperatorAddress);
      return;
    }

    try {
      await writeRemoveOperator({
        address: walletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "removeOperator",
        args: [finalRemoveOperatorAddress as `0x${string}`],
      });
      setRemoveOperatorAddress("");
    } catch (error) {
      console.error("Remove operator failed:", error);
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

  // Execute the parsed raw transaction
  const handleExecuteRawTx = async () => {
    if (!parsedTx) return;

    try {
      if (parsedTx.isBatch) {
        // Execute as batch
        await writeBatchExec({
          address: walletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "batchExec",
          args: [parsedTx.calls.map(c => ({ target: c.target as `0x${string}`, value: c.value, data: c.data }))],
        });
      } else {
        // Execute single call
        const call = parsedTx.calls[0];
        await writeExec({
          address: walletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "exec",
          args: [call.target as `0x${string}`, call.value, call.data],
        });
      }

      // Clear on success
      setRawTxJson("");
      setParsedTx(null);
      console.log("Raw transaction executed successfully!");
    } catch (error) {
      console.error("Raw transaction failed:", error);
    }
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
        <h1 className="text-4xl font-bold text-center mb-2">Smart Wallet</h1>
        <p className="text-center text-lg opacity-70 mb-8">View wallet details and permissions</p>

        {/* Wallet Info Card */}
        <div className="bg-base-200 rounded-3xl p-6 mb-8">
          <h2 className="text-2xl font-semibold mb-4">Wallet Details</h2>

          <div className="space-y-4">
            {/* Wallet Address */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">Wallet Address</p>
              <Address address={walletAddress as `0x${string}`} format="long" />
            </div>

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

            {/* Owner */}
            <div className="bg-base-100 rounded-xl p-4">
              <p className="text-sm font-medium opacity-60 mb-1">Owner</p>
              {ownerLoading ? (
                <span className="loading loading-spinner loading-sm"></span>
              ) : owner ? (
                <Address address={owner} />
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
              <Address address={connectedAddress} />

              <div className="mt-4">
                <p className="text-sm font-medium opacity-60 mb-2">Role</p>
                {isLoading ? (
                  <span className="loading loading-spinner loading-sm"></span>
                ) : (
                  <div className="flex gap-2">
                    {isOwner ? (
                      <span className="badge badge-primary badge-lg">Owner</span>
                    ) : isOperator ? (
                      <span className="badge badge-secondary badge-lg">Operator</span>
                    ) : (
                      <span className="badge badge-ghost badge-lg">No Permissions</span>
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

        {/* Transfer ETH Section - Only for owners/operators */}
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

        {/* Transfer USDC Section - Only for owners/operators */}
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

        {/* Transfer ZORA Section - Only for owners/operators */}
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

        {/* Swap USDC to ETH Section - Only for owners/operators */}
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

        {/* Manage Operators Section - Only for owners */}
        {connectedAddress && isOwner && !isLoading && (
          <div className="bg-base-200 rounded-3xl p-6 mt-8">
            <h2 className="text-2xl font-semibold mb-4">Manage Operators</h2>
            <p className="text-sm opacity-60 mb-4">Add or remove addresses that can execute transactions</p>

            <div className="space-y-6">
              {/* Add Operator */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Add Operator</p>
                <div className="space-y-3">
                  <AddressInput
                    value={newOperatorAddress}
                    onChange={setNewOperatorAddress}
                    placeholder="Enter operator address"
                  />
                  <button
                    className="btn btn-success w-full"
                    onClick={handleAddOperator}
                    disabled={
                      isAddingOperator ||
                      !newOperatorAddress ||
                      !finalNewOperatorAddress ||
                      !isAddress(finalNewOperatorAddress)
                    }
                  >
                    {isAddingOperator ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Adding...
                      </>
                    ) : (
                      "Add Operator"
                    )}
                  </button>
                </div>
              </div>

              {/* Remove Operator */}
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium opacity-60 mb-2">Remove Operator</p>
                <div className="space-y-3">
                  <AddressInput
                    value={removeOperatorAddress}
                    onChange={setRemoveOperatorAddress}
                    placeholder="Enter operator address"
                  />
                  <button
                    className="btn btn-error w-full"
                    onClick={handleRemoveOperator}
                    disabled={
                      isRemovingOperator ||
                      !removeOperatorAddress ||
                      !finalRemoveOperatorAddress ||
                      !isAddress(finalRemoveOperatorAddress)
                    }
                  >
                    {isRemovingOperator ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Removing...
                      </>
                    ) : (
                      "Remove Operator"
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Raw Transaction Section - Only for owners/operators */}
        {connectedAddress && hasPermissions && !isLoading && (
          <div className="bg-base-200 rounded-3xl p-6 mt-8">
            <h2 className="text-2xl font-semibold mb-4">Raw Transaction</h2>
            <p className="text-sm opacity-60 mb-4">
              Paste transaction JSON from GPT or other sources. Supports single calls or batch transactions.
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
                          <Address address={call.target as `0x${string}`} />
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

                  {/* Execute Button */}
                  <button
                    className="btn btn-primary w-full"
                    onClick={handleExecuteRawTx}
                    disabled={isTransferPending || isSwapping}
                  >
                    {isTransferPending || isSwapping ? (
                      <>
                        <span className="loading loading-spinner loading-sm"></span>
                        Executing...
                      </>
                    ) : (
                      `Execute ${parsedTx.isBatch ? "Batch" : "Transaction"}`
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* WalletConnect Section - Only for owners/operators */}
        {connectedAddress && hasPermissions && !isLoading && (
          <WalletConnectSection smartWalletAddress={walletAddress} />
        )}
      </div>

      {/* Impersonator Section - Only for owners/operators (full width) */}
      {connectedAddress && hasPermissions && !isLoading && (
        <div className="w-full max-w-7xl px-4 mt-8">
          <div className="bg-base-200 rounded-3xl p-6">
            <h2 className="text-2xl font-semibold mb-4">Impersonate at dApp</h2>
            <p className="text-sm opacity-60 mb-4">
              Enter a dApp URL to interact with it as this smart wallet on Base network
            </p>

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
                    rpcUrl={BASE_RPC_URL}
                    sendTransaction={async tx => {
                      const hash = await writeExec({
                        address: walletAddress as `0x${string}`,
                        abi: SMART_WALLET_ABI,
                        functionName: "exec",
                        args: [
                          (tx.to || "0x0000000000000000000000000000000000000000") as `0x${string}`,
                          BigInt(tx.value?.toString() || "0"),
                          (tx.data || "0x") as `0x${string}`,
                        ],
                      });
                      return hash;
                    }}
                  >
                    <ImpersonatorIframe
                      key={debouncedAppUrl + walletAddress}
                      src={debouncedAppUrl}
                      address={walletAddress}
                      rpcUrl={BASE_RPC_URL}
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
