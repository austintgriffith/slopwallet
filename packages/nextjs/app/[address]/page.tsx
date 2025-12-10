"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { Address, AddressInput, Balance, EtherInput } from "@scaffold-ui/components";
import { formatUnits, isAddress, parseEther } from "viem";
import { base } from "viem/chains";
import { normalize } from "viem/ens";
import { useAccount, useEnsAddress, useReadContract, useWriteContract } from "wagmi";
import { WalletConnectSection } from "~~/components/scaffold-eth";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";

// USDC on Base
const USDC_ADDRESS_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const ERC20_ABI = [
  {
    inputs: [{ name: "account", type: "address" }],
    name: "balanceOf",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
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

  // Operator management state
  const [newOperatorAddress, setNewOperatorAddress] = useState("");
  const [removeOperatorAddress, setRemoveOperatorAddress] = useState("");

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

  // Determine role
  const isOwner = connectedAddress && owner && connectedAddress.toLowerCase() === owner.toLowerCase();
  const isLoading = ownerLoading || operatorLoading;
  const hasPermissions = isOwner || isOperator;

  // Write contract hooks
  const { writeContractAsync: writeExec, isPending: isTransferPending } = useWriteContract();
  const { writeContractAsync: writeAddOperator, isPending: isAddingOperator } = useWriteContract();
  const { writeContractAsync: writeRemoveOperator, isPending: isRemovingOperator } = useWriteContract();

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
          <div className="bg-base-200 rounded-3xl p-6">
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
                <p className="text-sm font-medium opacity-60 mb-2">Amount (ETH)</p>
                <EtherInput placeholder="0.0" onValueChange={({ valueInEth }) => setEthAmount(valueInEth)} />
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

        {/* WalletConnect Section - Only for owners/operators */}
        {connectedAddress && hasPermissions && !isLoading && (
          <WalletConnectSection smartWalletAddress={walletAddress} />
        )}
      </div>
    </div>
  );
};

export default WalletPage;
