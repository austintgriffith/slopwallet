"use client";

import { useState } from "react";
import Link from "next/link";
import { Address, AddressInput } from "@scaffold-ui/components";
import type { NextPage } from "next";
import { useAccount } from "wagmi";
import { useScaffoldEventHistory, useScaffoldReadContract, useScaffoldWriteContract } from "~~/hooks/scaffold-eth";

const Home: NextPage = () => {
  const { address: connectedAddress } = useAccount();
  const [ownerAddress, setOwnerAddress] = useState<string>("");
  const [salt, setSalt] = useState<string>("0");
  const [predictedAddress, setPredictedAddress] = useState<string>("");

  // Read predicted wallet address
  const { data: walletAddress, refetch: refetchPredicted } = useScaffoldReadContract({
    contractName: "Factory",
    functionName: "getWalletAddress",
    args: [ownerAddress as `0x${string}`, `0x${salt.padStart(64, "0")}` as `0x${string}`],
  });

  // Write contract hook for creating wallet
  const { writeContractAsync: writeFactoryAsync, isMining } = useScaffoldWriteContract({
    contractName: "Factory",
  });

  // Get all WalletCreated events
  const { data: walletCreatedEvents, isLoading: eventsLoading } = useScaffoldEventHistory({
    contractName: "Factory",
    eventName: "WalletCreated",
    watch: true,
    fromBlock: 0n,
  });

  const handlePredict = () => {
    if (walletAddress) {
      setPredictedAddress(walletAddress);
    }
  };

  const handleDeploy = async () => {
    if (!ownerAddress) return;

    try {
      await writeFactoryAsync({
        functionName: "createWallet",
        args: [ownerAddress as `0x${string}`, `0x${salt.padStart(64, "0")}` as `0x${string}`],
      });
      // Refresh predicted address after deployment
      refetchPredicted();
    } catch (e) {
      console.error("Error deploying wallet:", e);
    }
  };

  return (
    <div className="flex flex-col items-center pt-10 px-4">
      <div className="max-w-2xl w-full">
        <h1 className="text-4xl font-bold text-center mb-2">Smart Wallet Factory</h1>
        <p className="text-center text-lg opacity-70 mb-8">Deploy deterministic smart wallets using CREATE2</p>

        {/* Deploy Section */}
        <div className="bg-base-200 rounded-3xl p-6 mb-8">
          <h2 className="text-2xl font-semibold mb-4">Deploy New Wallet</h2>

          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-1 block">Owner Address</label>
              <AddressInput value={ownerAddress} onChange={setOwnerAddress} placeholder="Enter owner address" />
            </div>

            <div>
              <label className="text-sm font-medium mb-1 block">Salt (number)</label>
              <input
                type="number"
                className="input input-bordered w-full"
                value={salt}
                onChange={e => setSalt(e.target.value)}
                placeholder="0"
              />
              <p className="text-xs opacity-60 mt-1">
                Use different salts to deploy multiple wallets for the same owner
              </p>
            </div>

            <div className="flex gap-2">
              <button className="btn btn-secondary flex-1" onClick={handlePredict} disabled={!ownerAddress}>
                Predict Address
              </button>
              <button className="btn btn-primary flex-1" onClick={handleDeploy} disabled={!ownerAddress || isMining}>
                {isMining ? <span className="loading loading-spinner loading-sm"></span> : "Deploy Wallet"}
              </button>
            </div>

            {predictedAddress && (
              <div className="bg-base-100 rounded-xl p-4">
                <p className="text-sm font-medium mb-2">Predicted Wallet Address:</p>
                <Address address={predictedAddress as `0x${string}`} />
              </div>
            )}
          </div>
        </div>

        {/* Connected Address Info */}
        {connectedAddress && (
          <div className="bg-base-200 rounded-3xl p-6 mb-8">
            <h2 className="text-xl font-semibold mb-2">Your Connected Address</h2>
            <Address address={connectedAddress} />
            <button className="btn btn-sm btn-outline mt-3" onClick={() => setOwnerAddress(connectedAddress)}>
              Use as Owner
            </button>
          </div>
        )}

        {/* Deployed Wallets Section */}
        <div className="bg-base-200 rounded-3xl p-6">
          <h2 className="text-2xl font-semibold mb-4">Deployed Wallets</h2>

          {eventsLoading ? (
            <div className="flex justify-center py-8">
              <span className="loading loading-spinner loading-lg"></span>
            </div>
          ) : walletCreatedEvents && walletCreatedEvents.length > 0 ? (
            <div className="space-y-3">
              {walletCreatedEvents.map((event, index) => (
                <Link
                  key={`${event.transactionHash}-${event.logIndex}-${index}`}
                  href={`/${event.args.wallet}`}
                  className="bg-base-100 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-base-300 transition-colors cursor-pointer"
                >
                  <div>
                    <p className="text-sm opacity-60">Owner</p>
                    <Address address={event.args.owner} />
                  </div>
                  <div>
                    <p className="text-sm opacity-60">Wallet</p>
                    <Address address={event.args.wallet} />
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-center py-8 opacity-60">No wallets deployed yet</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default Home;
