import { OPTIONS, jsonResponse } from "../cors";
import {
  Chain,
  concat,
  createPublicClient,
  encodeFunctionData,
  http,
  isAddress,
  keccak256,
  parseEther,
  parseUnits,
  toHex,
} from "viem";
import { base, mainnet } from "viem/chains";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";

export { OPTIONS };

// Supported chains
const SUPPORTED_CHAINS: Record<number, Chain> = {
  [base.id]: base,
  [mainnet.id]: mainnet,
};

// USDC contract addresses by chain
const USDC_ADDRESSES: Record<number, `0x${string}`> = {
  [base.id]: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base
  [mainnet.id]: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // Mainnet
};

// ERC20 transfer ABI
const ERC20_TRANSFER_ABI = [
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
] as const;

/**
 * Derive passkey address from public key coordinates (matches contract logic)
 * This is the same as SmartWallet.getPasskeyAddress(qx, qy)
 */
function derivePasskeyAddress(qx: `0x${string}`, qy: `0x${string}`): `0x${string}` {
  const hash = keccak256(concat([qx, qy]));
  // Take last 20 bytes of the hash (last 40 hex chars)
  return `0x${hash.slice(-40)}` as `0x${string}`;
}

// Get RPC URL for a chain
function getRpcUrl(chainId: number): string {
  const alchemyApiKey = process.env.ALCHEMY_API_KEY || process.env.NEXT_PUBLIC_ALCHEMY_API_KEY;

  if (chainId === base.id) {
    return alchemyApiKey ? `https://base-mainnet.g.alchemy.com/v2/${alchemyApiKey}` : "https://mainnet.base.org";
  }
  if (chainId === mainnet.id) {
    return "https://mainnet.rpc.buidlguidl.com";
  }

  // Fallback to base
  return alchemyApiKey ? `https://base-mainnet.g.alchemy.com/v2/${alchemyApiKey}` : "https://mainnet.base.org";
}

/**
 * Build the challenge hash that matches what the contract expects
 * keccak256(abi.encodePacked(chainId, wallet, target, value, data, nonce, deadline))
 */
function buildChallengeHash(
  chainId: number,
  wallet: `0x${string}`,
  target: `0x${string}`,
  value: bigint,
  data: `0x${string}`,
  nonce: bigint,
  deadline: bigint,
): `0x${string}` {
  const packedData = concat([
    toHex(BigInt(chainId), { size: 32 }),
    wallet,
    target,
    toHex(value, { size: 32 }),
    data,
    toHex(nonce, { size: 32 }),
    toHex(deadline, { size: 32 }),
  ]);

  return keccak256(packedData);
}

interface PrepareTransferRequest {
  chainId: number;
  wallet: string;
  qx: string;
  qy: string;
  asset: "ETH" | "USDC";
  amount: string;
  to: string;
}

/**
 * POST /api/prepare-transfer
 *
 * Consolidates transfer preparation into a single call:
 * - Encodes the transfer calldata
 * - Fetches the current nonce for the passkey
 * - Computes deadline (now + 1 hour)
 * - Computes the challenge hash for WebAuthn signing
 *
 * Request body:
 * {
 *   "chainId": 8453,
 *   "wallet": "0xSmartWalletAddress",
 *   "qx": "0x...",
 *   "qy": "0x...",
 *   "asset": "USDC",
 *   "amount": "10.00",
 *   "to": "0xRecipientAddress"
 * }
 *
 * Response:
 * {
 *   "success": true,
 *   "call": {
 *     "target": "0xUSDCContractAddress",
 *     "value": "0",
 *     "data": "0x...encodedTransferCalldata"
 *   },
 *   "nonce": "5",
 *   "deadline": "1734567890",
 *   "challengeHash": "0x..."
 * }
 */
export async function POST(request: Request) {
  try {
    const body: PrepareTransferRequest = await request.json();

    // Validate chainId
    if (!body.chainId || !SUPPORTED_CHAINS[body.chainId]) {
      return jsonResponse(
        { error: `Unsupported chain ID: ${body.chainId}. Supported: ${Object.keys(SUPPORTED_CHAINS).join(", ")}` },
        400,
      );
    }

    // Validate wallet address
    if (!body.wallet || !isAddress(body.wallet)) {
      return jsonResponse({ error: "Missing or invalid wallet address" }, 400);
    }

    // Validate recipient address
    if (!body.to || !isAddress(body.to)) {
      return jsonResponse({ error: "Missing or invalid recipient address" }, 400);
    }

    // Validate qx and qy
    if (!body.qx || !body.qy) {
      return jsonResponse({ error: "Missing passkey public key (qx, qy)" }, 400);
    }

    if (!body.qx.startsWith("0x") || !body.qy.startsWith("0x")) {
      return jsonResponse({ error: "qx and qy must be hex strings starting with 0x" }, 400);
    }

    // Validate asset type
    if (!body.asset || (body.asset !== "ETH" && body.asset !== "USDC")) {
      return jsonResponse({ error: "Invalid asset. Must be ETH or USDC" }, 400);
    }

    // Validate amount
    const amountNum = parseFloat(body.amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return jsonResponse({ error: "Invalid amount. Must be a positive number" }, 400);
    }

    // For USDC, verify we have the contract address for this chain
    if (body.asset === "USDC" && !USDC_ADDRESSES[body.chainId]) {
      return jsonResponse({ error: `USDC not supported on chain ${body.chainId}` }, 400);
    }

    // Generate the call data
    let callData: {
      target: `0x${string}`;
      value: bigint;
      data: `0x${string}`;
    };

    if (body.asset === "ETH") {
      // ETH transfer: send value directly to recipient
      const valueWei = parseEther(body.amount);
      callData = {
        target: body.to as `0x${string}`,
        value: valueWei,
        data: "0x",
      };
    } else {
      // USDC transfer: call transfer() on USDC contract
      const amountUnits = parseUnits(body.amount, 6); // USDC has 6 decimals
      const transferData = encodeFunctionData({
        abi: ERC20_TRANSFER_ABI,
        functionName: "transfer",
        args: [body.to as `0x${string}`, amountUnits],
      });

      callData = {
        target: USDC_ADDRESSES[body.chainId],
        value: 0n,
        data: transferData,
      };
    }

    // Derive passkey address from qx and qy
    const passkeyAddress = derivePasskeyAddress(body.qx as `0x${string}`, body.qy as `0x${string}`);

    // Setup chain and RPC
    const chain = SUPPORTED_CHAINS[body.chainId];
    const rpcUrl = getRpcUrl(body.chainId);

    // Create public client
    const publicClient = createPublicClient({
      chain,
      transport: http(rpcUrl),
    });

    // Fetch the current nonce for this passkey
    const nonce = (await publicClient.readContract({
      address: body.wallet as `0x${string}`,
      abi: SMART_WALLET_ABI,
      functionName: "nonces",
      args: [passkeyAddress],
    })) as bigint;

    // Compute deadline: now + 1 hour
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);

    // Compute the challenge hash
    const challengeHash = buildChallengeHash(
      body.chainId,
      body.wallet as `0x${string}`,
      callData.target,
      callData.value,
      callData.data,
      nonce,
      deadline,
    );

    return jsonResponse({
      success: true,
      call: {
        target: callData.target,
        value: callData.value.toString(),
        data: callData.data,
      },
      nonce: nonce.toString(),
      deadline: deadline.toString(),
      challengeHash,
    });
  } catch (error) {
    console.error("[PrepareTransfer API] Error:", error);
    return jsonResponse(
      {
        error: "Failed to prepare transfer",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
