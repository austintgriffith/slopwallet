import { OPTIONS, jsonResponse } from "../cors";
import { Chain, concat, createPublicClient, encodeAbiParameters, http, isAddress, keccak256, toHex } from "viem";
import { base, mainnet } from "viem/chains";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import { DEFAULT_ALCHEMY_API_KEY } from "~~/scaffold.config";

export { OPTIONS };

// Supported chains
const SUPPORTED_CHAINS: Record<number, Chain> = {
  [base.id]: base,
  [mainnet.id]: mainnet,
};

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
  const alchemyApiKey =
    process.env.ALCHEMY_API_KEY || process.env.NEXT_PUBLIC_ALCHEMY_API_KEY || DEFAULT_ALCHEMY_API_KEY;

  if (chainId === base.id) {
    return `https://base-mainnet.g.alchemy.com/v2/${alchemyApiKey}`;
  }
  if (chainId === mainnet.id) {
    return "https://mainnet.rpc.buidlguidl.com";
  }

  // Fallback to base
  return `https://base-mainnet.g.alchemy.com/v2/${alchemyApiKey}`;
}

/**
 * Build the challenge hash for single transactions
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

/**
 * Build the challenge hash for batch transactions (matches contract's metaBatchExecPasskey)
 * keccak256(abi.encodePacked(chainId, wallet, keccak256(abi.encode(calls)), nonce, deadline))
 */
function buildBatchChallengeHash(
  chainId: number,
  wallet: `0x${string}`,
  calls: Array<{ target: `0x${string}`; value: bigint; data: `0x${string}` }>,
  nonce: bigint,
  deadline: bigint,
): `0x${string}` {
  // First, encode the calls array using abi.encode (not packed!)
  const encodedCalls = encodeAbiParameters(
    [
      {
        type: "tuple[]",
        components: [
          { name: "target", type: "address" },
          { name: "value", type: "uint256" },
          { name: "data", type: "bytes" },
        ],
      },
    ],
    [calls.map(c => ({ target: c.target, value: c.value, data: c.data }))],
  );

  // Hash the encoded calls
  const callsHash = keccak256(encodedCalls);

  // Pack everything together
  const packedData = concat([
    toHex(BigInt(chainId), { size: 32 }),
    wallet,
    callsHash,
    toHex(nonce, { size: 32 }),
    toHex(deadline, { size: 32 }),
  ]);

  return keccak256(packedData);
}

interface CallData {
  target: string;
  value?: string;
  data?: string;
}

interface PrepareCallRequest {
  chainId: number;
  wallet: string;
  qx: string;
  qy: string;
  // Single call (for eth_sendTransaction)
  target?: string;
  value?: string;
  data?: string;
  // OR batch calls (for wallet_sendCalls)
  calls?: CallData[];
}

/**
 * POST /api/prepare-call
 *
 * Prepares arbitrary transaction data for passkey signing.
 * Supports both single calls (eth_sendTransaction) and batch calls (wallet_sendCalls).
 *
 * Request body:
 * {
 *   "chainId": 8453,
 *   "wallet": "0xSmartWalletAddress",
 *   "qx": "0x...",
 *   "qy": "0x...",
 *   // Either single call:
 *   "target": "0xContractAddress",
 *   "value": "0",
 *   "data": "0x..."
 *   // OR batch calls:
 *   "calls": [
 *     { "target": "0x...", "value": "0", "data": "0x..." },
 *     { "target": "0x...", "value": "1000000", "data": "0x..." }
 *   ]
 * }
 *
 * Response:
 * {
 *   "success": true,
 *   "isBatch": false,
 *   "calls": [{ "target": "0x...", "value": "0", "data": "0x..." }],
 *   "nonce": "5",
 *   "deadline": "1734567890",
 *   "challengeHash": "0x..."
 * }
 */
export async function POST(request: Request) {
  try {
    const body: PrepareCallRequest = await request.json();

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

    // Validate qx and qy
    if (!body.qx || !body.qy) {
      return jsonResponse({ error: "Missing passkey public key (qx, qy)" }, 400);
    }

    if (!body.qx.startsWith("0x") || !body.qy.startsWith("0x")) {
      return jsonResponse({ error: "qx and qy must be hex strings starting with 0x" }, 400);
    }

    // Determine if this is a batch call or single call
    const isBatch = Array.isArray(body.calls) && body.calls.length > 0;
    const hasSingleCall = body.target !== undefined;

    if (!isBatch && !hasSingleCall) {
      return jsonResponse({ error: "Must provide either 'target' for single call or 'calls' array for batch" }, 400);
    }

    // Normalize calls to array format
    let calls: Array<{ target: `0x${string}`; value: bigint; data: `0x${string}` }>;

    if (isBatch) {
      // Validate batch calls
      for (let i = 0; i < body.calls!.length; i++) {
        const call = body.calls![i];
        if (!call.target || !isAddress(call.target)) {
          return jsonResponse({ error: `Invalid target address in call ${i}` }, 400);
        }
      }

      calls = body.calls!.map(call => ({
        target: call.target as `0x${string}`,
        value: call.value ? BigInt(call.value) : 0n,
        data: (call.data || "0x") as `0x${string}`,
      }));
    } else {
      // Single call
      if (!isAddress(body.target!)) {
        return jsonResponse({ error: "Invalid target address" }, 400);
      }

      calls = [
        {
          target: body.target as `0x${string}`,
          value: body.value ? BigInt(body.value) : 0n,
          data: (body.data || "0x") as `0x${string}`,
        },
      ];
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

    // Compute the challenge hash based on single vs batch
    let challengeHash: `0x${string}`;

    if (isBatch && calls.length > 1) {
      // Batch transaction
      challengeHash = buildBatchChallengeHash(body.chainId, body.wallet as `0x${string}`, calls, nonce, deadline);
    } else {
      // Single transaction (even if passed as single-item batch)
      const call = calls[0];
      challengeHash = buildChallengeHash(
        body.chainId,
        body.wallet as `0x${string}`,
        call.target,
        call.value,
        call.data,
        nonce,
        deadline,
      );
    }

    return jsonResponse({
      success: true,
      isBatch: isBatch && calls.length > 1,
      calls: calls.map(c => ({
        target: c.target,
        value: c.value.toString(),
        data: c.data,
      })),
      nonce: nonce.toString(),
      deadline: deadline.toString(),
      challengeHash,
    });
  } catch (error) {
    console.error("[PrepareCall API] Error:", error);
    return jsonResponse(
      {
        error: "Failed to prepare call",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
