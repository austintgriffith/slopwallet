import { OPTIONS, jsonResponse } from "../cors";
import { Chain, concat, createPublicClient, http, isAddress, keccak256 } from "viem";
import { base, mainnet } from "viem/chains";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";

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
 * GET /api/nonce
 *
 * Query parameters:
 * - wallet: Smart wallet address (required)
 * - chainId: Chain ID (optional, defaults to Base)
 * - passkey: Passkey address (optional if qx and qy are provided)
 * - qx: Passkey public key x-coordinate (optional if passkey is provided)
 * - qy: Passkey public key y-coordinate (optional if passkey is provided)
 *
 * Response:
 * {
 *   "nonce": "1",
 *   "passkeyAddress": "0x..."
 * }
 */
export async function GET(request: Request) {
  try {
    const url = new URL(request.url);

    // Get query parameters
    const wallet = url.searchParams.get("wallet");
    const chainIdParam = url.searchParams.get("chainId");
    const passkeyParam = url.searchParams.get("passkey");
    const qx = url.searchParams.get("qx");
    const qy = url.searchParams.get("qy");

    // Validate wallet address
    if (!wallet || !isAddress(wallet)) {
      return jsonResponse({ error: "Missing or invalid wallet address" }, 400);
    }

    // Determine passkey address
    let passkeyAddress: `0x${string}`;

    if (passkeyParam && isAddress(passkeyParam)) {
      // Use provided passkey address
      passkeyAddress = passkeyParam as `0x${string}`;
    } else if (qx && qy) {
      // Derive passkey address from qx and qy
      if (!qx.startsWith("0x") || !qy.startsWith("0x")) {
        return jsonResponse({ error: "qx and qy must be hex strings starting with 0x" }, 400);
      }
      passkeyAddress = derivePasskeyAddress(qx as `0x${string}`, qy as `0x${string}`);
    } else {
      return jsonResponse(
        { error: "Must provide either 'passkey' address or both 'qx' and 'qy' public key coordinates" },
        400,
      );
    }

    // Determine chain
    const chainId = chainIdParam ? parseInt(chainIdParam, 10) : base.id;
    if (!SUPPORTED_CHAINS[chainId]) {
      return jsonResponse(
        { error: `Unsupported chain ID: ${chainId}. Supported: ${Object.keys(SUPPORTED_CHAINS).join(", ")}` },
        400,
      );
    }

    const chain = SUPPORTED_CHAINS[chainId];
    const rpcUrl = getRpcUrl(chainId);

    // Create public client
    const publicClient = createPublicClient({
      chain,
      transport: http(rpcUrl),
    });

    // Read nonce from contract
    const nonce = await publicClient.readContract({
      address: wallet as `0x${string}`,
      abi: SMART_WALLET_ABI,
      functionName: "nonces",
      args: [passkeyAddress],
    });

    return jsonResponse({
      nonce: nonce.toString(),
      passkeyAddress,
      wallet,
      chainId,
    });
  } catch (error) {
    console.error("[Nonce API] Error:", error);
    return jsonResponse(
      {
        error: "Failed to fetch nonce",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
