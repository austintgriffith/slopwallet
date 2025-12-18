import { OPTIONS, jsonResponse } from "../../cors";
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

// Type for a candidate public key
interface CandidateKey {
  qx: `0x${string}`;
  qy: `0x${string}`;
}

// Request body type
interface CheckPasskeyRequest {
  wallet: string;
  chainId?: number;
  candidates: CandidateKey[];
}

// Response match type
interface PasskeyMatch {
  qx: `0x${string}`;
  qy: `0x${string}`;
  passkeyAddress: `0x${string}`;
  isPasskey: boolean;
}

/**
 * POST /api/passkey/check
 *
 * Check which (if any) candidate passkey public keys are registered on a smart wallet.
 * This enables API-only passkey login flows where the client recovers candidate keys
 * from a signature and needs to determine which one is registered.
 *
 * Request body:
 * {
 *   "wallet": "0x...",           // Smart wallet address (required)
 *   "chainId": 8453,             // Chain ID (optional, defaults to Base)
 *   "candidates": [              // Array of candidate public keys (required, max 10)
 *     { "qx": "0x...", "qy": "0x..." },
 *     { "qx": "0x...", "qy": "0x..." }
 *   ]
 * }
 *
 * Response:
 * {
 *   "matches": [                 // Candidates that are registered as passkeys
 *     {
 *       "qx": "0x...",
 *       "qy": "0x...",
 *       "passkeyAddress": "0x...",
 *       "isPasskey": true
 *     }
 *   ],
 *   "wallet": "0x...",
 *   "chainId": 8453
 * }
 */
export async function POST(request: Request) {
  try {
    // Parse request body
    const body: CheckPasskeyRequest = await request.json();

    // Validate wallet address
    if (!body.wallet || !isAddress(body.wallet)) {
      return jsonResponse({ error: "Missing or invalid wallet address" }, 400);
    }

    // Validate candidates
    if (!body.candidates || !Array.isArray(body.candidates) || body.candidates.length === 0) {
      return jsonResponse({ error: "Missing or empty candidates array" }, 400);
    }

    // Limit candidates to prevent abuse
    if (body.candidates.length > 10) {
      return jsonResponse({ error: "Too many candidates (max 10)" }, 400);
    }

    // Validate each candidate
    for (let i = 0; i < body.candidates.length; i++) {
      const candidate = body.candidates[i];
      if (!candidate.qx || !candidate.qy) {
        return jsonResponse({ error: `Candidate ${i} missing qx or qy` }, 400);
      }
      if (!candidate.qx.startsWith("0x") || !candidate.qy.startsWith("0x")) {
        return jsonResponse({ error: `Candidate ${i} qx/qy must be hex strings starting with 0x` }, 400);
      }
      if (candidate.qx.length !== 66 || candidate.qy.length !== 66) {
        return jsonResponse({ error: `Candidate ${i} qx/qy must be 32-byte hex strings (66 chars with 0x)` }, 400);
      }
    }

    // Determine chain
    const chainId = body.chainId ?? base.id;
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

    // Check each candidate in parallel
    const checkResults = await Promise.all(
      body.candidates.map(async (candidate): Promise<PasskeyMatch> => {
        const passkeyAddress = derivePasskeyAddress(candidate.qx, candidate.qy);

        try {
          const isPasskey = await publicClient.readContract({
            address: body.wallet as `0x${string}`,
            abi: SMART_WALLET_ABI,
            functionName: "isPasskey",
            args: [passkeyAddress],
          });

          return {
            qx: candidate.qx,
            qy: candidate.qy,
            passkeyAddress,
            isPasskey: isPasskey as boolean,
          };
        } catch (error) {
          // If contract call fails (e.g., not a smart wallet), return false
          console.warn(`[Passkey Check] Failed to check candidate ${passkeyAddress}:`, error);
          return {
            qx: candidate.qx,
            qy: candidate.qy,
            passkeyAddress,
            isPasskey: false,
          };
        }
      }),
    );

    // Filter to only matches
    const matches = checkResults.filter(result => result.isPasskey);

    return jsonResponse({
      matches,
      wallet: body.wallet,
      chainId,
    });
  } catch (error) {
    console.error("[Passkey Check] Error:", error);
    return jsonResponse(
      {
        error: "Failed to check passkey candidates",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
