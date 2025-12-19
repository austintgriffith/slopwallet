import { OPTIONS, jsonResponse } from "../../cors";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Chain, concat, createPublicClient, http, isAddress, keccak256 } from "viem";
import { base, mainnet } from "viem/chains";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";
import { DEFAULT_ALCHEMY_API_KEY } from "~~/scaffold.config";

export { OPTIONS };

// Supported chains
const SUPPORTED_CHAINS: Record<number, Chain> = {
  [base.id]: base,
  [mainnet.id]: mainnet,
};

// P-256 curve order (used for S normalization)
const P256_CURVE_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

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
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Type for a candidate public key
interface CandidateKey {
  qx: `0x${string}`;
  qy: `0x${string}`;
  pubKeyBytes: Uint8Array;
}

// Request body type
interface RecoverPasskeyRequest {
  wallet: string;
  chainId?: number;
  signature: {
    r: `0x${string}`;
    s: `0x${string}`;
  };
  authenticatorData: `0x${string}`;
  clientDataJSON: string;
}

/**
 * Recover all candidate public keys from WebAuthn assertion data
 * Returns up to 4 candidates (2 recovery bits × 2 S values)
 */
function recoverCandidateKeys(
  r: bigint,
  s: bigint,
  authenticatorData: Uint8Array,
  clientDataJSON: string,
): CandidateKey[] {
  // Compute message hash: sha256(authenticatorData || sha256(clientDataJSON))
  const clientDataBytes = new TextEncoder().encode(clientDataJSON);
  const clientDataHash = sha256(clientDataBytes);
  const message = sha256(new Uint8Array([...authenticatorData, ...clientDataHash]));

  // Try all combinations: 2 S values (original and flipped) × 2 recovery bits
  const candidates: CandidateKey[] = [];
  const sValues = [s, P256_CURVE_ORDER - s]; // original and flipped

  for (const tryS of sValues) {
    for (const recovery of [0, 1]) {
      try {
        const sig = new p256.Signature(r, tryS, recovery);
        const pubKey = sig.recoverPublicKey(message);
        const pubKeyBytes = pubKey.toBytes(false); // uncompressed: 04 || x || y

        const qx = `0x${Array.from(pubKeyBytes.slice(1, 33))
          .map(b => b.toString(16).padStart(2, "0"))
          .join("")}` as `0x${string}`;
        const qy = `0x${Array.from(pubKeyBytes.slice(33, 65))
          .map(b => b.toString(16).padStart(2, "0"))
          .join("")}` as `0x${string}`;

        // Check for duplicates
        const isDuplicate = candidates.some(c => c.qx === qx && c.qy === qy);
        if (!isDuplicate) {
          candidates.push({ qx, qy, pubKeyBytes });
        }
      } catch {
        // This combination didn't work, skip
        continue;
      }
    }
  }

  return candidates;
}

/**
 * POST /api/passkey/recover
 *
 * Recover passkey public key from raw WebAuthn assertion data.
 * This enables API-only passkey login flows where the client sends raw
 * WebAuthn data and the server recovers and verifies the public key.
 *
 * Request body:
 * {
 *   "wallet": "0x...",                    // Smart wallet address (required)
 *   "chainId": 8453,                      // Chain ID (optional, defaults to Base)
 *   "signature": {                        // Signature components (required)
 *     "r": "0x...",                       // 32-byte hex
 *     "s": "0x..."                        // 32-byte hex
 *   },
 *   "authenticatorData": "0x...",         // Hex-encoded authenticatorData (required)
 *   "clientDataJSON": "..."               // Raw JSON string (required)
 * }
 *
 * Response (success):
 * {
 *   "qx": "0x...",
 *   "qy": "0x...",
 *   "passkeyAddress": "0x...",
 *   "wallet": "0x...",
 *   "chainId": 8453
 * }
 *
 * Response (no match):
 * {
 *   "error": "No registered passkey found among recovered candidates",
 *   "candidates": [...],
 *   "wallet": "0x...",
 *   "chainId": 8453
 * }
 */
export async function POST(request: Request) {
  try {
    // Parse request body
    const body: RecoverPasskeyRequest = await request.json();

    // Validate wallet address
    if (!body.wallet || !isAddress(body.wallet)) {
      return jsonResponse({ error: "Missing or invalid wallet address" }, 400);
    }

    // Validate signature
    if (!body.signature || !body.signature.r || !body.signature.s) {
      return jsonResponse({ error: "Missing signature (r and s required)" }, 400);
    }
    if (!body.signature.r.startsWith("0x") || !body.signature.s.startsWith("0x")) {
      return jsonResponse({ error: "Signature r and s must be hex strings starting with 0x" }, 400);
    }
    if (body.signature.r.length !== 66 || body.signature.s.length !== 66) {
      return jsonResponse({ error: "Signature r and s must be 32-byte hex strings (66 chars with 0x)" }, 400);
    }

    // Validate authenticatorData
    if (!body.authenticatorData) {
      return jsonResponse({ error: "Missing authenticatorData" }, 400);
    }
    if (!body.authenticatorData.startsWith("0x")) {
      return jsonResponse({ error: "authenticatorData must be a hex string starting with 0x" }, 400);
    }

    // Validate clientDataJSON
    if (!body.clientDataJSON || typeof body.clientDataJSON !== "string") {
      return jsonResponse({ error: "Missing or invalid clientDataJSON" }, 400);
    }

    // Determine chain
    const chainId = body.chainId ?? base.id;
    if (!SUPPORTED_CHAINS[chainId]) {
      return jsonResponse(
        { error: `Unsupported chain ID: ${chainId}. Supported: ${Object.keys(SUPPORTED_CHAINS).join(", ")}` },
        400,
      );
    }

    // Parse signature components to BigInt
    const r = BigInt(body.signature.r);
    const s = BigInt(body.signature.s);

    // Convert authenticatorData from hex to bytes
    const authenticatorData = hexToBytes(body.authenticatorData);

    // Recover candidate public keys
    const candidates = recoverCandidateKeys(r, s, authenticatorData, body.clientDataJSON);

    if (candidates.length === 0) {
      return jsonResponse({ error: "Could not recover any candidate public keys from signature" }, 400);
    }

    console.log(`[Passkey Recover] Recovered ${candidates.length} candidate keys for wallet ${body.wallet}`);

    // Set up chain client
    const chain = SUPPORTED_CHAINS[chainId];
    const rpcUrl = getRpcUrl(chainId);
    const publicClient = createPublicClient({
      chain,
      transport: http(rpcUrl),
    });

    // Check each candidate against the smart wallet
    for (const candidate of candidates) {
      const passkeyAddress = derivePasskeyAddress(candidate.qx, candidate.qy);

      try {
        const isPasskey = await publicClient.readContract({
          address: body.wallet as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "isPasskey",
          args: [passkeyAddress],
        });

        if (isPasskey) {
          console.log(`[Passkey Recover] Found matching passkey: ${passkeyAddress}`);
          return jsonResponse({
            qx: candidate.qx,
            qy: candidate.qy,
            passkeyAddress,
            wallet: body.wallet,
            chainId,
          });
        }
      } catch (error) {
        console.warn(`[Passkey Recover] Failed to check candidate ${passkeyAddress}:`, error);
        // Continue to next candidate
      }
    }

    // No matching passkey found
    return jsonResponse(
      {
        error: "No registered passkey found among recovered candidates",
        candidates: candidates.map(c => ({
          qx: c.qx,
          qy: c.qy,
          passkeyAddress: derivePasskeyAddress(c.qx, c.qy),
        })),
        wallet: body.wallet,
        chainId,
      },
      404,
    );
  } catch (error) {
    console.error("[Passkey Recover] Error:", error);
    return jsonResponse(
      {
        error: "Failed to recover passkey",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
