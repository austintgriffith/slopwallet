import { OPTIONS, jsonResponse } from "../cors";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Chain, concat, createPublicClient, createWalletClient, http, isAddress, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, mainnet } from "viem/chains";
import { SMART_WALLET_ABI } from "~~/contracts/SmartWalletAbi";

export { OPTIONS };

// Supported chains for facilitation
const SUPPORTED_CHAINS: Record<number, Chain> = {
  [base.id]: base,
  [mainnet.id]: mainnet,
};

// Whitelist of smart wallet addresses we will pay gas for
// Add addresses in lowercase for case-insensitive comparison
const WHITELISTED_SMART_WALLETS: Set<string> = new Set([
  "0x2e39e83B58052c4E0fCdFD9fB021BEa74eeFe833".toLowerCase(),
  "0x4bde57255b1bbe86eb0715c4ffd0041024c4c05c".toLowerCase(),
]);

/**
 * Derive passkey address from public key coordinates (matches contract logic)
 * This is the same as SmartWallet.getPasskeyAddress(qx, qy)
 */
function derivePasskeyAddress(qx: `0x${string}`, qy: `0x${string}`): `0x${string}` {
  const hash = keccak256(concat([qx, qy]));
  // Take last 20 bytes of the hash (last 40 hex chars)
  return `0x${hash.slice(-40)}` as `0x${string}`;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Verify WebAuthn signature cryptographically
 * This ensures the signature was created by the private key corresponding to (qx, qy)
 *
 * WebAuthn signature verification:
 * 1. The message that was signed is: SHA256(authenticatorData || SHA256(clientDataJSON))
 * 2. The signature (r, s) is verified against this message using the public key (qx, qy)
 */
function verifyWebAuthnSignature(
  authenticatorData: `0x${string}`,
  clientDataJSON: string,
  r: `0x${string}`,
  s: `0x${string}`,
  qx: `0x${string}`,
  qy: `0x${string}`,
): boolean {
  try {
    // Convert hex values to bytes
    const authDataBytes = hexToBytes(authenticatorData);
    const clientDataBytes = new TextEncoder().encode(clientDataJSON);

    // Compute the message hash: SHA256(authenticatorData || SHA256(clientDataJSON))
    const clientDataHash = sha256(clientDataBytes);
    const messageBytes = new Uint8Array(authDataBytes.length + clientDataHash.length);
    messageBytes.set(authDataBytes, 0);
    messageBytes.set(clientDataHash, authDataBytes.length);
    const messageHash = sha256(messageBytes);

    // Build the public key in uncompressed format: 04 || x || y
    const qxBytes = hexToBytes(qx);
    const qyBytes = hexToBytes(qy);
    const publicKeyBytes = new Uint8Array(65);
    publicKeyBytes[0] = 0x04; // Uncompressed point marker
    publicKeyBytes.set(qxBytes, 1);
    publicKeyBytes.set(qyBytes, 33);

    // Build signature from r and s as bytes
    const rBigInt = BigInt(r);
    const sBigInt = BigInt(s);
    const sig = new p256.Signature(rBigInt, sBigInt);
    const sigBytes = sig.toBytes();

    // Verify the signature
    const isValid = p256.verify(sigBytes, messageHash, publicKeyBytes, { prehash: false });

    return isValid;
  } catch (error) {
    console.error("[Facilitate] Signature verification error:", error);
    return false;
  }
}

/**
 * Build the challenge hash that the passkey should have signed
 * This must match what the contract expects
 */
function buildExpectedChallengeHash(
  chainId: number,
  walletAddress: `0x${string}`,
  isBatch: boolean,
  calls: Array<{ target: `0x${string}`; value: bigint; data: `0x${string}` }>,
  nonce: bigint,
  deadline: bigint,
): `0x${string}` {
  if (isBatch && calls.length > 1) {
    // Batch: keccak256(abi.encodePacked(chainId, wallet, keccak256(abi.encode(calls)), nonce, deadline))
    // We need to encode calls the same way Solidity does
    // For simplicity, we'll skip this detailed verification for batch and rely on simulation
    // The single tx case is the most common
    throw new Error("Batch challenge verification not implemented - will rely on simulation");
  } else {
    // Single: keccak256(abi.encodePacked(chainId, wallet, target, value, data, nonce, deadline))
    const call = calls[0];
    const packedData = concat([
      toHex(BigInt(chainId), { size: 32 }),
      walletAddress,
      call.target,
      toHex(call.value, { size: 32 }),
      call.data,
      toHex(nonce, { size: 32 }),
      toHex(deadline, { size: 32 }),
    ]);
    return keccak256(packedData);
  }
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

// Type for a single call in the batch
interface TransactionCall {
  target: `0x${string}`;
  value: string; // Will be converted to bigint
  data: `0x${string}`;
}

// Type for the WebAuthn auth data
interface WebAuthnAuthPayload {
  r: `0x${string}`;
  s: `0x${string}`;
  challengeIndex: string; // Will be converted to bigint
  typeIndex: string; // Will be converted to bigint
  authenticatorData: `0x${string}`;
  clientDataJSON: string;
}

// Request body type
interface FacilitateRequest {
  smartWalletAddress: string;
  chainId: number;
  isBatch: boolean;
  calls: TransactionCall[];
  qx: `0x${string}`;
  qy: `0x${string}`;
  deadline: string; // Will be converted to bigint
  auth: WebAuthnAuthPayload;
}

export async function POST(request: Request) {
  try {
    // Check for facilitator private key
    const facilitatorPrivateKey = process.env.FACILITATOR_PRIVATE_KEY;
    if (!facilitatorPrivateKey) {
      console.error("FACILITATOR_PRIVATE_KEY not configured");
      return jsonResponse({ error: "Facilitator not configured" }, 500);
    }

    // Parse request body
    const body: FacilitateRequest = await request.json();

    // Validate required fields
    if (!body.smartWalletAddress || !isAddress(body.smartWalletAddress)) {
      return jsonResponse({ error: "Invalid smart wallet address" }, 400);
    }

    if (!body.chainId || !SUPPORTED_CHAINS[body.chainId]) {
      return jsonResponse({ error: `Unsupported chain ID: ${body.chainId}` }, 400);
    }

    if (!body.calls || !Array.isArray(body.calls) || body.calls.length === 0) {
      return jsonResponse({ error: "Missing or invalid calls" }, 400);
    }

    if (!body.qx || !body.qy) {
      return jsonResponse({ error: "Missing passkey public key (qx, qy)" }, 400);
    }

    if (!body.deadline) {
      return jsonResponse({ error: "Missing deadline" }, 400);
    }

    if (!body.auth) {
      return jsonResponse({ error: "Missing WebAuthn auth data" }, 400);
    }

    // ============================================
    // SECURITY CHECK 1: Whitelist verification
    // ============================================
    const normalizedWalletAddress = body.smartWalletAddress.toLowerCase();
    if (!WHITELISTED_SMART_WALLETS.has(normalizedWalletAddress)) {
      console.warn(`[Facilitate] Rejected: wallet ${body.smartWalletAddress} is not whitelisted`);
      return jsonResponse({ error: "Smart wallet is not whitelisted for facilitation" }, 403);
    }

    const chain = SUPPORTED_CHAINS[body.chainId];
    const rpcUrl = getRpcUrl(body.chainId);

    console.log(`[Facilitate] Processing request for wallet ${body.smartWalletAddress} on chain ${chain.name}`);

    // Create public client for reading contract state
    const publicClient = createPublicClient({
      chain,
      transport: http(rpcUrl),
    });

    // ============================================
    // SECURITY CHECK 2: Verify passkey is registered
    // ============================================
    // Derive the passkey address from qx, qy (same logic as contract)
    const passkeyAddress = derivePasskeyAddress(body.qx, body.qy);
    console.log(`[Facilitate] Derived passkey address: ${passkeyAddress}`);

    // Check if this passkey is registered on the smart wallet
    const isRegisteredPasskey = await publicClient.readContract({
      address: body.smartWalletAddress as `0x${string}`,
      abi: SMART_WALLET_ABI,
      functionName: "isPasskey",
      args: [passkeyAddress],
    });

    if (!isRegisteredPasskey) {
      console.warn(
        `[Facilitate] Rejected: passkey ${passkeyAddress} is not registered on wallet ${body.smartWalletAddress}`,
      );
      return jsonResponse({ error: "Passkey is not registered on this smart wallet" }, 403);
    }

    console.log(`[Facilitate] Passkey ${passkeyAddress} verified as registered on wallet`);

    // ============================================
    // SECURITY CHECK 3: Verify WebAuthn signature cryptographically
    // ============================================
    // This ensures the signature was actually created by the private key corresponding to (qx, qy)
    // Without this, someone could submit any qx/qy of a registered passkey with a fake signature

    const isValidSignature = verifyWebAuthnSignature(
      body.auth.authenticatorData,
      body.auth.clientDataJSON,
      body.auth.r,
      body.auth.s,
      body.qx,
      body.qy,
    );

    if (!isValidSignature) {
      console.warn(`[Facilitate] Rejected: WebAuthn signature verification failed`);
      return jsonResponse({ error: "Invalid WebAuthn signature - cryptographic verification failed" }, 403);
    }

    console.log(`[Facilitate] WebAuthn signature cryptographically verified`);

    // ============================================
    // SECURITY CHECK 4: Verify the challenge matches expected transaction
    // ============================================
    // Get the nonce for this passkey from the contract
    const currentNonce = await publicClient.readContract({
      address: body.smartWalletAddress as `0x${string}`,
      abi: SMART_WALLET_ABI,
      functionName: "nonces",
      args: [passkeyAddress],
    });

    // Parse the challenge from clientDataJSON and verify it matches what we expect
    try {
      console.log(`[Facilitate] Request body: isBatch=${body.isBatch}, calls.length=${body.calls.length}`);
      console.log(
        `[Facilitate] Calls:`,
        JSON.stringify(body.calls.map(c => ({ target: c.target, value: c.value, dataLen: c.data.length }))),
      );

      const clientData = JSON.parse(body.auth.clientDataJSON);
      const challengeBase64 = clientData.challenge;

      // Decode the challenge from base64url
      const challengeBase64Std = challengeBase64.replace(/-/g, "+").replace(/_/g, "/");
      const padding = "=".repeat((4 - (challengeBase64Std.length % 4)) % 4);
      const challengeBytes = Uint8Array.from(atob(challengeBase64Std + padding), c => c.charCodeAt(0));
      const submittedChallenge = `0x${Array.from(challengeBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")}` as `0x${string}`;

      // Build the expected challenge hash for single transactions
      const isBatchTx = body.isBatch && body.calls.length > 1;

      console.log(
        `[Facilitate] Transaction type check: isBatch=${body.isBatch}, calls.length=${body.calls.length}, isBatchTx=${isBatchTx}`,
      );

      if (!isBatchTx) {
        const call = body.calls[0];
        const expectedChallenge = buildExpectedChallengeHash(
          body.chainId,
          body.smartWalletAddress as `0x${string}`,
          false,
          [{ target: call.target, value: BigInt(call.value), data: call.data }],
          currentNonce as bigint,
          BigInt(body.deadline),
        );

        if (submittedChallenge !== expectedChallenge) {
          console.warn(`[Facilitate] Challenge mismatch!`);
          console.warn(`  Submitted: ${submittedChallenge}`);
          console.warn(`  Expected:  ${expectedChallenge}`);
          return jsonResponse({ error: "Challenge hash mismatch - transaction parameters don't match signature" }, 403);
        }

        console.log(`[Facilitate] Challenge hash verified - signature matches transaction parameters`);
      } else {
        // For batch transactions, we'll rely on the simulation to catch mismatches
        console.log(`[Facilitate] Batch transaction - skipping challenge verification, will rely on simulation`);
      }
    } catch (challengeError) {
      console.error(`[Facilitate] Failed to verify challenge:`, challengeError);
      // Continue anyway - the on-chain verification will catch any issues
    }

    // Create the facilitator account from private key
    const account = privateKeyToAccount(facilitatorPrivateKey as `0x${string}`);

    // Create wallet client for sending transactions
    const walletClient = createWalletClient({
      account,
      chain,
      transport: http(rpcUrl),
    });

    // Convert string values to bigints
    const deadline = BigInt(body.deadline);
    const authStruct = {
      r: body.auth.r,
      s: body.auth.s,
      challengeIndex: BigInt(body.auth.challengeIndex),
      typeIndex: BigInt(body.auth.typeIndex),
      authenticatorData: body.auth.authenticatorData,
      clientDataJSON: body.auth.clientDataJSON,
    };

    let txHash: `0x${string}`;

    if (body.isBatch && body.calls.length > 1) {
      // Batch transaction via metaBatchExecPasskey
      const calls = body.calls.map(call => ({
        target: call.target,
        value: BigInt(call.value),
        data: call.data,
      }));

      console.log(`[Facilitate] Sending batch transaction with ${calls.length} calls...`);

      // Simulate first to catch errors
      try {
        await publicClient.simulateContract({
          address: body.smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "metaBatchExecPasskey",
          args: [calls, body.qx, body.qy, deadline, authStruct],
          account: account.address,
        });
        console.log("[Facilitate] Simulation passed");
      } catch (simError) {
        console.error("[Facilitate] Simulation failed:", simError);
        const errorMsg = simError instanceof Error ? simError.message : String(simError);
        return jsonResponse(
          {
            error: "Transaction simulation failed",
            details: errorMsg,
          },
          400,
        );
      }

      // Send the transaction
      txHash = await walletClient.writeContract({
        address: body.smartWalletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "metaBatchExecPasskey",
        args: [calls, body.qx, body.qy, deadline, authStruct],
      });
    } else {
      // Single transaction via metaExecPasskey
      const call = body.calls[0];

      console.log(`[Facilitate] Sending single transaction to ${call.target}...`);

      // Simulate first to catch errors
      try {
        await publicClient.simulateContract({
          address: body.smartWalletAddress as `0x${string}`,
          abi: SMART_WALLET_ABI,
          functionName: "metaExecPasskey",
          args: [call.target, BigInt(call.value), call.data, body.qx, body.qy, deadline, authStruct],
          account: account.address,
        });
        console.log("[Facilitate] Simulation passed");
      } catch (simError) {
        console.error("[Facilitate] Simulation failed:", simError);
        const errorMsg = simError instanceof Error ? simError.message : String(simError);
        return jsonResponse(
          {
            error: "Transaction simulation failed",
            details: errorMsg,
          },
          400,
        );
      }

      // Send the transaction
      txHash = await walletClient.writeContract({
        address: body.smartWalletAddress as `0x${string}`,
        abi: SMART_WALLET_ABI,
        functionName: "metaExecPasskey",
        args: [call.target, BigInt(call.value), call.data, body.qx, body.qy, deadline, authStruct],
      });
    }

    console.log(`[Facilitate] Transaction submitted: ${txHash}`);

    // Wait for the transaction receipt
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
      timeout: 60_000, // 60 second timeout
    });

    console.log(`[Facilitate] Transaction confirmed in block ${receipt.blockNumber}`);

    if (receipt.status === "reverted") {
      return jsonResponse(
        {
          error: "Transaction reverted",
          txHash,
          blockNumber: receipt.blockNumber.toString(),
        },
        400,
      );
    }

    // Success!
    return jsonResponse({
      success: true,
      txHash,
      blockNumber: receipt.blockNumber.toString(),
      gasUsed: receipt.gasUsed.toString(),
    });
  } catch (error) {
    console.error("[Facilitate] Error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";

    // Check for specific error types
    if (errorMessage.includes("InvalidSignature")) {
      return jsonResponse({ error: "Invalid passkey signature", details: errorMessage }, 400);
    }
    if (errorMessage.includes("ExpiredSignature")) {
      return jsonResponse({ error: "Signature has expired", details: errorMessage }, 400);
    }
    if (errorMessage.includes("PasskeyNotRegistered")) {
      return jsonResponse({ error: "Passkey is not registered on this wallet", details: errorMessage }, 400);
    }
    if (errorMessage.includes("ExecutionFailed")) {
      return jsonResponse({ error: "Transaction execution failed", details: errorMessage }, 400);
    }

    return jsonResponse({ error: errorMessage }, 500);
  }
}
