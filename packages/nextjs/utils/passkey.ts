import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, encodeAbiParameters, keccak256, toHex } from "viem";

// Types
export interface StoredPasskey {
  credentialId: string; // Base64 URL encoded credential ID
  qx: `0x${string}`; // Public key x-coordinate (32 bytes)
  qy: `0x${string}`; // Public key y-coordinate (32 bytes)
  passkeyAddress: `0x${string}`; // Derived address for quick lookup
}

export interface WebAuthnAuth {
  r: `0x${string}`; // 32 bytes
  s: `0x${string}`; // 32 bytes
  challengeIndex: bigint; // Index of "challenge":"..." in clientDataJSON
  typeIndex: bigint; // Index of "type":"..." in clientDataJSON
  authenticatorData: `0x${string}`;
  clientDataJSON: string;
}

// localStorage key prefix
const PASSKEY_STORAGE_PREFIX = "passkey:";

/**
 * Get localStorage key for a wallet address
 */
function getStorageKey(walletAddress: string): string {
  return `${PASSKEY_STORAGE_PREFIX}${walletAddress.toLowerCase()}`;
}

/**
 * Save passkey info to localStorage
 */
export function savePasskeyToStorage(walletAddress: string, passkey: StoredPasskey): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(getStorageKey(walletAddress), JSON.stringify(passkey));
}

/**
 * Get passkey info from localStorage
 */
export function getPasskeyFromStorage(walletAddress: string): StoredPasskey | null {
  if (typeof window === "undefined") return null;
  const stored = localStorage.getItem(getStorageKey(walletAddress));
  if (!stored) return null;
  try {
    return JSON.parse(stored) as StoredPasskey;
  } catch {
    return null;
  }
}

/**
 * Clear passkey from localStorage
 */
export function clearPasskeyFromStorage(walletAddress: string): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(getStorageKey(walletAddress));
}

/**
 * Derive passkey address from public key coordinates (matches contract logic)
 */
export function getPasskeyAddress(qx: `0x${string}`, qy: `0x${string}`): `0x${string}` {
  const hash = keccak256(concat([qx, qy]));
  // Take last 20 bytes of the hash
  return `0x${hash.slice(-40)}` as `0x${string}`;
}

/**
 * Compute keccak256 hash of a credentialId (for on-chain lookup)
 */
export function getCredentialIdHash(credentialId: string): `0x${string}` {
  const bytes = base64UrlToBytes(credentialId);
  return keccak256(bytes);
}

/**
 * Convert ArrayBuffer to hex string
 */
function bufferToHex(buffer: ArrayBuffer): `0x${string}` {
  return `0x${Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")}` as `0x${string}`;
}

/**
 * Convert base64url string to Uint8Array
 */
function base64UrlToBytes(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

/**
 * Convert Uint8Array to base64url string
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Parse SPKI public key to extract x,y coordinates
 * getPublicKey() returns SubjectPublicKeyInfo (SPKI) in DER format
 * For P-256, the public key is in uncompressed form: 04 || x (32 bytes) || y (32 bytes)
 */
function parseSpkiPublicKey(spkiKey: ArrayBuffer): { qx: `0x${string}`; qy: `0x${string}` } {
  const bytes = new Uint8Array(spkiKey);

  // For P-256 SPKI, the structure is:
  // SEQUENCE {
  //   SEQUENCE { OID, OID }  -- algorithm identifier
  //   BIT STRING { 04 || x || y }  -- public key (uncompressed point)
  // }

  // The uncompressed public key starts with 0x04 followed by 32 bytes x and 32 bytes y
  // We need to find the 0x04 marker that starts a 65-byte sequence (1 + 32 + 32)

  // Look for the uncompressed point format marker (0x04) near the end of the key
  // The last 65 bytes should be: 04 || x (32) || y (32)
  for (let i = bytes.length - 65; i >= 0; i--) {
    if (bytes[i] === 0x04) {
      // Verify this looks like a valid uncompressed point
      // (the previous byte should be 0x00 or the BIT STRING length)
      const x = bytes.slice(i + 1, i + 33);
      const y = bytes.slice(i + 33, i + 65);

      // Sanity check: x and y should not be all zeros
      const xAllZero = x.every(b => b === 0);
      const yAllZero = y.every(b => b === 0);

      if (!xAllZero && !yAllZero) {
        return {
          qx: bufferToHex(x.buffer.slice(x.byteOffset, x.byteOffset + 32)),
          qy: bufferToHex(y.buffer.slice(y.byteOffset, y.byteOffset + 32)),
        };
      }
    }
  }

  // Fallback: try to parse as raw COSE key (some implementations return this)
  // COSE keys use CBOR encoding with -2 (0x21) for x and -3 (0x22) for y
  let xStart = -1;
  let yStart = -1;

  for (let i = 0; i < bytes.length - 32; i++) {
    // Look for -2 (0x21) followed by bytes tag (0x58, 0x20 for 32 bytes)
    if (bytes[i] === 0x21 && bytes[i + 1] === 0x58 && bytes[i + 2] === 0x20) {
      xStart = i + 3;
    }
    // Look for -3 (0x22) followed by bytes tag
    if (bytes[i] === 0x22 && bytes[i + 1] === 0x58 && bytes[i + 2] === 0x20) {
      yStart = i + 3;
    }
  }

  if (xStart !== -1 && yStart !== -1) {
    const x = bytes.slice(xStart, xStart + 32);
    const y = bytes.slice(yStart, yStart + 32);
    return {
      qx: bufferToHex(x.buffer.slice(x.byteOffset, x.byteOffset + 32)),
      qy: bufferToHex(y.buffer.slice(y.byteOffset, y.byteOffset + 32)),
    };
  }

  // Debug: log the key for troubleshooting
  console.error("Failed to parse public key. Raw bytes:", bufferToHex(bytes.buffer));
  throw new Error("Could not parse public key: x or y coordinate not found");
}

/**
 * Create a new passkey using WebAuthn
 * Returns the credential ID and public key coordinates
 */
export async function createPasskey(): Promise<{
  credentialId: string;
  qx: `0x${string}`;
  qy: `0x${string}`;
  passkeyAddress: `0x${string}`;
}> {
  if (!window.PublicKeyCredential) {
    throw new Error("WebAuthn is not supported in this browser");
  }

  // Generate a random challenge for registration
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge,
    rp: {
      name: "SlopWallet",
      id: window.location.hostname,
    },
    user: {
      id: crypto.getRandomValues(new Uint8Array(32)), // Random ID since passkey isn't tied to one wallet
      name: "Slop Wallet",
      displayName: "Slop Wallet",
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" }, // ES256 (P-256) - required for our contract
      { alg: -257, type: "public-key" }, // RS256 - fallback for compatibility
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform", // Prefer platform authenticator (Touch ID, Face ID, Windows Hello)
      residentKey: "required", // Make it a discoverable credential
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "none", // We don't need attestation
  };

  const credential = (await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions,
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("Failed to create passkey");
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  // Get the public key from the response
  const publicKey = response.getPublicKey();
  if (!publicKey) {
    throw new Error("Failed to get public key from credential");
  }

  // Parse the SPKI public key to extract x,y coordinates
  const { qx, qy } = parseSpkiPublicKey(publicKey);

  // Derive the passkey address
  const passkeyAddress = getPasskeyAddress(qx, qy);

  // Convert credential ID to base64url
  const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));

  return {
    credentialId,
    qx,
    qy,
    passkeyAddress,
  };
}

/**
 * Login with an existing passkey
 *
 * Optimized flow:
 * - If checkIsOperator callback is provided, tries to find a registered operator from a single signature
 * - Falls back to two signatures if no registered operator found (for unregistered passkeys)
 *
 * @param checkIsOperator - Optional callback to check if an address is an operator on-chain
 */
export async function loginWithPasskey(checkIsOperator?: (passkeyAddress: `0x${string}`) => Promise<boolean>): Promise<{
  credentialIdHash: `0x${string}`;
  credentialId: string;
  qx: `0x${string}`;
  qy: `0x${string}`;
  passkeyAddress: `0x${string}`;
}> {
  if (!window.PublicKeyCredential) {
    throw new Error("WebAuthn is not supported in this browser");
  }

  console.log("Login: requesting first signature...");

  // FIRST signature - let user pick any passkey
  const credential1 = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: window.location.hostname,
      userVerification: "required",
      // No allowCredentials - let user pick from any available passkey
    },
  })) as PublicKeyCredential;

  if (!credential1) {
    throw new Error("Failed to authenticate with passkey (first signature)");
  }

  const credentialId = bytesToBase64Url(new Uint8Array(credential1.rawId));
  const credentialIdHash = keccak256(new Uint8Array(credential1.rawId));
  console.log("Login: first signature received, credentialId:", credentialId);

  // Recover all candidate public keys from first signature
  const candidates = recoverAllCandidateKeys(credential1);

  if (candidates.length === 0) {
    throw new Error("Could not recover any candidate public keys from signature");
  }

  // If only one candidate, we're done (unlikely but possible)
  if (candidates.length === 1) {
    console.log("Only one candidate key, skipping second signature");
    const { qx, qy } = candidates[0];
    return {
      credentialIdHash,
      credentialId,
      qx,
      qy,
      passkeyAddress: getPasskeyAddress(qx, qy),
    };
  }

  // OPTIMIZATION: If checkIsPasskey is provided, try to find the registered passkey
  // This avoids the second signature for already-registered passkeys
  if (checkIsOperator) {
    console.log("Login: checking candidates against on-chain passkeys...");
    for (const candidate of candidates) {
      const passkeyAddress = getPasskeyAddress(candidate.qx, candidate.qy);
      try {
        const isRegistered = await checkIsOperator(passkeyAddress);
        if (isRegistered) {
          console.log("Login: found registered passkey with single signature!", {
            qx: candidate.qx,
            qy: candidate.qy,
            passkeyAddress,
          });
          return {
            credentialIdHash,
            credentialId,
            qx: candidate.qx,
            qy: candidate.qy,
            passkeyAddress,
          };
        }
      } catch (e) {
        console.warn("Failed to check passkey status:", e);
      }
    }
    console.log("Login: no registered operator found among candidates, requesting second signature...");
  }

  console.log("Login: requesting second signature to determine correct key...");

  // SECOND signature - use the SAME credential (via allowCredentials)
  const credential2 = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: window.location.hostname,
      userVerification: "required",
      allowCredentials: [
        {
          id: credential1.rawId,
          type: "public-key",
          transports: ["internal", "hybrid"],
        },
      ],
    },
  })) as PublicKeyCredential;

  if (!credential2) {
    throw new Error("Failed to authenticate with passkey (second signature)");
  }

  console.log("Login: second signature received, finding correct key...");

  // Find the candidate that verifies BOTH signatures
  const { qx, qy } = findCorrectKey(candidates, credential2);

  // Derive the passkey address
  const passkeyAddress = getPasskeyAddress(qx, qy);

  console.log("Login successful:", { credentialId, qx, qy, passkeyAddress });

  return { credentialIdHash, credentialId, qx, qy, passkeyAddress };
}

/**
 * Build the challenge hash that matches what the contract expects
 */
export function buildChallengeHash(
  chainId: bigint,
  walletAddress: `0x${string}`,
  target: `0x${string}`,
  value: bigint,
  data: `0x${string}`,
  nonce: bigint,
  deadline: bigint,
): `0x${string}` {
  // Match the contract's encoding:
  // keccak256(abi.encodePacked(chainId, address(this), target, value, data, nonce, deadline))
  // Note: abi.encodePacked is different from abi.encode - we need packed encoding
  const packedData = concat([
    toHex(chainId, { size: 32 }),
    walletAddress,
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
 */
export function buildBatchChallengeHash(
  chainId: bigint,
  walletAddress: `0x${string}`,
  calls: Array<{ target: `0x${string}`; value: bigint; data: `0x${string}` }>,
  nonce: bigint,
  deadline: bigint,
): `0x${string}` {
  // Match the contract's encoding:
  // keccak256(abi.encodePacked(chainId, address(this), keccak256(abi.encode(calls)), nonce, deadline))

  // First, encode the calls array using abi.encode (not packed!)
  // The Call struct is: { address target, uint256 value, bytes data }
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
    toHex(chainId, { size: 32 }),
    walletAddress,
    callsHash,
    toHex(nonce, { size: 32 }),
    toHex(deadline, { size: 32 }),
  ]);

  return keccak256(packedData);
}

/**
 * Sign a challenge with passkey and return WebAuthnAuth struct
 */
export async function signWithPasskey(
  credentialId: string,
  challenge: Uint8Array,
): Promise<{ auth: WebAuthnAuth; credential: PublicKeyCredential }> {
  if (!window.PublicKeyCredential) {
    throw new Error("WebAuthn is not supported in this browser");
  }

  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: window.location.hostname,
    timeout: 60000,
    userVerification: "required",
    allowCredentials: [
      {
        id: base64UrlToBytes(credentialId),
        type: "public-key",
        transports: ["internal", "hybrid"],
      },
    ],
  };

  const credential = (await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions,
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("Failed to sign with passkey");
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  // Parse the signature (DER-encoded) to get r and s values
  const { r, s: rawS } = parseSignature(response.signature);

  // Normalize S to low-S form (required by some WebAuthn verifiers)
  // ECDSA signatures have two valid S values: S and N-S (where N is curve order)
  // Some implementations require S < N/2 (low-S)
  const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const halfN = P256_N / 2n;
  const sValue = BigInt(rawS);
  let s: `0x${string}`;

  if (sValue > halfN) {
    console.log(">>> S VALUE IS HIGH - normalizing to low-S");
    console.log("Original S:", rawS);
    const normalizedS = P256_N - sValue;
    s = `0x${normalizedS.toString(16).padStart(64, "0")}` as `0x${string}`;
    console.log("Normalized S:", s);
  } else {
    s = rawS;
  }

  // Get authenticator data and client data JSON
  const authenticatorData = bufferToHex(response.authenticatorData);
  const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);

  // Log raw WebAuthn response for debugging
  console.log("=== WEBAUTHN RAW RESPONSE ===");
  console.log("credentialId used:", credentialId);
  console.log("authenticatorData (hex):", authenticatorData);
  console.log("signature (hex):", bufferToHex(response.signature));
  console.log("clientDataJSON:", clientDataJSON);
  console.log("Parsed r:", r);
  console.log("Parsed s (after normalization):", s);

  // Find the indices of "challenge" and "type" in clientDataJSON
  const challengeIndex = clientDataJSON.indexOf('"challenge"');
  const typeIndex = clientDataJSON.indexOf('"type"');

  if (challengeIndex === -1 || typeIndex === -1) {
    throw new Error("Invalid clientDataJSON: missing challenge or type field");
  }

  return {
    auth: {
      r,
      s,
      challengeIndex: BigInt(challengeIndex),
      typeIndex: BigInt(typeIndex),
      authenticatorData,
      clientDataJSON,
    },
    credential,
  };
}

/**
 * Parse DER-encoded ECDSA signature to get r and s values
 * WebAuthn signatures are DER-encoded
 */
function parseSignature(signature: ArrayBuffer): { r: `0x${string}`; s: `0x${string}` } {
  const bytes = new Uint8Array(signature);

  // DER structure: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  if (bytes[0] !== 0x30) {
    throw new Error("Invalid signature: expected DER sequence");
  }

  let offset = 2; // Skip 0x30 and length byte

  // Parse r
  if (bytes[offset] !== 0x02) {
    throw new Error("Invalid signature: expected integer tag for r");
  }
  offset++;
  const rLength = bytes[offset];
  offset++;
  let rBytes = bytes.slice(offset, offset + rLength);
  offset += rLength;

  // Parse s
  if (bytes[offset] !== 0x02) {
    throw new Error("Invalid signature: expected integer tag for s");
  }
  offset++;
  const sLength = bytes[offset];
  offset++;
  let sBytes = bytes.slice(offset, offset + sLength);

  // Remove leading zero if present (DER encoding adds a leading zero for positive numbers with high bit set)
  if (rBytes.length === 33 && rBytes[0] === 0) {
    rBytes = rBytes.slice(1);
  }
  if (sBytes.length === 33 && sBytes[0] === 0) {
    sBytes = sBytes.slice(1);
  }

  // Pad to 32 bytes if needed
  const rPadded = new Uint8Array(32);
  const sPadded = new Uint8Array(32);
  rPadded.set(rBytes, 32 - rBytes.length);
  sPadded.set(sBytes, 32 - sBytes.length);

  return {
    r: bufferToHex(rPadded.buffer),
    s: bufferToHex(sPadded.buffer),
  };
}

// P-256 curve order (used for S normalization)
const P256_CURVE_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/**
 * Candidate public key from recovery
 */
interface CandidateKey {
  qx: `0x${string}`;
  qy: `0x${string}`;
  pubKeyBytes: Uint8Array;
}

/**
 * Recover ALL possible candidate public keys from a WebAuthn credential response
 * Returns up to 4 candidates (2 recovery bits × 2 S values)
 */
function recoverAllCandidateKeys(credential: PublicKeyCredential): CandidateKey[] {
  const response = credential.response as AuthenticatorAssertionResponse;

  // Parse the signature
  const sigBytes = new Uint8Array(response.signature);
  if (sigBytes[0] !== 0x30) {
    throw new Error("Invalid signature: expected DER sequence");
  }

  let offset = 2;
  if (sigBytes[offset] !== 0x02) throw new Error("Invalid signature: expected integer tag for r");
  offset++;
  const rLength = sigBytes[offset];
  offset++;
  let rBytes = sigBytes.slice(offset, offset + rLength);
  offset += rLength;

  if (sigBytes[offset] !== 0x02) throw new Error("Invalid signature: expected integer tag for s");
  offset++;
  const sLength = sigBytes[offset];
  offset++;
  let sBytes = sigBytes.slice(offset, offset + sLength);

  // Remove leading zeros
  if (rBytes.length === 33 && rBytes[0] === 0) rBytes = rBytes.slice(1);
  if (sBytes.length === 33 && sBytes[0] === 0) sBytes = sBytes.slice(1);

  const r = BigInt(
    "0x" +
      Array.from(rBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""),
  );
  const s = BigInt(
    "0x" +
      Array.from(sBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""),
  );

  // Compute message hash
  const clientDataHash = sha256(new Uint8Array(response.clientDataJSON));
  const message = sha256(new Uint8Array([...new Uint8Array(response.authenticatorData), ...clientDataHash]));

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

        candidates.push({ qx, qy, pubKeyBytes });
      } catch {
        // This combination didn't work, skip
        continue;
      }
    }
  }

  console.log(`Recovered ${candidates.length} candidate public keys`);
  return candidates;
}

/**
 * Find the correct public key by verifying a second signature against all candidates
 * The correct key is the only one that validates BOTH signatures
 */
function findCorrectKey(
  candidates: CandidateKey[],
  credential2: PublicKeyCredential,
): { qx: `0x${string}`; qy: `0x${string}` } {
  const response2 = credential2.response as AuthenticatorAssertionResponse;

  // Parse signature 2
  const sigBytes2 = new Uint8Array(response2.signature);
  if (sigBytes2[0] !== 0x30) {
    throw new Error("Invalid signature 2: expected DER sequence");
  }

  let offset = 2;
  if (sigBytes2[offset] !== 0x02) throw new Error("Invalid signature 2: expected integer tag for r");
  offset++;
  const rLength = sigBytes2[offset];
  offset++;
  let rBytes = sigBytes2.slice(offset, offset + rLength);
  offset += rLength;

  if (sigBytes2[offset] !== 0x02) throw new Error("Invalid signature 2: expected integer tag for s");
  offset++;
  const sLength = sigBytes2[offset];
  offset++;
  let sBytes = sigBytes2.slice(offset, offset + sLength);

  // Remove leading zeros
  if (rBytes.length === 33 && rBytes[0] === 0) rBytes = rBytes.slice(1);
  if (sBytes.length === 33 && sBytes[0] === 0) sBytes = sBytes.slice(1);

  const r2 = BigInt(
    "0x" +
      Array.from(rBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""),
  );
  const s2 = BigInt(
    "0x" +
      Array.from(sBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""),
  );

  // Compute message hash for signature 2
  const clientDataHash2 = sha256(new Uint8Array(response2.clientDataJSON));
  const message2 = sha256(new Uint8Array([...new Uint8Array(response2.authenticatorData), ...clientDataHash2]));

  // Try both S values for signature 2
  const s2Values = [s2, P256_CURVE_ORDER - s2];

  // For each candidate, check if signature 2 verifies
  for (const candidate of candidates) {
    for (const tryS2 of s2Values) {
      try {
        const sig2 = new p256.Signature(r2, tryS2);
        const sigBytes = sig2.toBytes();
        const isValid = p256.verify(sigBytes, message2, candidate.pubKeyBytes, { prehash: false });

        if (isValid) {
          console.log("Found correct public key:", { qx: candidate.qx, qy: candidate.qy });
          return { qx: candidate.qx, qy: candidate.qy };
        }
      } catch {
        // Verification failed, try next
        continue;
      }
    }
  }

  throw new Error("Could not find a public key that verifies both signatures");
}

/**
 * Check if WebAuthn is supported in the current browser
 */
export function isWebAuthnSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}

/**
 * Check if the platform supports platform authenticators (Touch ID, Face ID, Windows Hello)
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
