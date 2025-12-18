# SlopWallet.com

> an experiment with smart contract wallet factories, wallet connecting, and passkey verification

Built with Scaffold-ETH 2.

## Quickstart

1. Install dependencies:

```
yarn install
```

2. Run a local network:

```
yarn chain
```

3. Deploy the contracts:

```
yarn deploy
```

4. Configure environment variables in `packages/nextjs/.env.local`:

```
NEXT_PUBLIC_ALCHEMY_API_KEY=your_alchemy_api_key
FACILITATOR_PRIVATE_KEY=0x...
ANTHROPIC_API_KEY=your_anthropic_api_key
```

5. Start the app:

```
yarn start
```

Visit `http://localhost:3000`

---

## API Reference

All endpoints support CORS and return JSON. Base URL: `/api`

### Passkey Endpoints

#### `POST /api/passkey/check`

Check which candidate passkey public keys are registered on a smart wallet. Used for API-only passkey login flows where you recover candidate keys from a signature.

**Request:**

```json
{
  "wallet": "0x...",
  "chainId": 8453,
  "candidates": [
    { "qx": "0x...", "qy": "0x..." },
    { "qx": "0x...", "qy": "0x..." }
  ]
}
```

**Response:**

```json
{
  "matches": [
    {
      "qx": "0x...",
      "qy": "0x...",
      "passkeyAddress": "0x...",
      "isPasskey": true
    }
  ],
  "wallet": "0x...",
  "chainId": 8453
}
```

**Notes:**

- Maximum 10 candidates per request
- `qx` and `qy` must be 32-byte hex strings (66 chars with `0x` prefix)
- Supported chains: Base (8453), Ethereum Mainnet (1)

---

#### `GET /api/nonce`

Get the current nonce for a passkey on a smart wallet.

**Query params:**

- `wallet` (required): Smart wallet address
- `chainId` (optional): Chain ID (default: 8453)
- `passkey`: Passkey address, OR
- `qx` + `qy`: Public key coordinates

**Response:**

```json
{
  "nonce": "1",
  "passkeyAddress": "0x...",
  "wallet": "0x...",
  "chainId": 8453
}
```

---

#### `POST /api/facilitate`

Submit a gasless meta-transaction signed by a passkey. The facilitator pays the gas.

**Request:**

```json
{
  "smartWalletAddress": "0x...",
  "chainId": 8453,
  "isBatch": false,
  "calls": [{ "target": "0x...", "value": "0", "data": "0x..." }],
  "qx": "0x...",
  "qy": "0x...",
  "deadline": "1234567890",
  "auth": {
    "r": "0x...",
    "s": "0x...",
    "challengeIndex": "36",
    "typeIndex": "1",
    "authenticatorData": "0x...",
    "clientDataJSON": "..."
  }
}
```

**Response:**

```json
{
  "success": true,
  "txHash": "0x...",
  "blockNumber": "12345",
  "gasUsed": "50000"
}
```

**Notes:**

- Only whitelisted smart wallets are supported
- Verifies WebAuthn signature cryptographically before submitting

---

### Balance & Token Endpoints

#### `GET /api/balances`

Get ETH and USDC balances for an address on Base.

**Query params:**

- `address` (required): Ethereum address

**Response:**

```json
{
  "address": "0x...",
  "balances": {
    "eth": {
      "raw": "1000000000000000000",
      "formatted": "1.0",
      "symbol": "ETH",
      "decimals": 18
    },
    "usdc": {
      "raw": "1000000",
      "formatted": "1.0",
      "symbol": "USDC",
      "decimals": 6
    }
  }
}
```

---

#### `POST /api/transfer`

Generate calldata for an ETH or USDC transfer.

**Request:**

```json
{
  "asset": "ETH",
  "amount": "0.1",
  "to": "0x..."
}
```

**Response:**

```json
{
  "success": true,
  "asset": "ETH",
  "amount": "0.1",
  "to": "0x...",
  "call": {
    "target": "0x...",
    "value": "100000000000000000",
    "data": "0x"
  }
}
```

---

### Swap Endpoints

#### `GET /api/swap/quote`

Get a quote for swapping ETH <-> USDC on Base via Uniswap V3.

**Query params:**

- `from` (required): "ETH" or "USDC"
- `to` (required): "ETH" or "USDC"
- `amountIn` (required): Amount to swap (human readable)

**Response:**

```json
{
  "from": "ETH",
  "to": "USDC",
  "amountIn": "0.1",
  "amountInRaw": "100000000000000000",
  "amountOut": "350.25",
  "amountOutRaw": "350250000",
  "pricePerToken": "3502.50",
  "fee": "0.05%",
  "gasEstimate": "150000"
}
```

---

#### `POST /api/swap`

Generate calldata for an ETH <-> USDC swap.

**Request:**

```json
{
  "from": "ETH",
  "to": "USDC",
  "amountIn": "0.1",
  "amountOutMinimum": "340",
  "recipient": "0x..."
}
```

**Response:**

```json
{
  "success": true,
  "from": "ETH",
  "to": "USDC",
  "amountIn": "0.1",
  "amountOutMinimum": "340",
  "recipient": "0x...",
  "calls": [
    { "target": "0x...", "value": "100000000000000000", "data": "0x..." }
  ]
}
```

**Notes:**

- USDC -> ETH requires 3 calls (approve, swap, unwrap)
- ETH -> USDC requires 1 call

---

### ENS Endpoint

#### `GET /api/ens`

Resolve ENS names to addresses or addresses to ENS names.

**Query params:**

- `query` (required): ENS name (e.g., `vitalik.eth`) or Ethereum address

**Response (forward resolution):**

```json
{
  "query": "vitalik.eth",
  "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "ensName": "vitalik.eth",
  "type": "forward"
}
```

**Response (reverse resolution):**

```json
{
  "query": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "ensName": "vitalik.eth",
  "type": "reverse"
}
```

---

### AI Agent Endpoint

#### `POST /api/agent`

Natural language transaction generation using Claude.

**Request:**

```json
{
  "prompt": "Send 0.1 ETH to vitalik.eth",
  "walletAddress": "0x..."
}
```

**Response (transaction):**

```json
{
  "calls": [{ "target": "0x...", "value": "100000000000000000", "data": "0x" }]
}
```

**Response (information):**

```json
{
  "response": "Your current balance is 1.5 ETH and 500 USDC."
}
```

**Notes:**

- Requires `ANTHROPIC_API_KEY` environment variable
- Automatically fetches wallet holdings for context

---

### Transaction Analysis Endpoint

#### `POST /api/unblind`

Analyze a transaction or message signature for security risks using Unblind.

**Request (transaction):**

```json
{
  "type": "transaction",
  "chainId": "8453",
  "from": "0x...",
  "to": "0x...",
  "value": "0x0",
  "data": "0x..."
}
```

**Request (message):**

```json
{
  "type": "message",
  "signatureMethod": "eth_signTypedData_v4",
  "from": "0x...",
  "data": { ... }
}
```

**Response:**

```json
{
  "analysis": "This transaction transfers 100 USDC to 0x...",
  "warnings": []
}
```

---

## Passkey Public Key Recovery

When logging in with an existing passkey, WebAuthn only returns a signature - not the public key. To derive `qx`/`qy`:

1. From one ECDSA signature on P-256, recover up to 4 candidate public keys
2. Check which candidate is registered on-chain via `/api/passkey/check`
3. If no match, get a second signature - only one candidate will verify both

**Libraries needed:**

```typescript
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

// Recover from signature
const sig = new p256.Signature(r, s, recoveryBit);
const pubKey = sig.recoverPublicKey(messageHash);
```

See `packages/nextjs/utils/passkey.ts` for the full implementation.

---

## Contributing

See [CONTRIBUTING.MD](https://github.com/scaffold-eth/scaffold-eth-2/blob/main/CONTRIBUTING.md)
