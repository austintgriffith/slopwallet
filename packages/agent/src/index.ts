import Anthropic from "@anthropic-ai/sdk";
import * as dotenv from "dotenv";
import * as path from "path";
import { fileURLToPath } from "url";
import { isAddress } from "viem";
import { holdings } from "./holdings.js";

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from packages/agent/.env
dotenv.config({ path: path.join(__dirname, "../.env") });

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY || "";
const WALLET_ADDRESS = process.env.WALLET_ADDRESS || "";

function buildContext(walletAddress: string): string {
  return `# SlopWallet Transaction Agent

You generate JSON for a smart wallet on Base. Always respond with raw JSON only - no markdown, no code blocks, no explanations.

## Response Format

For questions or information:
{"response": "Your answer here"}

For transactions:
{"calls": [{"target": "0x...", "value": "0", "data": "0x..."}]}

Never wrap in \`\`\`json blocks. Output raw JSON only.

## User's Wallet

Address: ${walletAddress}
Chain: Base (chainId: 8453)

## Transaction Fields

- target: Contract address to call
- value: ETH in wei ("0" for no ETH)
- data: ABI-encoded calldata

## Base Contract Addresses

- USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 (6 decimals)
- WETH: 0x4200000000000000000000000000000000000006 (18 decimals)`;
}

async function main() {
  // Get prompt from command line arguments
  const prompt = process.argv.slice(2).join(" ");

  if (!prompt) {
    console.error("Usage: yarn start <your prompt>");
    console.error('Example: yarn start "send all my USDC to 0x1234..."');
    process.exit(1);
  }

  // Check for API keys
  if (!ANTHROPIC_API_KEY) {
    console.error("Error: ANTHROPIC_API_KEY not set in .env file");
    process.exit(1);
  }

  if (!ALCHEMY_API_KEY) {
    console.error("Error: ALCHEMY_API_KEY not set in .env file");
    process.exit(1);
  }

  if (!WALLET_ADDRESS || !isAddress(WALLET_ADDRESS)) {
    console.error("Error: WALLET_ADDRESS not set or invalid in .env file");
    process.exit(1);
  }

  // Build context with wallet address
  const context = buildContext(WALLET_ADDRESS);

  // Fetch current holdings
  const holdingsReport = await holdings(
    WALLET_ADDRESS as `0x${string}`,
    ALCHEMY_API_KEY
  );
  const fullContext = context + "\n\n" + holdingsReport;

  // Initialize Anthropic client
  const anthropic = new Anthropic({
    apiKey: ANTHROPIC_API_KEY,
  });

  try {
    // Send message to Claude
    const message = await anthropic.messages.create({
      model: "claude-sonnet-4-20250514",
      max_tokens: 4096,
      system: fullContext,
      messages: [
        {
          role: "user",
          content: prompt,
        },
      ],
    });

    // Extract and print response
    const response =
      message.content[0].type === "text" ? message.content[0].text : "";
    console.log(response);
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown error";
    console.error("Error calling Anthropic API:", errorMessage);
    process.exit(1);
  }
}

main();
