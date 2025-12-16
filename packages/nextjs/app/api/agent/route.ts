import { OPTIONS, jsonResponse } from "../cors";
import Anthropic from "@anthropic-ai/sdk";
import { createPublicClient, erc20Abi, formatEther, formatUnits, http, isAddress } from "viem";
import { base } from "viem/chains";

export { OPTIONS };

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const WETH = "0x4200000000000000000000000000000000000006" as const;

async function getHoldings(walletAddress: `0x${string}`, alchemyApiKey: string): Promise<string> {
  const client = createPublicClient({
    chain: base,
    transport: http(`https://base-mainnet.g.alchemy.com/v2/${alchemyApiKey}`),
  });

  const [ethBalance, usdcBalance, wethBalance] = await Promise.all([
    client.getBalance({ address: walletAddress }),
    client.readContract({
      address: USDC,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [walletAddress],
    }),
    client.readContract({
      address: WETH,
      abi: erc20Abi,
      functionName: "balanceOf",
      args: [walletAddress],
    }),
  ]);

  return `## Current Holdings
- ETH: ${formatEther(ethBalance)}
- USDC: ${formatUnits(usdcBalance, 6)}
- WETH: ${formatEther(wethBalance)}`;
}

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

export async function POST(request: Request) {
  try {
    const { prompt, walletAddress } = await request.json();

    if (!prompt || typeof prompt !== "string") {
      return jsonResponse({ error: "Missing prompt" }, 400);
    }

    if (!walletAddress || !isAddress(walletAddress)) {
      return jsonResponse({ error: "Invalid wallet address" }, 400);
    }

    const anthropicApiKey = process.env.ANTHROPIC_API_KEY;
    const alchemyApiKey = process.env.ALCHEMY_API_KEY || process.env.NEXT_PUBLIC_ALCHEMY_API_KEY;

    if (!anthropicApiKey) {
      return jsonResponse({ error: "ANTHROPIC_API_KEY not configured" }, 500);
    }

    if (!alchemyApiKey) {
      return jsonResponse({ error: "ALCHEMY_API_KEY not configured" }, 500);
    }

    // Build context and fetch holdings
    const context = buildContext(walletAddress);
    const holdings = await getHoldings(walletAddress as `0x${string}`, alchemyApiKey);
    const fullContext = context + "\n\n" + holdings;

    // Call Anthropic API
    const anthropic = new Anthropic({
      apiKey: anthropicApiKey,
    });

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

    // Extract response text
    const responseText = message.content[0].type === "text" ? message.content[0].text : "";

    // Parse JSON response from Claude
    try {
      const parsed = JSON.parse(responseText);
      return jsonResponse(parsed);
    } catch {
      // If Claude didn't return valid JSON, wrap it as a response
      return jsonResponse({ response: responseText });
    }
  } catch (error) {
    console.error("Agent API error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return jsonResponse({ error: errorMessage }, 500);
  }
}
