import { createPublicClient, formatEther, formatUnits, http, parseEther, parseUnits } from "viem";
import { base } from "viem/chains";

// Contract addresses on Base
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const WETH_ADDRESS = "0x4200000000000000000000000000000000000006" as const;
const QUOTER_V2_ADDRESS = "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a" as const;

// QuoterV2 ABI for quoteExactInputSingle
const QUOTER_V2_ABI = [
  {
    inputs: [
      {
        components: [
          { name: "tokenIn", type: "address" },
          { name: "tokenOut", type: "address" },
          { name: "amountIn", type: "uint256" },
          { name: "fee", type: "uint24" },
          { name: "sqrtPriceLimitX96", type: "uint160" },
        ],
        name: "params",
        type: "tuple",
      },
    ],
    name: "quoteExactInputSingle",
    outputs: [
      { name: "amountOut", type: "uint256" },
      { name: "sqrtPriceX96After", type: "uint160" },
      { name: "initializedTicksCrossed", type: "uint32" },
      { name: "gasEstimate", type: "uint256" },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

function getRpcUrl(): string {
  const alchemyKey = process.env.ALCHEMY_API_KEY;
  if (alchemyKey) {
    return `https://base-mainnet.g.alchemy.com/v2/${alchemyKey}`;
  }
  return "https://mainnet.base.org";
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const from = searchParams.get("from")?.toUpperCase();
    const to = searchParams.get("to")?.toUpperCase();
    const amountIn = searchParams.get("amountIn");

    // Validate parameters
    if (!from || !to || !amountIn) {
      return Response.json({ error: "Missing required parameters: from, to, amountIn" }, { status: 400 });
    }

    if ((from !== "ETH" && from !== "USDC") || (to !== "ETH" && to !== "USDC")) {
      return Response.json({ error: "Invalid asset. Must be ETH or USDC" }, { status: 400 });
    }

    if (from === to) {
      return Response.json({ error: "Cannot swap same asset" }, { status: 400 });
    }

    const amountNum = parseFloat(amountIn);
    if (isNaN(amountNum) || amountNum <= 0) {
      return Response.json({ error: "Invalid amountIn. Must be a positive number" }, { status: 400 });
    }

    // Determine token addresses and decimals based on direction
    let tokenIn: `0x${string}`;
    let tokenOut: `0x${string}`;
    let amountInWei: bigint;
    let decimalsOut: number;

    if (from === "USDC" && to === "ETH") {
      tokenIn = USDC_ADDRESS;
      tokenOut = WETH_ADDRESS;
      decimalsOut = 18;
      amountInWei = parseUnits(amountIn, 6);
    } else {
      // ETH to USDC
      tokenIn = WETH_ADDRESS;
      tokenOut = USDC_ADDRESS;
      decimalsOut = 6;
      amountInWei = parseEther(amountIn);
    }

    const rpcUrl = getRpcUrl();
    const publicClient = createPublicClient({
      chain: base,
      transport: http(rpcUrl),
    });

    // Call QuoterV2 to get the quote
    // Note: quoteExactInputSingle is marked as nonpayable but can be called via staticcall
    const result = await publicClient.simulateContract({
      address: QUOTER_V2_ADDRESS,
      abi: QUOTER_V2_ABI,
      functionName: "quoteExactInputSingle",
      args: [
        {
          tokenIn,
          tokenOut,
          amountIn: amountInWei,
          fee: 500, // 0.05% fee tier - best liquidity for USDC/WETH on Base
          sqrtPriceLimitX96: 0n,
        },
      ],
    });

    const [amountOut, , , gasEstimate] = result.result;

    // Format output based on decimals
    const formattedAmountOut = decimalsOut === 18 ? formatEther(amountOut) : formatUnits(amountOut, decimalsOut);

    // Calculate price per token
    const pricePerToken = amountNum > 0 ? parseFloat(formattedAmountOut) / amountNum : 0;

    return Response.json({
      from,
      to,
      amountIn,
      amountInRaw: amountInWei.toString(),
      amountOut: formattedAmountOut,
      amountOutRaw: amountOut.toString(),
      pricePerToken: pricePerToken.toFixed(decimalsOut === 6 ? 2 : 8),
      fee: "0.05%",
      gasEstimate: gasEstimate.toString(),
    });
  } catch (error) {
    console.error("[Swap Quote API] Error:", error);

    // Check for common errors
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (errorMessage.includes("insufficient liquidity")) {
      return Response.json({ error: "Insufficient liquidity for this swap" }, { status: 400 });
    }

    return Response.json(
      {
        error: "Failed to get swap quote",
        details: errorMessage,
      },
      { status: 500 },
    );
  }
}
