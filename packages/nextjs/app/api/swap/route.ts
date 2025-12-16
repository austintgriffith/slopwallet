import { OPTIONS, jsonResponse } from "../cors";
import { encodeFunctionData, isAddress, parseEther, parseUnits } from "viem";

export { OPTIONS };

// Contract addresses on Base
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const WETH_ADDRESS = "0x4200000000000000000000000000000000000006" as const;
const SWAP_ROUTER_ADDRESS = "0x2626664c2603336E57B271c5C0b26F421741e481" as const;

// ERC20 ABI for approve
const ERC20_ABI = [
  {
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    name: "approve",
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

// Uniswap V3 SwapRouter02 ABI
const SWAP_ROUTER_ABI = [
  {
    inputs: [
      {
        components: [
          { name: "tokenIn", type: "address" },
          { name: "tokenOut", type: "address" },
          { name: "fee", type: "uint24" },
          { name: "recipient", type: "address" },
          { name: "amountIn", type: "uint256" },
          { name: "amountOutMinimum", type: "uint256" },
          { name: "sqrtPriceLimitX96", type: "uint160" },
        ],
        name: "params",
        type: "tuple",
      },
    ],
    name: "exactInputSingle",
    outputs: [{ name: "amountOut", type: "uint256" }],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      { name: "amountMinimum", type: "uint256" },
      { name: "recipient", type: "address" },
    ],
    name: "unwrapWETH9",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
] as const;

interface SwapRequest {
  from: "ETH" | "USDC";
  to: "ETH" | "USDC";
  amountIn: string;
  amountOutMinimum: string;
  recipient: string;
}

export async function POST(request: Request) {
  try {
    const body: SwapRequest = await request.json();

    // Validate required fields
    if (!body.from || !body.to || !body.amountIn || !body.amountOutMinimum || !body.recipient) {
      return jsonResponse({ error: "Missing required fields: from, to, amountIn, amountOutMinimum, recipient" }, 400);
    }

    const from = body.from.toUpperCase();
    const to = body.to.toUpperCase();

    if ((from !== "ETH" && from !== "USDC") || (to !== "ETH" && to !== "USDC")) {
      return jsonResponse({ error: "Invalid asset. Must be ETH or USDC" }, 400);
    }

    if (from === to) {
      return jsonResponse({ error: "Cannot swap same asset" }, 400);
    }

    if (!isAddress(body.recipient)) {
      return jsonResponse({ error: "Invalid recipient address" }, 400);
    }

    const amountNum = parseFloat(body.amountIn);
    if (isNaN(amountNum) || amountNum <= 0) {
      return jsonResponse({ error: "Invalid amountIn. Must be a positive number" }, 400);
    }

    const calls: Array<{ target: `0x${string}`; value: string; data: `0x${string}` }> = [];

    if (from === "USDC" && to === "ETH") {
      // USDC -> ETH swap (3 calls: approve, swap, unwrap)
      const amountInWei = parseUnits(body.amountIn, 6);
      const amountOutMinWei = parseEther(body.amountOutMinimum);

      // 1. Approve USDC to SwapRouter
      const approveData = encodeFunctionData({
        abi: ERC20_ABI,
        functionName: "approve",
        args: [SWAP_ROUTER_ADDRESS, amountInWei],
      });

      calls.push({
        target: USDC_ADDRESS,
        value: "0",
        data: approveData,
      });

      // 2. Swap USDC -> WETH (recipient = SwapRouter for unwrap)
      const swapData = encodeFunctionData({
        abi: SWAP_ROUTER_ABI,
        functionName: "exactInputSingle",
        args: [
          {
            tokenIn: USDC_ADDRESS,
            tokenOut: WETH_ADDRESS,
            fee: 500, // 0.05% fee tier
            recipient: SWAP_ROUTER_ADDRESS, // WETH goes to router for unwrap
            amountIn: amountInWei,
            amountOutMinimum: amountOutMinWei,
            sqrtPriceLimitX96: 0n,
          },
        ],
      });

      calls.push({
        target: SWAP_ROUTER_ADDRESS,
        value: "0",
        data: swapData,
      });

      // 3. Unwrap WETH to ETH and send to recipient
      const unwrapData = encodeFunctionData({
        abi: SWAP_ROUTER_ABI,
        functionName: "unwrapWETH9",
        args: [amountOutMinWei, body.recipient as `0x${string}`],
      });

      calls.push({
        target: SWAP_ROUTER_ADDRESS,
        value: "0",
        data: unwrapData,
      });
    } else {
      // ETH -> USDC swap (1 call with ETH value)
      const amountInWei = parseEther(body.amountIn);
      const amountOutMinWei = parseUnits(body.amountOutMinimum, 6);

      // Swap ETH -> USDC (SwapRouter handles WETH wrapping)
      const swapData = encodeFunctionData({
        abi: SWAP_ROUTER_ABI,
        functionName: "exactInputSingle",
        args: [
          {
            tokenIn: WETH_ADDRESS,
            tokenOut: USDC_ADDRESS,
            fee: 500, // 0.05% fee tier
            recipient: body.recipient as `0x${string}`,
            amountIn: amountInWei,
            amountOutMinimum: amountOutMinWei,
            sqrtPriceLimitX96: 0n,
          },
        ],
      });

      calls.push({
        target: SWAP_ROUTER_ADDRESS,
        value: amountInWei.toString(), // Send ETH with the call
        data: swapData,
      });
    }

    return jsonResponse({
      success: true,
      from,
      to,
      amountIn: body.amountIn,
      amountOutMinimum: body.amountOutMinimum,
      recipient: body.recipient,
      calls,
    });
  } catch (error) {
    console.error("[Swap API] Error:", error);
    return jsonResponse(
      {
        error: "Failed to generate swap calldata",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
