import { OPTIONS, jsonResponse } from "../cors";
import { encodeFunctionData, isAddress, parseEther, parseUnits } from "viem";

export { OPTIONS };

// USDC contract address on Base
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;

// ERC20 transfer ABI
const ERC20_TRANSFER_ABI = [
  {
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    name: "transfer",
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

interface TransferRequest {
  asset: "ETH" | "USDC";
  amount: string;
  to: string;
}

export async function POST(request: Request) {
  try {
    const body: TransferRequest = await request.json();

    // Validate required fields
    if (!body.asset || !body.amount || !body.to) {
      return jsonResponse({ error: "Missing required fields: asset, amount, to" }, 400);
    }

    // Validate asset type
    if (body.asset !== "ETH" && body.asset !== "USDC") {
      return jsonResponse({ error: "Invalid asset. Must be ETH or USDC" }, 400);
    }

    // Validate recipient address
    if (!isAddress(body.to)) {
      return jsonResponse({ error: "Invalid recipient address" }, 400);
    }

    // Validate amount is a valid number
    const amountNum = parseFloat(body.amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return jsonResponse({ error: "Invalid amount. Must be a positive number" }, 400);
    }

    let callData: {
      target: `0x${string}`;
      value: string;
      data: `0x${string}`;
    };

    if (body.asset === "ETH") {
      // ETH transfer: send value directly to recipient
      const valueWei = parseEther(body.amount);
      callData = {
        target: body.to as `0x${string}`,
        value: valueWei.toString(),
        data: "0x",
      };
    } else {
      // USDC transfer: call transfer() on USDC contract
      const amountUnits = parseUnits(body.amount, 6); // USDC has 6 decimals
      const transferData = encodeFunctionData({
        abi: ERC20_TRANSFER_ABI,
        functionName: "transfer",
        args: [body.to as `0x${string}`, amountUnits],
      });

      callData = {
        target: USDC_ADDRESS,
        value: "0",
        data: transferData,
      };
    }

    return jsonResponse({
      success: true,
      asset: body.asset,
      amount: body.amount,
      to: body.to,
      call: callData,
    });
  } catch (error) {
    console.error("[Transfer API] Error:", error);
    return jsonResponse(
      {
        error: "Failed to generate transfer calldata",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
