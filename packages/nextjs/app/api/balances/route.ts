import { createPublicClient, formatEther, formatUnits, http, isAddress } from "viem";
import { base } from "viem/chains";

// USDC contract address on Base
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;

// ERC20 ABI for balanceOf
const ERC20_ABI = [
  {
    inputs: [{ name: "account", type: "address" }],
    name: "balanceOf",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
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
    const address = searchParams.get("address");

    // Validate address
    if (!address) {
      return Response.json({ error: "Missing address parameter" }, { status: 400 });
    }

    if (!isAddress(address)) {
      return Response.json({ error: "Invalid address format" }, { status: 400 });
    }

    const rpcUrl = getRpcUrl();
    const publicClient = createPublicClient({
      chain: base,
      transport: http(rpcUrl),
    });

    // Fetch ETH and USDC balances in parallel
    const [ethBalance, usdcBalance] = await Promise.all([
      publicClient.getBalance({ address: address as `0x${string}` }),
      publicClient.readContract({
        address: USDC_ADDRESS,
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [address as `0x${string}`],
      }),
    ]);

    return Response.json({
      address,
      balances: {
        eth: {
          raw: ethBalance.toString(),
          formatted: formatEther(ethBalance),
          symbol: "ETH",
          decimals: 18,
        },
        usdc: {
          raw: usdcBalance.toString(),
          formatted: formatUnits(usdcBalance, 6),
          symbol: "USDC",
          decimals: 6,
        },
      },
    });
  } catch (error) {
    console.error("[Balances API] Error:", error);
    return Response.json(
      {
        error: "Failed to fetch balances",
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}
