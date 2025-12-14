import {
  createPublicClient,
  http,
  formatEther,
  formatUnits,
  erc20Abi,
} from "viem";
import { base } from "viem/chains";

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const WETH = "0x4200000000000000000000000000000000000006" as const;

export async function holdings(
  walletAddress: `0x${string}`,
  alchemyApiKey: string
): Promise<string> {
  const client = createPublicClient({
    chain: base,
    transport: http(`https://base-mainnet.g.alchemy.com/v2/${alchemyApiKey}`),
  });

  // Fetch ETH, USDC, WETH balances in parallel
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
