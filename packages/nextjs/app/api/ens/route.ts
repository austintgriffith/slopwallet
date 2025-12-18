import { OPTIONS, jsonResponse } from "../cors";
import { createPublicClient, fallback, http, isAddress } from "viem";
import { mainnet } from "viem/chains";
import { normalize } from "viem/ens";

export { OPTIONS };

// Build fallback transport chain: BuidlGuidl -> Alchemy (if available) -> Cloudflare
const transports = [
  http("https://mainnet.rpc.buidlguidl.com"),
  ...(process.env.ALCHEMY_API_KEY ? [http(`https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`)] : []),
  http("https://cloudflare-eth.com"),
];

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get("query");

    // Validate query parameter
    if (!query) {
      return jsonResponse({ error: "Missing query parameter" }, 400);
    }

    const trimmedQuery = query.trim();

    const publicClient = createPublicClient({
      chain: mainnet,
      transport: fallback(transports),
    });

    // Detect if input is an ENS name or an address
    const isEnsName = trimmedQuery.includes(".");

    if (isEnsName) {
      // Forward resolution: ENS name → address
      try {
        const normalizedName = normalize(trimmedQuery);
        const address = await publicClient.getEnsAddress({ name: normalizedName });

        if (!address) {
          return jsonResponse({
            query: trimmedQuery,
            address: null,
            ensName: normalizedName,
            type: "forward",
            error: "ENS name not found or not resolved to an address",
          });
        }

        // Also try to get the primary ENS name for this address (may differ from input)
        const primaryName = await publicClient.getEnsName({ address });

        return jsonResponse({
          query: trimmedQuery,
          address,
          ensName: primaryName || normalizedName,
          type: "forward",
        });
      } catch (normalizeError) {
        return jsonResponse(
          {
            error: "Invalid ENS name format",
            details: normalizeError instanceof Error ? normalizeError.message : String(normalizeError),
          },
          400,
        );
      }
    } else if (isAddress(trimmedQuery)) {
      // Reverse resolution: address → ENS name
      const address = trimmedQuery as `0x${string}`;
      const ensName = await publicClient.getEnsName({ address });

      return jsonResponse({
        query: trimmedQuery,
        address,
        ensName: ensName || null,
        type: "reverse",
      });
    } else {
      return jsonResponse(
        {
          error: "Invalid query format. Provide an ENS name (e.g., vitalik.eth) or an Ethereum address (0x...)",
        },
        400,
      );
    }
  } catch (error) {
    console.error("[ENS API] Error:", error);
    return jsonResponse(
      {
        error: "Failed to resolve ENS",
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    );
  }
}
