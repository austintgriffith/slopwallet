/**
 * API route to proxy requests to the Unblind API
 * This keeps the API key server-side and handles request formatting
 */

const UNBLIND_API_URL = "https://api.unblind.app";

// Unblind API response types
interface UnblindTransactionResponse {
  hash?: string;
  analysis: string;
  warnings: string[];
  messageJSON?: string;
}

interface UnblindMessageResponse {
  hash?: string;
  analysis: string;
  warnings: string[];
  messageJSON?: string;
}

// Request body types
interface TransactionRequest {
  type: "transaction";
  chainId: string; // e.g., "eip155:8453" or "8453"
  from: string;
  to?: string;
  value?: string;
  data?: string;
  gas?: string;
  origin?: string;
}

interface MessageRequest {
  type: "message";
  signatureMethod: "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4" | "personal_sign" | "eth_sign";
  from?: string;
  data: unknown; // The typed data or message to be signed
}

type UnblindRequest = TransactionRequest | MessageRequest;

export async function POST(request: Request) {
  try {
    const body: UnblindRequest = await request.json();

    if (body.type === "transaction") {
      // Format chainId for Unblind API (expects "eip155:X" format with decimal chain ID)
      let chainId = body.chainId;

      // Handle various chain ID formats
      if (chainId.startsWith("eip155:")) {
        // Extract the chain ID part after "eip155:"
        const chainIdPart = chainId.slice(7);
        // Convert hex to decimal if needed (e.g., "0x2105" -> "8453")
        if (chainIdPart.startsWith("0x")) {
          const decimalChainId = parseInt(chainIdPart, 16);
          chainId = `eip155:${decimalChainId}`;
        }
      } else if (chainId.startsWith("0x")) {
        // Direct hex chain ID without eip155 prefix
        const decimalChainId = parseInt(chainId, 16);
        chainId = `eip155:${decimalChainId}`;
      } else {
        // Assume it's already decimal, just add prefix
        chainId = `eip155:${chainId}`;
      }

      // Build payload - only include defined fields to avoid serialization issues
      const unblindPayload: Record<string, string> = {
        chainId,
        from: body.from,
        gas: body.gas || "0x7A120", // Default 500000 gas for contract interactions
      };

      // Only include optional fields if they have values
      if (body.to) unblindPayload.to = body.to;
      if (body.value) unblindPayload.value = body.value;
      if (body.data) unblindPayload.data = body.data;
      if (body.origin) unblindPayload.origin = body.origin;

      console.log("[Unblind] Analyzing transaction:", {
        chainId: unblindPayload.chainId,
        from: unblindPayload.from,
        to: unblindPayload.to,
        value: unblindPayload.value,
        dataLength: unblindPayload.data?.length || 0,
      });

      const jsonBody = JSON.stringify(unblindPayload);
      console.log("[Unblind] Request payload size:", jsonBody.length, "bytes");

      // Add timeout to prevent hanging
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

      let response: Response;
      try {
        response = await fetch(`${UNBLIND_API_URL}/unblind/transaction`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: jsonBody,
          signal: controller.signal,
        });
      } catch (fetchError) {
        clearTimeout(timeoutId);
        if (fetchError instanceof Error && fetchError.name === "AbortError") {
          console.error("[Unblind] Request timed out");
          return Response.json({ error: "Analysis request timed out" }, { status: 504 });
        }
        throw fetchError;
      }
      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        console.error("[Unblind] Transaction API error:", response.status, errorText);
        return Response.json(
          { error: `Unblind API error: ${response.status}`, details: errorText },
          { status: response.status },
        );
      }

      const result: UnblindTransactionResponse = await response.json();
      console.log("[Unblind] Transaction analysis:", result.analysis);
      if (result.warnings?.length > 0) {
        console.log("[Unblind] Warnings:", result.warnings);
      }

      return Response.json({
        analysis: result.analysis,
        warnings: result.warnings || [],
      });
    } else if (body.type === "message") {
      const unblindPayload = {
        signatureMethod: body.signatureMethod,
        from: body.from,
        data: body.data,
      };

      console.log("[Unblind] Analyzing message signature:", {
        signatureMethod: body.signatureMethod,
        from: body.from,
      });

      const response = await fetch(`${UNBLIND_API_URL}/unblind/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(unblindPayload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error("[Unblind] Message API error:", response.status, errorText);
        return Response.json(
          { error: `Unblind API error: ${response.status}`, details: errorText },
          { status: response.status },
        );
      }

      const result: UnblindMessageResponse = await response.json();
      console.log("[Unblind] Message analysis:", result.analysis);
      if (result.warnings?.length > 0) {
        console.log("[Unblind] Warnings:", result.warnings);
      }

      return Response.json({
        analysis: result.analysis,
        warnings: result.warnings || [],
      });
    } else {
      return Response.json({ error: "Invalid request type. Use 'transaction' or 'message'" }, { status: 400 });
    }
  } catch (error) {
    console.error("[Unblind] Error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return Response.json({ error: errorMessage }, { status: 500 });
  }
}
