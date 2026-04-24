// Stdio entry for @paybridge-np/mcp. Reads PAYBRIDGE_API_KEY from env (or
// --api-key=... flag), wires up an ApiClient + StdioServerTransport, and
// registers every tool exported by @paybridge/mcp-core.
//
// Install:
//   npx -y @paybridge-np/mcp@latest
//
// Claude Desktop config:
//   {
//     "mcpServers": {
//       "paybridge": {
//         "command": "npx",
//         "args": ["-y", "@paybridge-np/mcp@latest"],
//         "env": { "PAYBRIDGE_API_KEY": "sk_live_..." }
//       }
//     }
//   }

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  ApiClient,
  TOOLS,
  getTool,
  PROMPTS,
  getPrompt,
  McpToolError,
  ScopeError,
  redactResponse,
  hasScope,
  dispatchTool,
  MCP_CORE_VERSION,
  type ScopeContext,
  type ToolContext,
} from "@paybridge/mcp-core";

function readApiKey(): string {
  const fromEnv = process.env.PAYBRIDGE_API_KEY;
  if (fromEnv) return fromEnv;
  const flag = process.argv.find((a) => a.startsWith("--api-key="));
  if (flag) return flag.slice("--api-key=".length);
  throw new Error(
    "Missing PayBridgeNP API key. Set PAYBRIDGE_API_KEY in env or pass --api-key=sk_live_...",
  );
}

async function main(): Promise<void> {
  const apiKey = readApiKey();
  const baseUrl = process.env.PAYBRIDGE_API_BASE_URL;

  const api = new ApiClient({ apiKey, baseUrl });

  // Phase 1: scopes are not yet read from the api_keys row. Until Phase 2
  // we treat every key as having full access (granted = null).
  const scope: ScopeContext = { granted: null };

  const server = new Server(
    {
      name: "paybridge-np",
      version: MCP_CORE_VERSION,
    },
    {
      capabilities: {
        tools: { listChanged: false },
        prompts: { listChanged: false },
        logging: {},
      },
    },
  );

  // Captured from the InitializeRequest handshake; populated in onInitialized.
  let clientName = "unknown";
  server.oninitialized = () => {
    const info = server.getClientVersion();
    if (info?.name) clientName = info.name;
  };

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: t.annotations,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const tool = getTool(name);

    if (!tool) {
      return errorResult(`Unknown tool: ${name}`);
    }

    for (const required of tool.requiredScopes) {
      if (!hasScope(scope, required as never)) {
        return errorResult(`Missing required scope: ${required}`);
      }
    }

    // Wire elicitation only when the client declared the capability during
    // the initialize handshake. Hosts that didn't advertise it cause our
    // destructive helpers to fail-closed with `elicitation_unsupported`.
    const clientCaps = server.getClientCapabilities();
    const elicit = clientCaps?.elicitation
      ? async (req: { message: string; schema: Record<string, unknown> }) => {
          const r = await server.elicitInput({
            mode: "form" as const,
            message: req.message,
            requestedSchema: req.schema as never,
          });
          return r as { action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> };
        }
      : undefined;

    const ctx: ToolContext = {
      api,
      scope,
      clientName,
      elicit,
    };

    try {
      const raw = await dispatchTool(tool, args, ctx);
      const includePii = hasScope(scope, "pii:read");
      const safe = redactResponse(raw, { includePii });
      return {
        content: [{ type: "text", text: JSON.stringify(safe, null, 2) }],
      };
    } catch (err) {
      if (err instanceof ScopeError) {
        return errorResult(`Missing required scope: ${err.required}`);
      }
      if (err instanceof McpToolError) {
        return errorResult(`${err.code}: ${err.message}`);
      }
      return errorResult(`Tool ${name} failed: ${(err as Error).message}`);
    }
  });

  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: PROMPTS.map((p) => ({
      name: p.name,
      description: p.description,
      arguments: p.arguments ?? [],
    })),
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (req) => {
    const name = req.params.name;
    const args = (req.params.arguments ?? {}) as Record<string, string>;
    const prompt = getPrompt(name);

    if (!prompt) {
      throw new Error(`Unknown prompt: ${name}`);
    }

    return {
      description: prompt.description,
      messages: prompt.handler(args),
    };
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function errorResult(message: string) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
  };
}

main().catch((err: Error) => {
  // stdio MCP servers must never write to stdout for non-protocol output.
  // Errors go to stderr.
  process.stderr.write(`[paybridge-mcp] fatal: ${err.message}\n`);
  process.exit(1);
});
