#!/usr/bin/env node

// src/index.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from "@modelcontextprotocol/sdk/types.js";

// ../mcp-core/src/errors.ts
var McpToolError = class extends Error {
  code;
  statusCode;
  raw;
  constructor(code, message, statusCode = 500, raw = null) {
    super(message);
    this.name = "McpToolError";
    this.code = code;
    this.statusCode = statusCode;
    this.raw = raw;
    Object.setPrototypeOf(this, new.target.prototype);
  }
};
function fromUpstream(status, body) {
  const message = typeof body?.error === "string" ? body.error : typeof body?.message === "string" ? body.message : `HTTP ${status}`;
  switch (status) {
    case 401:
      return new McpToolError("unauthorized", message, 401, body);
    case 403:
      return new McpToolError("forbidden", message, 403, body);
    case 404:
      return new McpToolError("not_found", message, 404, body);
    case 400:
    case 422:
      return new McpToolError("invalid_request", message, status, body);
    case 429:
      return new McpToolError("rate_limited", message, 429, body);
    default:
      return new McpToolError("upstream_error", message, status, body);
  }
}

// ../mcp-core/src/client/api.ts
var DEFAULT_BASE_URL = "https://api.paybridgenp.com";
var DEFAULT_TIMEOUT_MS = 3e4;
var DEFAULT_MAX_RETRIES = 2;
var RETRYABLE_STATUSES = /* @__PURE__ */ new Set([500, 502, 503, 504]);
var ApiClient = class {
  baseUrl;
  apiKey;
  timeoutMs;
  maxRetries;
  userAgent;
  constructor(cfg) {
    if (!cfg.apiKey) {
      throw new McpToolError("unauthorized", "Missing PayBridgeNP API key", 401);
    }
    this.apiKey = cfg.apiKey;
    this.baseUrl = (cfg.baseUrl ?? process.env.PAYBRIDGE_API_BASE_URL ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = cfg.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.userAgent = cfg.userAgent ?? `PayBridgeNP-MCP/${process.env.npm_package_version ?? "0.1.0"}`;
  }
  get(path, opts) {
    return this.request("GET", path, opts);
  }
  post(path, opts) {
    return this.request("POST", path, opts);
  }
  patch(path, opts) {
    return this.request("PATCH", path, opts);
  }
  delete(path, opts) {
    return this.request("DELETE", path, opts);
  }
  async request(method, path, opts = {}) {
    const url = this.buildUrl(path, opts.query);
    const headers = {
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": this.userAgent
    };
    if (opts.body !== void 0) {
      headers["Content-Type"] = "application/json";
    }
    if (opts.idempotencyKey) {
      headers["Idempotency-Key"] = opts.idempotencyKey;
    }
    let attempt = 0;
    while (true) {
      attempt++;
      let res;
      try {
        res = await fetch(url, {
          method,
          headers,
          body: opts.body !== void 0 ? JSON.stringify(opts.body) : void 0,
          signal: AbortSignal.timeout(this.timeoutMs)
        });
      } catch (err) {
        if (attempt > this.maxRetries) {
          throw new McpToolError(
            "connection_error",
            `Connection error reaching ${this.baseUrl}: ${err.message}`,
            0
          );
        }
        await sleep(backoff(attempt));
        continue;
      }
      if (res.ok) {
        if (res.status === 204) return void 0;
        const text = await res.text();
        return text ? JSON.parse(text) : void 0;
      }
      if (RETRYABLE_STATUSES.has(res.status) && attempt <= this.maxRetries) {
        const retryAfter = res.headers.get("Retry-After");
        const delay = retryAfter ? Number.parseInt(retryAfter, 10) * 1e3 : backoff(attempt);
        await sleep(delay);
        continue;
      }
      let raw = null;
      try {
        raw = await res.json();
      } catch {
      }
      throw fromUpstream(res.status, raw);
    }
  }
  buildUrl(path, query) {
    const url = new URL(path.startsWith("/") ? path : `/${path}`, this.baseUrl);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== void 0 && v !== null) {
          url.searchParams.set(k, String(v));
        }
      }
    }
    return url.toString();
  }
};
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function backoff(attempt) {
  return 500 * 2 ** (attempt - 1) + Math.random() * 100;
}

// ../mcp-core/src/scopes.ts
function hasScope(ctx, required) {
  if (ctx.granted === null) return true;
  return ctx.granted.includes(required);
}
var ScopeError = class extends Error {
  required;
  constructor(required) {
    super(`Missing required scope: ${required}`);
    this.name = "ScopeError";
    this.required = required;
    Object.setPrototypeOf(this, new.target.prototype);
  }
};

// ../mcp-core/src/redact.ts
var SECRET_PATTERNS = [
  [/\bsk_(live|test)_[A-Za-z0-9]{16,}\b/g, "[REDACTED:secret_key]"],
  [/\bpk_(live|test)_[A-Za-z0-9]{16,}\b/g, "[REDACTED:publishable_key]"],
  [/\bwhsec_[A-Za-z0-9]{16,}\b/g, "[REDACTED:webhook_secret]"],
  [/\bBearer\s+[A-Za-z0-9._\-]{20,}\b/gi, "[REDACTED:bearer_token]"]
];
var ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
var UNTRUSTED_FIELDS = /* @__PURE__ */ new Set([
  "customer_name",
  "customer_email",
  "customer_phone",
  "description",
  "title",
  "notes",
  "metadata",
  "reference_id",
  "inactive_message"
]);
var PAISA_FIELDS = /* @__PURE__ */ new Set([
  "amount",
  "amount_paisa",
  "amountPaisa",
  "refunded_amount",
  "refundedAmount",
  "remaining_refundable",
  "remainingRefundable",
  "spend_cap_paisa",
  "spendCapPaisa",
  "total_refunded",
  "totalRefunded",
  "total_amount",
  "totalAmount",
  "min_amount",
  "minAmount",
  "max_amount",
  "maxAmount",
  "subtotal",
  "tax_amount",
  "taxAmount",
  "gross_volume",
  "grossVolume",
  "net_volume",
  "netVolume",
  "refunds_total",
  "refundsTotal",
  "elicit_threshold_paisa",
  "elicitThresholdPaisa"
]);
function redactSecrets(input) {
  let out = input;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}
function stripZeroWidth(input) {
  return input.replace(ZERO_WIDTH, "");
}
function fenceUntrusted(value) {
  if (value == null) return "";
  const str = typeof value === "string" ? value : JSON.stringify(value);
  const cleaned = stripZeroWidth(str);
  return `<untrusted>${cleaned.replace(/<\/?untrusted>/g, "")}</untrusted>`;
}
function hashEmail(email) {
  const at = email.indexOf("@");
  if (at <= 0) return "[REDACTED]";
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const head = local.slice(0, Math.min(2, local.length));
  return `${head}***@${domain}`;
}
function hashPhone(phone) {
  const digits = phone.replace(/\D/g, "");
  if (digits.length < 4) return "[REDACTED]";
  return `***${digits.slice(-4)}`;
}
function redactResponse(value, opts) {
  return walk(value, opts);
}
function walk(value, opts, key) {
  if (value == null) return value;
  if (typeof value === "string") {
    let out = redactSecrets(stripZeroWidth(value));
    if (!opts.includePii) {
      if (key === "customerEmail" || key === "customer_email" || key === "email") {
        return hashEmail(out);
      }
      if (key === "customerPhone" || key === "customer_phone" || key === "phone") {
        return hashPhone(out);
      }
    }
    if (key && UNTRUSTED_FIELDS.has(snake(key))) {
      out = fenceUntrusted(out);
    }
    return out;
  }
  if (Array.isArray(value)) {
    return value.map((v) => walk(v, opts, key));
  }
  if (typeof value === "object") {
    const src = value;
    const out = {};
    for (const [k, v] of Object.entries(src)) {
      out[k] = walk(v, opts, k);
    }
    addNprDisplayFields(src, out);
    return out;
  }
  return value;
}
function addNprDisplayFields(src, out) {
  const currency = typeof src.currency === "string" && src.currency.length > 0 ? src.currency.toUpperCase() : "NPR";
  for (const [k, v] of Object.entries(src)) {
    if (!PAISA_FIELDS.has(k)) continue;
    if (typeof v !== "number" || !Number.isFinite(v)) continue;
    const base = stripPaisaSuffix(k);
    const nprKey = `${base}_npr`;
    const displayKey = `${base}_display`;
    if (!(nprKey in out)) out[nprKey] = (v / 100).toFixed(2);
    if (!(displayKey in out)) out[displayKey] = `${currency} ${(v / 100).toFixed(2)}`;
  }
}
function stripPaisaSuffix(k) {
  return k.replace(/_paisa$/i, "").replace(/Paisa$/, "");
}
function snake(s) {
  return s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`).replace(/^_/, "");
}

// ../mcp-core/src/dispatch.ts
import { createHash } from "crypto";
var AUDIT_PATH = "/v1/internal/mcp-audit";
async function dispatchTool(def, args, ctx) {
  const startedAt = Date.now();
  const argsHash = hashArgs(args);
  let result;
  try {
    result = await def.handler(args, ctx);
  } catch (err) {
    void emitAudit(ctx, {
      tool: def.name,
      elapsed_ms: Date.now() - startedAt,
      result: "error",
      args_hash: argsHash,
      error_code: errorCode(err)
    });
    throw err;
  }
  void emitAudit(ctx, {
    tool: def.name,
    elapsed_ms: Date.now() - startedAt,
    result: "ok",
    args_hash: argsHash
  });
  return result;
}
async function emitAudit(ctx, payload) {
  try {
    await ctx.api.post(AUDIT_PATH, {
      body: payload
    });
  } catch {
  }
}
function hashArgs(args) {
  const normalized = JSON.stringify(normalize(args));
  return createHash("sha256").update(normalized).digest("hex");
}
function normalize(v) {
  if (v === null || v === void 0) return null;
  if (Array.isArray(v)) return v.map(normalize);
  if (typeof v === "object") {
    const sorted = {};
    for (const k of Object.keys(v).sort()) {
      const val = v[k];
      if (val !== void 0) sorted[k] = normalize(val);
    }
    return sorted;
  }
  return v;
}
function errorCode(err) {
  if (err instanceof ScopeError) return "missing_scope";
  if (err instanceof McpToolError) return err.code;
  return "tool_error";
}

// ../mcp-core/src/elicit.ts
async function confirmDestructive(elicit, req) {
  if (!elicit) {
    throw new McpToolError(
      "elicitation_unsupported",
      "This tool requires a client that supports MCP elicitation. Please upgrade your client, or perform this action in the PayBridgeNP dashboard at https://dashboard.paybridgenp.com.",
      400
    );
  }
  const properties = {};
  const required = ["confirm"];
  if (req.summary) {
    for (const [k, v] of Object.entries(req.summary)) {
      if (v == null) continue;
      properties[k] = {
        type: typeof v === "number" ? "number" : "string",
        title: humanise(k),
        default: v,
        description: "Read-only \u2014 confirms what will happen."
      };
    }
  }
  properties.confirm = {
    type: "boolean",
    title: "I confirm this action",
    description: "Set to true to proceed."
  };
  const result = await elicit({
    message: req.message,
    schema: {
      type: "object",
      properties,
      required
    }
  });
  if (result.action !== "accept") return false;
  return result.content?.confirm === true;
}
function humanise(snake2) {
  return snake2.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

// ../mcp-core/src/version.ts
var MCP_CORE_VERSION = "0.1.0";

// ../mcp-core/src/tools/_helpers.ts
var DEFAULT_LIMIT = 25;
var MAX_LIMIT = 100;
function encodeCursor(c) {
  return Buffer.from(JSON.stringify(c), "utf8").toString("base64url");
}
function decodeCursor(cursor) {
  if (cursor == null || cursor === "") return { offset: 0 };
  if (typeof cursor !== "string") {
    throw new Error("cursor must be a string");
  }
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    if (typeof parsed.offset !== "number" || parsed.offset < 0) {
      throw new Error("invalid cursor");
    }
    return parsed;
  } catch {
    throw new Error("cursor is malformed");
  }
}
function clampLimit(raw) {
  const n = typeof raw === "number" ? raw : Number.parseInt(String(raw ?? ""), 10);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(MAX_LIMIT, Math.floor(n));
}
function paginate(raw, limit, offset) {
  const total = Number(raw.meta?.total ?? raw.data.length);
  const consumed = offset + raw.data.length;
  const next = consumed < total ? encodeCursor({ offset: consumed }) : null;
  return { items: raw.data, next_cursor: next, total };
}
var cursorAndLimitSchema = {
  type: "object",
  properties: {
    cursor: {
      type: "string",
      description: "Opaque pagination token from a previous response. Omit on the first call."
    },
    limit: {
      type: "integer",
      minimum: 1,
      maximum: MAX_LIMIT,
      default: DEFAULT_LIMIT,
      description: `Maximum items to return (1\u2013${MAX_LIMIT}, default ${DEFAULT_LIMIT}).`
    }
  },
  additionalProperties: false
};
function idOnlySchema(name, description) {
  return {
    type: "object",
    properties: {
      [name]: { type: "string", description }
    },
    required: [name],
    additionalProperties: false
  };
}

// ../mcp-core/src/tools/payments.ts
var ELICIT_THRESHOLD_PAISA = 5e5;
var list_payments = {
  name: "list_payments",
  description: "List payments for the API key's project. Most recent first. Use cursor to page. Each payment has id, amount (paisa), currency, provider, status, customer info, and timestamps.",
  inputSchema: cursorAndLimitSchema,
  annotations: { readOnlyHint: true, title: "List payments" },
  requiredScopes: ["payments:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/payments", {
      query: { limit, offset }
    });
    return paginate(raw, limit, offset);
  }
};
var get_payment = {
  name: "get_payment",
  description: "Fetch a single payment by id. Returns full payment record including provider reference, amount, status, customer details, and metadata.",
  inputSchema: idOnlySchema("payment_id", "PayBridgeNP payment id (e.g., pay_abc123)."),
  annotations: { readOnlyHint: true, title: "Get payment" },
  requiredScopes: ["payments:read"],
  async handler(args, ctx) {
    const { payment_id } = args;
    if (!payment_id) throw new Error("payment_id is required");
    return ctx.api.get(`/v1/payments/${encodeURIComponent(payment_id)}`);
  }
};
var create_checkout_session = {
  name: "create_checkout_session",
  description: "Create a hosted checkout session and return its checkout_url. Amount is in PAISA (e.g., 50000 = Rs 500). Customer is redirected to PayBridge to pick eSewa/Khalti/ConnectIPS and pay. Asks for confirmation when amount is large (default >= Rs 5,000).",
  inputSchema: {
    type: "object",
    properties: {
      amount: {
        type: "integer",
        minimum: 1,
        description: "Amount in paisa (1/100 of NPR)."
      },
      currency: {
        type: "string",
        default: "NPR",
        description: "ISO currency code. Currently only NPR is supported."
      },
      provider: {
        type: "string",
        enum: ["esewa", "khalti", "connectips"],
        description: "Lock the session to a single provider. Omit to let the customer pick."
      },
      return_url: {
        type: "string",
        format: "uri",
        description: "Where the customer is redirected after a successful payment."
      },
      cancel_url: {
        type: "string",
        format: "uri",
        description: "Where the customer is redirected if they cancel."
      },
      description: {
        type: "string",
        description: "Short description of what is being purchased (shown on the hosted page)."
      },
      customer: {
        type: "object",
        description: "Optional customer details to pre-fill on the hosted page.",
        properties: {
          name: { type: "string" },
          email: { type: "string", format: "email" },
          phone: { type: "string" }
        },
        additionalProperties: false
      },
      metadata: {
        type: "object",
        description: "Free-form key/value pairs returned in the webhook + visible in the dashboard.",
        additionalProperties: true
      },
      idempotency_key: {
        type: "string",
        description: "Optional Idempotency-Key \u2014 safe-retry the same operation without creating duplicates."
      }
    },
    required: ["amount", "return_url", "cancel_url"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, idempotentHint: true, title: "Create checkout session" },
  requiredScopes: ["payments:write"],
  async handler(args, ctx) {
    const a = args;
    if (!Number.isInteger(a.amount) || a.amount <= 0) {
      throw new McpToolError("invalid_request", "amount must be a positive integer (paisa)", 400);
    }
    if (a.amount >= ELICIT_THRESHOLD_PAISA) {
      const ok = await confirmDestructive(ctx.elicit, {
        message: `Create a checkout session for ${a.currency ?? "NPR"} ${(a.amount / 100).toFixed(2)}?`,
        summary: {
          amount: `${a.currency ?? "NPR"} ${(a.amount / 100).toFixed(2)}`,
          provider: a.provider ?? "(customer picks)",
          customer: a.customer?.email ?? a.customer?.name ?? "(none)",
          description: a.description ?? "(none)"
        }
      });
      if (!ok) {
        throw new McpToolError("user_cancelled", "Checkout session cancelled by user.", 0);
      }
    }
    return ctx.api.post("/v1/checkout", {
      body: {
        amount: a.amount,
        currency: a.currency ?? "NPR",
        provider: a.provider,
        returnUrl: a.return_url,
        cancelUrl: a.cancel_url,
        description: a.description,
        customer: a.customer,
        metadata: a.metadata
      },
      idempotencyKey: a.idempotency_key
    });
  }
};

// ../mcp-core/src/tools/refunds.ts
var list_refunds = {
  name: "list_refunds",
  description: "List refunds for the API key's project. Most recent first. Use cursor to page.",
  inputSchema: cursorAndLimitSchema,
  annotations: { readOnlyHint: true, title: "List refunds" },
  requiredScopes: ["refunds:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/refunds", { query: { limit, offset } });
    return paginate(raw, limit, offset);
  }
};
var get_refund = {
  name: "get_refund",
  description: "Fetch a single refund by id. Returns the refund's amount, status, reason, notes, and the underlying payment id.",
  inputSchema: idOnlySchema("refund_id", "PayBridgeNP refund id (e.g., rfd_abc123)."),
  annotations: { readOnlyHint: true, title: "Get refund" },
  requiredScopes: ["refunds:read"],
  async handler(args, ctx) {
    const { refund_id } = args;
    if (!refund_id) throw new Error("refund_id is required");
    return ctx.api.get(`/v1/refunds/${encodeURIComponent(refund_id)}`);
  }
};
var REFUND_REASONS = ["customer_request", "duplicate", "fraudulent", "other"];
var create_refund = {
  name: "create_refund",
  description: "Issue a refund against a successful payment. Amount is in PAISA (e.g., 50000 = Rs 500). Pass amount to refund a partial amount; omit to refund the full payment. Always asks the user to confirm before executing.",
  inputSchema: {
    type: "object",
    properties: {
      payment_id: {
        type: "string",
        description: "PayBridgeNP payment id to refund (must be a successful payment)."
      },
      amount: {
        type: "integer",
        minimum: 1,
        description: "Refund amount in paisa (1/100 of NPR). Omit to refund the full payment amount."
      },
      reason: {
        type: "string",
        enum: REFUND_REASONS,
        description: "Why the refund is being issued."
      },
      notes: {
        type: "string",
        description: "Optional internal note for the merchant's records."
      }
    },
    required: ["payment_id", "reason"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Issue refund" },
  requiredScopes: ["refunds:write"],
  async handler(args, ctx) {
    const a = args;
    if (!a.payment_id) throw new Error("payment_id is required");
    if (!REFUND_REASONS.includes(a.reason)) {
      throw new Error(`reason must be one of: ${REFUND_REASONS.join(", ")}`);
    }
    const payment = await ctx.api.get(
      `/v1/payments/${encodeURIComponent(a.payment_id)}`
    ).catch(() => null);
    if (!payment) {
      throw new McpToolError("not_found", `Payment ${a.payment_id} not found`, 404);
    }
    const refundAmount = a.amount ?? payment.amount;
    if (refundAmount > payment.amount) {
      throw new McpToolError(
        "invalid_request",
        `Refund amount ${refundAmount} exceeds payment amount ${payment.amount}`,
        400
      );
    }
    const ok = await confirmDestructive(ctx.elicit, {
      message: `Issue a ${refundAmount === payment.amount ? "FULL" : "PARTIAL"} refund of ${formatPaisa(refundAmount, payment.currency)} on payment ${payment.id}?`,
      summary: {
        payment_id: payment.id,
        refund_amount: formatPaisa(refundAmount, payment.currency),
        original_amount: formatPaisa(payment.amount, payment.currency),
        customer: payment.customerEmail ?? "(unknown)",
        provider: payment.provider ?? "(unknown)",
        reason: a.reason
      }
    });
    if (!ok) {
      throw new McpToolError("user_cancelled", "Refund cancelled by user.", 0);
    }
    return ctx.api.post("/v1/refunds", {
      body: {
        paymentId: a.payment_id,
        amount: refundAmount,
        reason: a.reason,
        notes: a.notes
      }
    });
  }
};
function formatPaisa(amount, currency) {
  const major = (amount / 100).toFixed(2);
  return `${currency} ${major}`;
}

// ../mcp-core/src/tools/webhooks.ts
var KNOWN_WEBHOOK_EVENTS = [
  "payment.succeeded",
  "payment.failed",
  "payment.refunded",
  "payment_link.paid",
  "subscription.created",
  "subscription.cancelled",
  "subscription.paused",
  "subscription.resumed",
  "invoice.created",
  "invoice.paid",
  "invoice.overdue"
];
var list_webhook_endpoints = {
  name: "list_webhook_endpoints",
  description: "List webhook endpoints registered on the API key's project. Returns each endpoint's id, url, subscribed events, and enabled status. Signing secrets are never returned here \u2014 they are shown only at endpoint creation.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
  annotations: { readOnlyHint: true, title: "List webhook endpoints" },
  requiredScopes: ["webhooks:read"],
  async handler(_args, ctx) {
    const raw = await ctx.api.get("/v1/webhooks");
    return raw;
  }
};
var create_webhook_endpoint = {
  name: "create_webhook_endpoint",
  description: "Register a new webhook endpoint. The signing_secret is returned ONCE here and never again \u2014 show it to the user immediately so they can store it for HMAC verification. URL must be HTTPS and publicly reachable (private IPs are rejected server-side).",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        format: "uri",
        description: "Public HTTPS URL where webhook events will POST."
      },
      events: {
        type: "array",
        items: { type: "string", enum: [...KNOWN_WEBHOOK_EVENTS] },
        minItems: 1,
        description: "Event types to subscribe to."
      }
    },
    required: ["url", "events"],
    additionalProperties: false
  },
  annotations: { idempotentHint: false, title: "Create webhook endpoint" },
  requiredScopes: ["webhooks:write"],
  async handler(args, ctx) {
    const a = args;
    if (!a.url?.startsWith("https://")) {
      throw new McpToolError("invalid_request", "url must be HTTPS", 400);
    }
    if (!Array.isArray(a.events) || a.events.length === 0) {
      throw new McpToolError("invalid_request", "events must be a non-empty array", 400);
    }
    return ctx.api.post("/v1/webhooks", { body: { url: a.url, events: a.events } });
  }
};
var update_webhook_endpoint = {
  name: "update_webhook_endpoint",
  description: "Update a webhook endpoint's URL or subscribed events.",
  inputSchema: {
    type: "object",
    properties: {
      endpoint_id: { type: "string", description: "Webhook endpoint id (e.g., whe_abc123)." },
      url: { type: "string", format: "uri", description: "New HTTPS URL." },
      events: {
        type: "array",
        items: { type: "string", enum: [...KNOWN_WEBHOOK_EVENTS] },
        description: "Replacement event subscription list."
      }
    },
    required: ["endpoint_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Update webhook endpoint" },
  requiredScopes: ["webhooks:write"],
  async handler(args, ctx) {
    const a = args;
    if (!a.endpoint_id) throw new Error("endpoint_id is required");
    const body = {};
    if (a.url !== void 0) body.url = a.url;
    if (a.events !== void 0) body.events = a.events;
    return ctx.api.patch(`/v1/webhooks/${encodeURIComponent(a.endpoint_id)}`, { body });
  }
};
var delete_webhook_endpoint = {
  name: "delete_webhook_endpoint",
  description: "Permanently delete a webhook endpoint. The endpoint will stop receiving events immediately. Asks the user to confirm before executing.",
  inputSchema: idOnlySchema("endpoint_id", "Webhook endpoint id (e.g., whe_abc123)."),
  annotations: { destructiveHint: true, title: "Delete webhook endpoint" },
  requiredScopes: ["webhooks:write"],
  async handler(args, ctx) {
    const { endpoint_id } = args;
    if (!endpoint_id) throw new Error("endpoint_id is required");
    const list = await ctx.api.get("/v1/webhooks");
    const target = list.data?.find((e) => e.id === endpoint_id);
    const ok = await confirmDestructive(ctx.elicit, {
      message: `Permanently delete webhook endpoint ${endpoint_id}?`,
      summary: {
        endpoint_id,
        url: target?.url ?? "(not found \u2014 confirm to delete anyway)"
      }
    });
    if (!ok) {
      throw new McpToolError("user_cancelled", "Delete cancelled by user.", 0);
    }
    return ctx.api.delete(`/v1/webhooks/${encodeURIComponent(endpoint_id)}`);
  }
};
var list_webhook_deliveries = {
  name: "list_webhook_deliveries",
  description: "List recent delivery attempts for a webhook endpoint. Each delivery has event type, status (pending/delivered/failed), HTTP response code, retry count, and timestamps. Use this to diagnose why a webhook didn't reach the merchant's server.",
  inputSchema: {
    type: "object",
    properties: {
      endpoint_id: {
        type: "string",
        description: "Webhook endpoint id (e.g., whe_abc123)."
      },
      cursor: cursorAndLimitSchema.properties.cursor,
      limit: cursorAndLimitSchema.properties.limit
    },
    required: ["endpoint_id"],
    additionalProperties: false
  },
  annotations: { readOnlyHint: true, title: "List webhook deliveries" },
  requiredScopes: ["webhooks:read"],
  async handler(args, ctx) {
    const a = args;
    if (!a.endpoint_id) throw new Error("endpoint_id is required");
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get(
      `/v1/webhooks/${encodeURIComponent(a.endpoint_id)}/deliveries`,
      { query: { limit, offset } }
    );
    return paginate(raw, limit, offset);
  }
};

// ../mcp-core/src/tools/billing.ts
var INTERVAL_UNITS = ["day", "week", "month", "quarter", "year"];
var list_plans = {
  name: "list_plans",
  description: "List subscription billing plans (recurring price configurations) for the merchant. Each plan has code, name, billing interval, amount in paisa, and trial days.",
  inputSchema: cursorAndLimitSchema,
  annotations: { readOnlyHint: true, title: "List billing plans" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/billing/plans", { query: { limit, offset } });
    return paginate(raw, limit, offset);
  }
};
var get_plan = {
  name: "get_plan",
  description: "Fetch a single billing plan by id.",
  inputSchema: idOnlySchema("plan_id", "Billing plan id (e.g., plan_abc123)."),
  annotations: { readOnlyHint: true, title: "Get billing plan" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const { plan_id } = args;
    if (!plan_id) throw new Error("plan_id is required");
    return ctx.api.get(`/v1/billing/plans/${encodeURIComponent(plan_id)}`);
  }
};
var list_customers = {
  name: "list_customers",
  description: "List billing customers (people the merchant bills repeatedly via subscriptions). Each customer has id, email, name, and phone.",
  inputSchema: cursorAndLimitSchema,
  annotations: { readOnlyHint: true, title: "List billing customers" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/billing/customers", { query: { limit, offset } });
    return paginate(raw, limit, offset);
  }
};
var get_customer = {
  name: "get_customer",
  description: "Fetch a single billing customer by id.",
  inputSchema: idOnlySchema("customer_id", "Billing customer id (e.g., bcus_abc123)."),
  annotations: { readOnlyHint: true, title: "Get billing customer" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const { customer_id } = args;
    if (!customer_id) throw new Error("customer_id is required");
    return ctx.api.get(`/v1/billing/customers/${encodeURIComponent(customer_id)}`);
  }
};
var list_subscriptions = {
  name: "list_subscriptions",
  description: "List subscriptions. Each subscription links a customer to a plan and tracks status (active, past_due, paused, cancelled, completed) plus current period.",
  inputSchema: cursorAndLimitSchema,
  annotations: { readOnlyHint: true, title: "List subscriptions" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/billing/subscriptions", { query: { limit, offset } });
    return paginate(raw, limit, offset);
  }
};
var get_subscription = {
  name: "get_subscription",
  description: "Fetch a single subscription by id including its current period and upcoming invoice date.",
  inputSchema: idOnlySchema("subscription_id", "Subscription id (e.g., sub_abc123)."),
  annotations: { readOnlyHint: true, title: "Get subscription" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const { subscription_id } = args;
    if (!subscription_id) throw new Error("subscription_id is required");
    return ctx.api.get(`/v1/billing/subscriptions/${encodeURIComponent(subscription_id)}`);
  }
};
var list_invoices = {
  name: "list_invoices",
  description: "List invoices generated by subscriptions. Each invoice has status (draft, open, paid, overdue, void, uncollectible), amount due, amount paid, and due date.",
  inputSchema: cursorAndLimitSchema,
  annotations: { readOnlyHint: true, title: "List invoices" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/billing/invoices", { query: { limit, offset } });
    return paginate(raw, limit, offset);
  }
};
var get_invoice = {
  name: "get_invoice",
  description: "Fetch a single invoice by id.",
  inputSchema: idOnlySchema("invoice_id", "Invoice id (e.g., inv_abc123)."),
  annotations: { readOnlyHint: true, title: "Get invoice" },
  requiredScopes: ["billing:read"],
  async handler(args, ctx) {
    const { invoice_id } = args;
    if (!invoice_id) throw new Error("invoice_id is required");
    return ctx.api.get(`/v1/billing/invoices/${encodeURIComponent(invoice_id)}`);
  }
};
var create_plan = {
  name: "create_plan",
  description: "Create a new subscription billing plan. Amount is in PAISA. code must be unique within the merchant \u2014 used by automation to reference the plan stably.",
  inputSchema: {
    type: "object",
    properties: {
      code: { type: "string", description: "Unique plan code (e.g., 'pro-monthly')." },
      name: { type: "string", description: "Display name." },
      description: { type: "string" },
      amount: { type: "integer", minimum: 0, description: "Amount per billing period in paisa." },
      currency: { type: "string", default: "NPR" },
      interval_unit: { type: "string", enum: [...INTERVAL_UNITS] },
      interval_count: { type: "integer", minimum: 1, default: 1 },
      trial_days: { type: "integer", minimum: 0, default: 0 }
    },
    required: ["code", "name", "amount", "interval_unit"],
    additionalProperties: false
  },
  annotations: { idempotentHint: false, title: "Create billing plan" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const a = args;
    return ctx.api.post("/v1/billing/plans", {
      body: {
        code: a.code,
        name: a.name,
        description: a.description,
        amount: a.amount,
        currency: a.currency ?? "NPR",
        intervalUnit: a.interval_unit,
        intervalCount: a.interval_count ?? 1,
        trialDays: a.trial_days ?? 0
      }
    });
  }
};
var update_plan = {
  name: "update_plan",
  description: "Update a billing plan's display name, description, or active state.",
  inputSchema: {
    type: "object",
    properties: {
      plan_id: { type: "string", description: "Plan id." },
      name: { type: "string" },
      description: { type: "string" },
      active: { type: "boolean" }
    },
    required: ["plan_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Update billing plan" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const { plan_id, ...rest } = args;
    if (!plan_id) throw new Error("plan_id is required");
    return ctx.api.patch(`/v1/billing/plans/${encodeURIComponent(plan_id)}`, { body: rest });
  }
};
var create_customer = {
  name: "create_customer",
  description: "Create a billing customer. Required for creating subscriptions.",
  inputSchema: {
    type: "object",
    properties: {
      email: { type: "string", format: "email" },
      name: { type: "string" },
      phone: { type: "string" }
    },
    required: ["email"],
    additionalProperties: false
  },
  annotations: { idempotentHint: false, title: "Create billing customer" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    return ctx.api.post("/v1/billing/customers", { body: args });
  }
};
var update_customer = {
  name: "update_customer",
  description: "Update a billing customer's name, email, or phone.",
  inputSchema: {
    type: "object",
    properties: {
      customer_id: { type: "string" },
      email: { type: "string", format: "email" },
      name: { type: "string" },
      phone: { type: "string" }
    },
    required: ["customer_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Update billing customer" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const { customer_id, ...rest } = args;
    if (!customer_id) throw new Error("customer_id is required");
    return ctx.api.patch(`/v1/billing/customers/${encodeURIComponent(customer_id)}`, { body: rest });
  }
};
var create_subscription = {
  name: "create_subscription",
  description: "Subscribe a customer to a plan. The first invoice generates immediately (or after the plan's trial period if set).",
  inputSchema: {
    type: "object",
    properties: {
      customer_id: { type: "string" },
      plan_id: { type: "string" },
      start_date: { type: "string", format: "date-time", description: "Optional ISO timestamp; defaults to now." }
    },
    required: ["customer_id", "plan_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, idempotentHint: false, title: "Create subscription" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const a = args;
    return ctx.api.post("/v1/billing/subscriptions", {
      body: { customerId: a.customer_id, planId: a.plan_id, startDate: a.start_date }
    });
  }
};
var pause_subscription = {
  name: "pause_subscription",
  description: "Pause a subscription. No new invoices generate while paused.",
  inputSchema: {
    type: "object",
    properties: {
      subscription_id: { type: "string" },
      reason: { type: "string" }
    },
    required: ["subscription_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Pause subscription" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const a = args;
    return ctx.api.post(`/v1/billing/subscriptions/${encodeURIComponent(a.subscription_id)}/pause`, {
      body: { reason: a.reason }
    });
  }
};
var resume_subscription = {
  name: "resume_subscription",
  description: "Resume a paused subscription.",
  inputSchema: idOnlySchema("subscription_id", "Subscription id."),
  annotations: { destructiveHint: true, title: "Resume subscription" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const { subscription_id } = args;
    return ctx.api.post(`/v1/billing/subscriptions/${encodeURIComponent(subscription_id)}/resume`, { body: {} });
  }
};
var cancel_subscription = {
  name: "cancel_subscription",
  description: "Cancel a subscription. Asks the user to confirm before executing. By default cancels at the end of the current period; set immediately=true to cancel now.",
  inputSchema: {
    type: "object",
    properties: {
      subscription_id: { type: "string" },
      immediately: { type: "boolean", default: false },
      reason: { type: "string" }
    },
    required: ["subscription_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Cancel subscription" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const a = args;
    if (!a.subscription_id) throw new Error("subscription_id is required");
    const ok = await confirmDestructive(ctx.elicit, {
      message: `Cancel subscription ${a.subscription_id}${a.immediately ? " IMMEDIATELY" : " at period end"}?`,
      summary: {
        subscription_id: a.subscription_id,
        when: a.immediately ? "immediately" : "at period end",
        reason: a.reason ?? "(none)"
      }
    });
    if (!ok) {
      throw new McpToolError("user_cancelled", "Cancellation rejected by user.", 0);
    }
    return ctx.api.post(`/v1/billing/subscriptions/${encodeURIComponent(a.subscription_id)}/cancel`, {
      body: { atPeriodEnd: !a.immediately, reason: a.reason }
    });
  }
};
var change_subscription_plan = {
  name: "change_subscription_plan",
  description: "Switch a subscription to a different plan. The new amount applies from the next billing period unless the plan API supports immediate proration.",
  inputSchema: {
    type: "object",
    properties: {
      subscription_id: { type: "string" },
      plan_id: { type: "string", description: "New plan id to switch to." }
    },
    required: ["subscription_id", "plan_id"],
    additionalProperties: false
  },
  annotations: { destructiveHint: true, title: "Change subscription plan" },
  requiredScopes: ["billing:write"],
  async handler(args, ctx) {
    const a = args;
    return ctx.api.post(
      `/v1/billing/subscriptions/${encodeURIComponent(a.subscription_id)}/change-plan`,
      { body: { planId: a.plan_id } }
    );
  }
};

// ../mcp-core/src/tools/sessions.ts
var list_checkout_sessions = {
  name: "list_checkout_sessions",
  description: "List checkout sessions for the API key's project. A session represents a customer's attempt at paying via the hosted checkout page. Each session has status (pending / initiated / success / failed / expired), amount, customer, and timestamps. Use this to see in-flight or recently abandoned checkouts.",
  inputSchema: {
    type: "object",
    properties: {
      cursor: cursorAndLimitSchema.properties.cursor,
      limit: cursorAndLimitSchema.properties.limit,
      status: {
        type: "string",
        enum: ["pending", "initiated", "success", "failed", "expired"],
        description: "Optional status filter."
      }
    },
    additionalProperties: false
  },
  annotations: { readOnlyHint: true, title: "List checkout sessions" },
  requiredScopes: ["sessions:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/sessions", {
      query: { limit, offset, status: a.status }
    });
    return paginate(raw, limit, offset);
  }
};
var get_checkout_session = {
  name: "get_checkout_session",
  description: "Fetch a single checkout session by id.",
  inputSchema: idOnlySchema("session_id", "Checkout session id (e.g., cs_abc123)."),
  annotations: { readOnlyHint: true, title: "Get checkout session" },
  requiredScopes: ["sessions:read"],
  async handler(args, ctx) {
    const { session_id } = args;
    if (!session_id) throw new Error("session_id is required");
    return ctx.api.get(`/v1/sessions/${encodeURIComponent(session_id)}`);
  }
};

// ../mcp-core/src/tools/links.ts
var list_payment_links = {
  name: "list_payment_links",
  description: "List payment links for the API key's project. Payment links are shareable URLs (no code integration needed) that customers open to pay. Each link has title, amount or amount range, active state, used count, expiry.",
  inputSchema: {
    type: "object",
    properties: {
      cursor: cursorAndLimitSchema.properties.cursor,
      limit: cursorAndLimitSchema.properties.limit,
      active: {
        type: "boolean",
        description: "Filter by active=true (live, accepting payments) or active=false (paused/cancelled)."
      }
    },
    additionalProperties: false
  },
  annotations: { readOnlyHint: true, title: "List payment links" },
  requiredScopes: ["links:read"],
  async handler(args, ctx) {
    const a = args;
    const limit = clampLimit(a.limit);
    const { offset } = decodeCursor(a.cursor);
    const raw = await ctx.api.get("/v1/payment-links", {
      query: { limit, offset, active: a.active === void 0 ? void 0 : String(a.active) }
    });
    return paginate(raw, limit, offset);
  }
};
var get_payment_link = {
  name: "get_payment_link",
  description: "Fetch a single payment link by id, including its usage stats (views, used_count, conversion_rate).",
  inputSchema: idOnlySchema("link_id", "Payment link id (e.g., lnk_abc123)."),
  annotations: { readOnlyHint: true, title: "Get payment link" },
  requiredScopes: ["links:read"],
  async handler(args, ctx) {
    const { link_id } = args;
    if (!link_id) throw new Error("link_id is required");
    return ctx.api.get(`/v1/payment-links/${encodeURIComponent(link_id)}`);
  }
};

// ../mcp-core/src/tools/analytics.ts
var get_analytics_overview = {
  name: "get_analytics_overview",
  description: "Headline KPIs for the project over a rolling window (default 30 days, max 90). Returns: total payment count, success / failed counts, success rate, success volume in paisa, checkout funnel (sessions created \u2192 initiated \u2192 paid), per-provider breakdown.",
  inputSchema: {
    type: "object",
    properties: {
      days: {
        type: "integer",
        minimum: 1,
        maximum: 90,
        default: 30,
        description: "Rolling window in days (1\u201390)."
      }
    },
    additionalProperties: false
  },
  annotations: { readOnlyHint: true, title: "Analytics overview" },
  requiredScopes: ["analytics:read"],
  async handler(args, ctx) {
    const a = args;
    return ctx.api.get("/v1/analytics/overview", { query: { days: a.days } });
  }
};

// ../mcp-core/src/tools/account.ts
var get_account = {
  name: "get_account",
  description: "Get info about the merchant account, project, and API key the assistant is currently authenticated as. Useful at the start of a session so the agent knows whose account it's operating on, and what scopes / spend cap / expiry are in effect.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
  annotations: { readOnlyHint: true, title: "Get account" },
  requiredScopes: ["account:read"],
  async handler(_args, ctx) {
    return ctx.api.get("/v1/account");
  }
};

// ../mcp-core/src/tools/index.ts
var READ_TOOLS = [
  get_account,
  list_payments,
  get_payment,
  list_refunds,
  get_refund,
  list_checkout_sessions,
  get_checkout_session,
  list_payment_links,
  get_payment_link,
  list_webhook_endpoints,
  list_webhook_deliveries,
  list_plans,
  get_plan,
  list_customers,
  get_customer,
  list_subscriptions,
  get_subscription,
  list_invoices,
  get_invoice,
  get_analytics_overview
];
var WRITE_TOOLS = [
  create_checkout_session,
  create_refund,
  create_webhook_endpoint,
  update_webhook_endpoint,
  delete_webhook_endpoint,
  create_plan,
  update_plan,
  create_customer,
  update_customer,
  create_subscription,
  pause_subscription,
  resume_subscription,
  cancel_subscription,
  change_subscription_plan
];
var TOOLS = [...READ_TOOLS, ...WRITE_TOOLS];
var TOOL_MAP = new Map(
  TOOLS.map((t) => [t.name, t])
);
function getTool(name) {
  return TOOL_MAP.get(name);
}

// src/index.ts
function readApiKey() {
  const fromEnv = process.env.PAYBRIDGE_API_KEY;
  if (fromEnv) return fromEnv;
  const flag = process.argv.find((a) => a.startsWith("--api-key="));
  if (flag) return flag.slice("--api-key=".length);
  throw new Error(
    "Missing PayBridgeNP API key. Set PAYBRIDGE_API_KEY in env or pass --api-key=sk_live_..."
  );
}
async function main() {
  const apiKey = readApiKey();
  const baseUrl = process.env.PAYBRIDGE_API_BASE_URL;
  const api = new ApiClient({ apiKey, baseUrl });
  const scope = { granted: null };
  const server = new Server(
    {
      name: "paybridge-np",
      version: MCP_CORE_VERSION
    },
    {
      capabilities: {
        tools: { listChanged: false },
        logging: {}
      }
    }
  );
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
      annotations: t.annotations
    }))
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const args = req.params.arguments ?? {};
    const tool = getTool(name);
    if (!tool) {
      return errorResult(`Unknown tool: ${name}`);
    }
    for (const required of tool.requiredScopes) {
      if (!hasScope(scope, required)) {
        return errorResult(`Missing required scope: ${required}`);
      }
    }
    const clientCaps = server.getClientCapabilities();
    const elicit = clientCaps?.elicitation ? async (req2) => {
      const r = await server.elicitInput({
        mode: "form",
        message: req2.message,
        requestedSchema: req2.schema
      });
      return r;
    } : void 0;
    const ctx = {
      api,
      scope,
      clientName,
      elicit
    };
    try {
      const raw = await dispatchTool(tool, args, ctx);
      const includePii = hasScope(scope, "pii:read");
      const safe = redactResponse(raw, { includePii });
      return {
        content: [{ type: "text", text: JSON.stringify(safe, null, 2) }]
      };
    } catch (err) {
      if (err instanceof ScopeError) {
        return errorResult(`Missing required scope: ${err.required}`);
      }
      if (err instanceof McpToolError) {
        return errorResult(`${err.code}: ${err.message}`);
      }
      return errorResult(`Tool ${name} failed: ${err.message}`);
    }
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
function errorResult(message) {
  return {
    isError: true,
    content: [{ type: "text", text: message }]
  };
}
main().catch((err) => {
  process.stderr.write(`[paybridge-mcp] fatal: ${err.message}
`);
  process.exit(1);
});
//# sourceMappingURL=index.js.map