# @paybridge-np/mcp

Official [Model Context Protocol](https://modelcontextprotocol.io) server for [PayBridgeNP](https://paybridgenp.com), the Nepali payment gateway.

Lets Claude, ChatGPT, Cursor, Claude Code, VS Code Copilot — any MCP-compatible AI assistant — read and act on your PayBridgeNP account through natural language. Refund payments, create payment links, inspect failed webhooks, pull weekly revenue, draft integration code — all without leaving your assistant.

## Install

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "paybridge": {
      "command": "npx",
      "args": ["-y", "@paybridge-np/mcp@latest"],
      "env": {
        "PAYBRIDGE_API_KEY": "sk_live_..."
      }
    }
  }
}
```

Restart Claude Desktop.

### Cursor / Claude Code / VS Code

Same JSON format, in each editor's MCP config UI. Generate a scoped MCP token from your [PayBridgeNP dashboard](https://dashboard.paybridgenp.com/mcp) — don't paste a full-access REST key.

## What it can do (V1)

Read-only tools that work today:

- `list_payments`, `get_payment` — search and inspect payments
- `list_refunds`, `get_refund` — refund history
- `list_checkout_sessions`, `get_checkout_session`
- `list_payment_links`, `get_payment_link`, `get_link_stats` — manage and inspect payment links
- `list_webhook_endpoints`, `list_webhook_deliveries` — inspect webhook delivery history
- `list_plans`, `list_customers`, `list_subscriptions`, `list_invoices` — billing surface
- `get_analytics_overview`, `get_funnel_analytics`, `get_health_analytics` — KPIs and operational health
- `search_paybridge` — free-text search across payments, refunds, links, customers
- `get_account` — your merchant info, plan, and project counts

Write tools (refund creation, payment-link management, etc.) ship in v0.2.

## Security

- **Scoped tokens.** Issue MCP-kind keys from the dashboard with read-only by default, write scopes opt-in per scope.
- **Spend caps.** Optional 24-hour Rs cap on destructive actions per token.
- **Confirmation prompts.** Money-moving tools (`create_refund`, large `create_checkout_session`) require explicit user confirmation in the host UI.
- **No secrets returned.** Webhook signing secrets are returned only at creation; provider credentials never.
- **Audit trail.** Every tool call is recorded against your merchant account and surfaced in `/dashboard/mcp`.
- **Open source.** Source for the server is at `github.com/paybridgenp/paybridgenp-mcp` so you can audit what runs against your key.

## Configuration

| Env var | Required | Default |
|---|---|---|
| `PAYBRIDGE_API_KEY` | yes | — |
| `PAYBRIDGE_API_BASE_URL` | no | `https://api.paybridgenp.com` |

You can also pass `--api-key=sk_live_...` as a CLI argument instead of setting the env var.

## License

MIT — see `LICENSE`.
