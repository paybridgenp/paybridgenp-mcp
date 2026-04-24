# @paybridge-np/mcp

Official [Model Context Protocol](https://modelcontextprotocol.io) server for [PayBridgeNP](https://paybridgenp.com), the Nepali payment gateway.

Lets Claude, ChatGPT, Cursor, Claude Code, VS Code — any MCP-compatible AI assistant — read and act on your PayBridgeNP account through natural language. Issue refunds, create payment links, manage subscriptions, inspect failed webhooks, pull KPIs — all by chatting.

**69 tools. 6 built-in prompt templates. Scoped tokens. Spend caps. Full audit trail.**

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

### Cursor

Same JSON in `.cursor/mcp.json` or via Settings → MCP.

### Claude Code

```bash
claude mcp add paybridge \
  --env PAYBRIDGE_API_KEY=sk_live_... \
  -- npx -y @paybridge-np/mcp@latest
```

### VS Code

`.vscode/mcp.json`:

```json
{
  "servers": {
    "paybridge": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@paybridge-np/mcp@latest"],
      "env": { "PAYBRIDGE_API_KEY": "sk_live_..." }
    }
  }
}
```

Generate a scoped MCP token from your [PayBridgeNP dashboard](https://dashboard.paybridgenp.com/mcp). Don't paste a full-access REST key.

## Tools (69)

### Read (31)

| Category | Tools |
|---|---|
| Account | `get_account` |
| Payments | `list_payments`, `get_payment` |
| Refunds | `list_refunds`, `get_refund` |
| Sessions | `list_checkout_sessions`, `get_checkout_session` |
| Payment Links | `list_payment_links`, `get_payment_link` |
| Webhooks | `list_webhook_endpoints`, `list_webhook_deliveries` |
| Plans | `list_plans`, `get_plan` |
| Customers | `list_customers`, `get_customer` |
| Subscriptions | `list_subscriptions`, `get_subscription` |
| Invoices | `list_invoices`, `get_invoice` |
| Coupons | `list_coupons`, `get_coupon` |
| Promotions | `list_promotion_codes`, `get_promotion_code`, `validate_promotion_code` |
| Tax | `get_tax_settings` |
| Dunning | `list_dunning_policies`, `get_dunning_invoice_status` |
| Usage | `preview_subscription_proration`, `get_subscription_usage_summary`, `list_usage_records` |
| Analytics | `get_analytics_overview` |

### Write (38)

Money-moving tools (`create_refund`, `cancel_subscription`, `delete_*`) require explicit confirmation in the host UI before executing.

| Category | Tools |
|---|---|
| Payments | `create_checkout_session` |
| Refunds | `create_refund` |
| Payment Links | `create_payment_link`, `update_payment_link`, `cancel_payment_link`, `delete_payment_link` |
| Webhooks | `create_webhook_endpoint`, `update_webhook_endpoint`, `delete_webhook_endpoint` |
| Plans | `create_plan`, `update_plan` |
| Customers | `create_customer`, `update_customer`, `add_customer_credit` |
| Subscriptions | `create_subscription`, `pause_subscription`, `resume_subscription`, `cancel_subscription`, `change_subscription_plan`, `end_trial`, `extend_trial` |
| Invoices | `create_invoice_item`, `delete_invoice_item` |
| Coupons | `create_coupon`, `deactivate_coupon` |
| Promotions | `create_promotion_code`, `deactivate_promotion_code`, `apply_coupon_to_subscription`, `remove_subscription_discount` |
| Tax | `update_tax_settings` |
| Dunning | `create_dunning_policy`, `update_dunning_policy`, `set_subscription_dunning_policy`, `stop_invoice_dunning`, `retry_invoice_dunning_now` |
| Usage | `report_subscription_usage`, `update_subscription_quantity` |

## Prompts

6 built-in prompt templates — appear as slash commands in Claude Desktop and Cursor (`/` → type `paybridge`):

| Prompt | What it does |
|---|---|
| `daily_summary` | End-of-day digest: revenue, payments, refunds, checkout funnel, webhook failures |
| `monthly_reconciliation` | Full month reconciliation table ready to share with your accountant. Takes optional `month` arg (e.g. `2026-04`) |
| `investigate_failed_payment` | Diagnose why payments failed — takes optional `payment_id` or `customer_email` |
| `onboard_customer` | Create a customer + subscribe to a plan in one flow. Takes `email`, `name`, `plan_id`, optional `coupon_code` |
| `review_dunning` | List all past-due invoices, categorize as retry/stop/wait, act with confirmation |
| `apply_discount` | Validate and apply a promo code to a subscription, showing before/after price first |

## Security

- **Scoped tokens** — 16 scopes grouped Read / Write / Sensitive. Read-only by default, writes opt-in per category. PII (email, phone) is its own scope.
- **Elicitation gates** — refunds and large checkout sessions require explicit confirmation in the host UI before executing.
- **24-hour spend cap** — hard rolling cap on refunds + checkout sessions per token. Auto-prefilled to Rs 50,000 on write tokens.
- **Per-token rate limits** — 60 calls/60s overall, 6 destructive/60s, 2 elicitation-gated/60s.
- **Prompt-injection defense** — customer-controlled fields wrapped as `<untrusted>` data. Zero-width characters stripped. Secrets pattern-redacted on output.
- **Full audit trail** — every tool call recorded with token id and assistant name, visible in `/dashboard/mcp`.
- **Open source** — audit exactly what runs against your key at [github.com/paybridgenp/paybridgenp-mcp](https://github.com/paybridgenp/paybridgenp-mcp).

## Configuration

| Env var | Required | Default |
|---|---|---|
| `PAYBRIDGE_API_KEY` | yes | — |
| `PAYBRIDGE_API_BASE_URL` | no | `https://api.paybridgenp.com` |

You can also pass `--api-key=sk_live_...` as a CLI argument.

## License

MIT — see `LICENSE`.
