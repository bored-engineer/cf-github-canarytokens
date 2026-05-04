# cf-github-canarytokens
A Cloudflare Worker that monitors GitHub canarytokens (PATs and deploy keys) for unauthorized use and alerts via Slack.

<img width="2264" height="1224" alt="image" src="https://github.com/user-attachments/assets/90d3fb5a-7c11-451a-b5da-d103d39a4467" />

## Deploy

### 1. Create the KV namespace

```console
npx wrangler@latest kv namespace create cf-github-canarytokens
```

Copy the `id` from the output and update the `kv_namespaces` entry in [`wrangler.jsonc`](wrangler.jsonc):

```json
"kv_namespaces": [
  {
    "binding": "KV",
    "id": "<REPLACE ME>",
    "remote": true
  }
],
```

### 2. Set secrets

**`GITHUB_CREDENTIALS`** — a JSON object mapping each credential to a human-readable description, ex:
```json
{
  "github_pat_yourtoken": "Stored in `~/.netrc` on self-hosted `ubuntu` GitHub Actions runners",
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5M+BuaHbZTSfYkrkRUwagvfUTF4m5TW8YohzNdI58q": "Stored in `~/.ssh/id_ed25519` on self-hosted `ubuntu` GitHub Actions runners"
}
```

```console
npx wrangler@latest secret put GITHUB_CREDENTIALS
```

**`SLACK_INCOMING_WEBHOOK_URL`** — Slack [Incoming Webhook URL](https://slack.com/marketplace/A0F7XDUAZ-incoming-webhooks) for alerts.

```console
npx wrangler@latest secret put SLACK_INCOMING_WEBHOOK_URL
```

**`SPLUNK_TOKEN`** — token used to authenticate inbound audit log events on the HEC endpoint (omit to skip auth).

```console
npx wrangler@latest secret put SPLUNK_TOKEN
```

### 3. Deploy
```console
npx wrangler@latest deploy
```

The worker URL is printed at the end of deployment, e.g. `https://cf-github-canarytokens.<your-subdomain>.workers.dev`.

### 4. Configure GitHub audit log streaming

To receive real-time audit log events, set up [GitHub audit log streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise) to a **Splunk** destination:

| Field | Value |
|---|---|
| Server URL | `cf-github-canarytokens.<your-subdomain>.workers.dev:443` |
| Token | The value you set for `SPLUNK_TOKEN` |
| SSL verification | Enabled |

# Debugging
A local deployment which reads credentials from `.env` can be started via:
```console
npx wrangler@latest dev
```
GitHub audit event ingestion can be simulated via `curl`:
```console
curl http://localhost:8787/services/collector -d@sample.deploy_key_clone.json
curl http://localhost:8787/services/collector -d@sample.token_api_request.json
```
The cron handler can also be triggered via `curl`:
```console
curl http://localhost:8787/cdn-cgi/handler/scheduled
```
