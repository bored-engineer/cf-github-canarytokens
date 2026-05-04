import { env } from "cloudflare:workers";

// Determines if the given credential is a PAT
function isToken(credential: string): boolean {
  for (const prefix of ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]) {
    if (credential.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

// Determines if the given credential is a known SSH key
function isSSH(credential: string): boolean {
  for (const prefix of ["ssh-", "ecdsa-sha2-"]) {
    if (credential.startsWith(prefix) || credential.startsWith("sk-" + prefix)) {
      return true;
    }
  }
  return false;
}

// Converts a plaintext PAT to the 'hashed_token' format in GitHub audit logs
async function hashToken(token: string) : Promise<string> {
  const rawBytes = new TextEncoder().encode(token);
  const hashedBytes = await crypto.subtle.digest("SHA-256", rawBytes);
  return new Uint8Array(hashedBytes).toBase64({ omitPadding: false });
}

// Converts a SSH public key the 'hashed_token' format in GitHub audit logs
async function hashSSH(publicKey: string) : Promise<string> {
  // SSH public keys are "<type> <base64> [comment]" — we only need the base64 blob
  const rawBytes = Uint8Array.fromBase64(publicKey.trim().split(/\s+/)[1]);
  const hashedBytes = await crypto.subtle.digest("SHA-256", rawBytes);
  return new Uint8Array(hashedBytes).toBase64({ omitPadding: true });
}

// Parse the configured credentials as a Map(token, description)
const credentials = new Map<string, string>(Object.entries(JSON.parse(env.GITHUB_CREDENTIALS ?? "{}")));

// Convert the credentials into a Map(hashed_token, token) for use in audit log event lookups
const hashedCredentials = new Map<string, string>(await Promise.all(
  Array.from(credentials).map(async ([cred, _]): Promise<[string, string]> => {
    if (isToken(cred)) {
      return [await hashToken(cred), cred];
    } else if (isSSH(cred)) {
      return [await hashSSH(cred), cred];
    }
    return [cred, cred];
  })
));

// Helper to publish messages to Slack via Incoming Webhooks
async function postSlack(
  text: string,
  description: string,
  details: Map<string, string>,
  ...attachments: any[]
): Promise<void> {
  console.warn({
    message: `Posting message to Slack`,
    text: text,
    description: description,
    details: Object.fromEntries(details),
    attachments: attachments,
  })
  if (!env.SLACK_INCOMING_WEBHOOK_URL) return;
  const detailsFlat = Array.from(details).map(([key, value]) => `${key}: ${value}`).join("\n");
  const emojis = ":rotating_light:".repeat(3);
  const response = await fetch(env.SLACK_INCOMING_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "GitHub Canarytokens",
      icon_url: "https://a.slack-edge.com/80588/img/plugins/github/service_512.png",
      text: `<!channel>${emojis}${text}${emojis}\n${description.replace(/^/g, "> ")}\n${detailsFlat}`,
      attachments: attachments.map((attachment) => {
        return {
          fallback: JSON.stringify(attachment),
          color: "#ff0000",
          text: "```" + JSON.stringify(attachment, null, 2) + "```",
          mrkdwn_in: ["text"],
        }
      }),
    }),
  });
  if (!response.ok) {
    const body = await response.text();
    console.error({
      message: `Failed to send message to Slack: ${response.status} ${response.statusText}`,
      response: body,
    });
  }
}

// Helper to invoke the /rate_limit API and return the parsed 
async function fetchRateLimits(token: string) : Promise<Record<string, number>> {
  const response: Response = await fetch("https://api.github.com/rate_limit", {
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "https://github.com/bored-engineer/cf-github-canarytokens",
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub API returned ${response.status}: ${body}`);
  }
  const data: any = await response.json();
  let limits: Record<string, number> = {};
  for (const [resource, info] of Object.entries(data.resources)) {
    limits[resource] = (info as { used: number })["used"];
  }
  return limits;
}

// Exported functions for Cloudflare
export default {
  // cron entrypoint
  async scheduled(event: ScheduledController): Promise<void> {

    // Gather the raw tokens
    let hashedTokens = Array.from(
      hashedCredentials.entries().
        filter(([_, credential]) => isToken(credential)).
        map(([hashedToken, _]) => hashedToken)
    );
    if (!hashedTokens) return;

    // Fetch the previously seen rate limits for each PAT token from KV (if known)
    let previousLimits : Map<string, Record<string, number> | string | null> = await env.KV.get(hashedTokens, "json");

    // In parallel, loop over each configured credential
    await Promise.all(Array.from(previousLimits).map(async ([hashedToken, previousLimits]) => {
      const token = hashedCredentials.get(hashedToken)!;
      const description = credentials.get(token)!;

      // If the previous limits is a string ("revoked"), skip trying to fetch the limits for this token
      if (typeof previousLimits === "string") {
        return;
      }

      // Attempt to fetch the current rate-limits for the token
      const timeISO = new Date().toISOString();
      let limits;
      try {
        limits = await fetchRateLimits(token);
      } catch (err) {
        // If we get a 401, the token has been revoked
        if (err instanceof Error && err.message.includes("GitHub API returned 401") && err.message.includes("Bad credentials")) {
          // Update KV so we don't keep trying to poll this token
          await env.KV.put(hashedToken, "revoked");
          // Publish an alert to Slack
          let details = new Map<string, string>();
          details.set("Credential", `\`${hashedToken}\``);
          await postSlack(`GitHub Token Revoked Alert at \`${timeISO}\`, assume compromise!`, description, details);
        } else {
          console.error("failed to fetch /rate_limit for token", {
            hashed_token: hashedToken,
            description: description,
            error: err,
          });
        }
        return;
      }

      // If we had never seen this token before, just store the current limits and return
      if (!previousLimits) {
        await env.KV.put(hashedToken, JSON.stringify(limits));
        return;
      }

      // Loop over each resource in the rate limits, comparing the current values to the previous values.
      let modified = false;
      for (const [resource, current_used] of Object.entries(limits)) {
        let used = current_used - (previousLimits[resource] ?? 0);
        
        // 'code_scanning_upload' is just an alias for 'core', avoid duplicate alerts
        if (resource === "code_scanning_upload") continue;

        // If we went negative, that means the rate-limit reset, the used is just the return API value now
        // TODO: Technically if there's a reset and then the exact same amount of usage we would miss an alert
        // TODO: We could fix this with some complex logic comparing the 'reset' field as well
        if (used < 0) {
          used = current_used
        }

        // Don't alert if there's no usage
        if (used === 0) continue
        modified = true;

        // Publish an alert to Slack
        let details = new Map<string, string>();
        details.set("Credential", `\`${hashedToken}\``);
        details.set("API Resource", `\`${resource}\``);
        details.set("API Requests", String(used));
        await postSlack(`GitHub Rate Limit Alert at \`${timeISO}\`, assume compromise!`, description, details);
      }

      if (modified) {
        // Store the current limits in KV for next time
        await env.KV.put(hashedToken, JSON.stringify(limits));
      }
    }));
  },

  // http entrypoint
  async fetch(request: Request): Promise<Response> {
    // If we have a Splunk secret configured, ensure it matches the incoming Authorization header
    if (env.SPLUNK_TOKEN) {
      if (request.headers.get("Authorization") !== `Splunk ${env.SPLUNK_TOKEN}`) {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    // Parse the path from the incoming request URL
    const { pathname } = new URL(request.url);

    // If it's a health-check, just return a 200 OK
    if (pathname === "/services/collector/health" || pathname === "/services/collector/health/1.0") {
      return Response.json({
        text: "HEC is healthy",
        code: 17,
      });
    }

    // If it's anything other than a POST to the expected endpoint, return a 404
    if (request.method !== "POST" && pathname !== "/services/collector") {
      return new Response("Not found", { status: 404 });
    }

    // Parse the request body as text as it's multiple concatenated JSON documented, ex:
    // {"event":{...},"time":"123"}{"event":{...},"time":"456"}
    let body = await request.text();

    // Convert to valid JSON by wrapping in an [array] and injecting commas between events
    let bodyJSON = JSON.parse(`[` + body.replace(/}{"/g, `},{"`) + `]`);

    // Iterate over the parsed events
    for (const {time, event} of bodyJSON) {
      // Parse the Splunk time field
      const timeISO = new Date(parseFloat(time) * 1000).toISOString();

      // Log every event to the Cloudflare Worker console for debugging
      console.info({
        message: `parsed HEC Event`,
        time: timeISO,
        userAgent: request.headers.get('User-Agent'),
        sourceIP: request.headers.get('CF-Connecting-IP'),
        event: event,
      });

      // Lookup the token used to generate the event, if not found, ignore the event
      const credential = hashedCredentials.get(event.hashed_token);
      if (!credential) continue;
      const description = credentials.get(credential)!;

      // Build up as much context to inject into the message as possible
      let details = new Map<string, string>();
      details.set("Credential", `\`${event.hashed_token}\` - _${event.programmatic_access_type}_`);
      if (event.actor !== "deploy_key") {
        details.set("Owner", `<https://github.com/${event.actor}|${event.actor}>`);
      }
      details.set("Action", `\`${event.action}\``);
      if (event.action == "api.request") {
        details.set("URL", `${event.request_method} \`${event.url_path}${event.url_query ? "?" + event.url_query : ""}\``);
      }
      if (event.repo) {
        details.set("Repository", `<https://github.com/${event.repo}|${event.repo}>`);
      }
      if (event.org) {
        details.set("Organization", `<https://github.com/${event.org}|${event.org}>`);
      };
      if (event.actor_ip) {
        details.set("Source IP", `\`${event.actor_ip}\``);
      }
      if (event.user_agent) {
        details.set("User Agent", `\`${event.user_agent.replace(/`/g, "\\`")}\``);
      }

      // Send it off to Slack
      // TODO: Use ctx.waitUntil to write to Slack in the background?
      await postSlack(`GitHub Audit Log Alert at \`${timeISO}\`, assume compromise!`, description, details, event)
    }

    // Pretend we successfully ingested the event
    return Response.json({
      text: "Success",
      code: 0,
    });
  },
};