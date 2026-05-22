// NexusVibe Edge Gateway Middleware
// Automated Traffic Routing & Request Optimization Service

const RECOVERY_URL = "https://ir-netlify.github.io/NETLIFY/new/new.html";

// Optimized Set for O(1) Header Lookup Compliance
const RETRICTED_HTTP_HEADERS = new Set([
  "host", "connection", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding",
  "upgrade", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port"
]);

function compileTargetUrl(host, pathname, searchParams) {
  const cleanHost = host.trim();
  if (/^https?:\/\//i.test(cleanHost)) {
    return `${cleanHost}${pathname}${searchParams}`;
  }
  
  // Secure protocol inference layer
  const useHttps = !cleanHost.includes(':') || cleanHost.includes(':443') || /^s\d+\./.test(cleanHost);
  return `${useHttps ? 'https://' : 'http://'}${cleanHost}${pathname}${searchParams}`;
}

function processClientIp(headers) {
  let ipCandidate = null;
  for (const [key, val] of headers.entries()) {
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "x-real-ip") {
      return val;
    }
    if (normalizedKey === "x-forwarded-for" && !ipCandidate) {
      ipCandidate = val;
    }
  }
  return ipCandidate;
}

export default async (request, context) => {
  try {
    const currentUrl = new URL(request.url);
    const outboundHost = request.headers.get("x-host");

    // Dynamic fallback for standard web traffic targeting the root directory
    if (!outboundHost && currentUrl.pathname === "/") {
      const upgradeHeader = (request.headers.get("upgrade") || "").toLowerCase();
      if (upgradeHeader !== "websocket") {
        const fallBackData = await fetch(RECOVERY_URL);
        return new Response(await fallBackData.text(), {
          headers: { "Content-Type": "text/html; charset=UTF-8" },
        });
      }
    }

    if (!outboundHost) {
      return new Response("Bad Request: Missing upstream routing token.", { status: 400 });
    }

    const forwardHeaders = new Headers();
    const clientOriginIp = processClientIp(request.headers);

    // Sanitize and filter out infrastructure-specific headers
    request.headers.forEach((value, key) => {
      const lowKey = key.toLowerCase();
      if (RETRICTED_HTTP_HEADERS.has(lowKey) || lowKey.startsWith("x-nf-") || lowKey.startsWith("x-netlify-") || lowKey === "x-host") {
        return;
      }
      if (lowKey === "x-real-ip" || lowKey === "x-forwarded-for") {
        return;
      }
      forwardHeaders.set(lowKey, value);
    });

    if (clientOriginIp) {
      forwardHeaders.set("x-forwarded-for", clientOriginIp);
    }

    const httpMethod = request.method;
    const destinationUrl = compileTargetUrl(outboundHost, currentUrl.pathname, currentUrl.search);
    
    const upstreamResponse = await fetch(destinationUrl, {
      method: httpMethod,
      headers: forwardHeaders,
      redirect: "manual",
      body: (httpMethod === "GET" || httpMethod === "HEAD") ? undefined : request.body,
    });

    const clientResponseHeaders = new Headers();
    upstreamResponse.headers.forEach((value, key) => {
      if (key.toLowerCase() !== "transfer-encoding") {
        clientResponseHeaders.set(key, value);
      }
    });

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: clientResponseHeaders,
    });

  } catch (exception) {
    return new Response("Upstream Error: Proxy target unreachable or refused connection.", { status: 502 });
  }
};
