const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]);
const BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "bank", "chase"];
const PHISHING_WORDS = ["verify", "password", "urgent", "suspend", "locked", "wallet", "signin", "login", "security-check"];

type ScanStatus = "Safe" | "Warning" | "Phishing";

export default async (req: Request) => {
  const url = new URL(req.url);

  if (url.pathname === "/scan/fast" || url.pathname === "/result") {
    return json(await scanUrlRequest(req));
  }

  if (url.pathname.startsWith("/scan/status/")) {
    const scanId = url.pathname.split("/").pop() || "netlify-preview";
    return json({
      done: true,
      success: false,
      scan_id: scanId,
      final_status: "Warning",
      error: "Sandbox screenshots are unavailable in this Netlify preview because the original Python Playwright sandbox is not running on Netlify Functions.",
      layers: {},
      forensics: {},
    });
  }

  if (url.pathname === "/api/scan_email") {
    return json(await scanEmail(req));
  }

  if (url.pathname === "/api/scan_qr") {
    return json(await scanQr(req));
  }

  if (url.pathname === "/scan-file") {
    return json(await scanFile(req));
  }

  if (url.pathname === "/rescan") {
    return Response.redirect(new URL("/", req.url), 302);
  }

  return json({ error: "Not found" }, 404);
};

export const config = {
  path: ["/scan/fast", "/scan/status/:scan_id", "/api/scan_email", "/api/scan_qr", "/scan-file", "/result", "/rescan"],
  preferStatic: true,
};

async function scanUrlRequest(req: Request) {
  const body = await readBody(req);
  const target = body.get("name") || body.get("url") || "";
  if (!target) {
    return { error: "No URL provided" };
  }

  const scan = analyzeUrl(String(target));
  const scanId = `netlify-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

  return {
    status: scan.status,
    is_safe: scan.status === "Safe",
    is_warning: scan.status === "Warning",
    url: scan.normalizedUrl,
    scan_id: scanId,
    preliminary: true,
    layers: scan.layers,
    forensics: scan.forensics,
  };
}

async function scanEmail(req: Request) {
  const body = await readBody(req);
  const emailText = String(body.get("email_text") || "");
  if (!emailText.trim()) {
    return { success: false, error: "No email content provided" };
  }

  const urls = extractUrls(emailText).map((value) => {
    const scan = analyzeUrl(value);
    return {
      url: scan.normalizedUrl,
      domain: scan.domain,
      status: scan.status === "Phishing" ? "phishing" : scan.status === "Warning" ? "suspicious" : "safe",
      mismatch: false,
      shortened: SHORTENERS.has(scan.domain),
    };
  });

  const lower = emailText.toLowerCase();
  const urgency = PHISHING_WORDS.filter((word) => lower.includes(word));
  const highRiskLinks = urls.filter((item) => item.status === "phishing").length;
  const suspiciousLinks = urls.filter((item) => item.status === "suspicious").length;
  const riskScore = clamp(urgency.length * 12 + highRiskLinks * 35 + suspiciousLinks * 18, 0, 100);
  const riskLevel = scoreToLevel(riskScore);

  return {
    success: true,
    risk_score: riskScore,
    risk_level: riskLevel,
    sender: parseSender(emailText),
    links: { urls },
    content: {
      urgency_indicators: urgency,
      threat_indicators: urgency.filter((word) => ["suspend", "locked", "urgent"].includes(word)),
      financial_indicators: lower.includes("bank") || lower.includes("wallet") ? ["financial request"] : [],
      prize_indicators: lower.includes("prize") || lower.includes("winner") ? ["prize language"] : [],
    },
    headers: {
      spf: { status: "not_available" },
      dkim: { status: "not_available" },
      dmarc: { status: "not_available" },
    },
    brand_claim: detectBrandClaim(emailText),
    explanation: buildExplanations(riskLevel, urls.length, urgency),
  };
}

async function scanQr(req: Request) {
  const body = await readBody(req);
  const content = String(body.get("qr_content") || "");
  if (!content.trim()) {
    return {
      success: false,
      error: "This Netlify preview can analyze decoded QR text. Camera/image QR decoding remains client-side or requires the original Python backend.",
      risk_score: 0,
      risk_level: "Safe",
    };
  }

  const scan = analyzeUrl(content);
  return {
    success: true,
    qr_content: content,
    content_type: content.startsWith("http") ? "URL" : "Text",
    risk_score: scan.riskScore,
    risk_level: scan.status,
    critical_flags: scan.reasons,
    recommendations: scan.status === "Safe" ? ["No obvious phishing indicators found."] : ["Do not open the destination until verified."],
  };
}

async function scanFile(req: Request) {
  const form = await req.formData();
  const file = form.get("file");
  if (!(file instanceof File)) {
    return { error: "No file provided" };
  }

  const text = await safeReadText(file);
  const urls = extractUrls(text);
  const urlScans = urls.map((item) => analyzeUrl(item));
  const highRisk = urlScans.filter((item) => item.status === "Phishing").length;
  const suspicious = urlScans.filter((item) => item.status === "Warning").length;
  const scripts = detectScripts(text);
  const macros = /\.(docm|xlsm)$/i.test(file.name);
  const riskScore = clamp(highRisk * 35 + suspicious * 18 + scripts.length * 15 + (macros ? 35 : 0), 0, 100);
  const riskLevel = scoreToLevel(riskScore);

  return {
    filename: file.name,
    file_type: file.type || extension(file.name).toUpperCase() || "Unknown",
    file_size: file.size,
    risk_score: riskScore,
    risk_level: riskLevel,
    summary: riskLevel === "Safe" ? "No obvious threats found in the deploy preview scan." : "Potentially risky content was detected.",
    urls_found: urlScans.map((item) => ({ url: item.normalizedUrl, risk: item.status === "Phishing" ? "high" : item.status === "Warning" ? "medium" : "none" })),
    url_analysis: {
      total_urls: urlScans.length,
      trusted_urls: urlScans.filter((item) => item.status === "Safe").length,
      suspicious_urls: suspicious,
      high_risk_urls: highRisk,
    },
    scripts_detected: scripts,
    macros_detected: macros,
    entropy_score: estimateEntropy(text),
    entropy_level: estimateEntropy(text) > 4.5 ? "High" : estimateEntropy(text) > 3.5 ? "Medium" : "Low",
    malware_scan: {
      status: riskLevel === "Phishing" ? "Suspicious" : "Clean",
      suspicious_signatures: scripts,
    },
  };
}

async function readBody(req: Request) {
  const contentType = req.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const payload = await req.json().catch(() => ({}));
    return new Map(Object.entries(payload).map(([key, value]) => [key, String(value ?? "")]));
  }
  const form = await req.formData();
  return new Map(Array.from(form.entries()).map(([key, value]) => [key, typeof value === "string" ? value : value.name]));
}

function analyzeUrl(input: string) {
  const normalizedUrl = normalizeUrl(input);
  let parsed: URL | null = null;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return scanResult(normalizedUrl, "", 65, ["Invalid URL format"]);
  }

  const domain = parsed.hostname.toLowerCase();
  const lowerUrl = normalizedUrl.toLowerCase();
  const reasons: string[] = [];
  let riskScore = 0;

  if (parsed.protocol !== "https:") addRisk("Missing HTTPS", 15);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) addRisk("Uses raw IP address", 30);
  if (SHORTENERS.has(domain)) addRisk("Uses URL shortener", 20);
  if ((domain.match(/-/g) || []).length >= 2) addRisk("Excessive hyphens in domain", 15);
  if (domain.length > 45) addRisk("Unusually long domain", 15);
  if (domain.includes("xn--")) addRisk("Punycode domain", 20);
  if (PHISHING_WORDS.some((word) => lowerUrl.includes(word))) addRisk("Sensitive-account wording", 20);

  const brand = BRANDS.find((item) => domain.includes(item) && !domain.endsWith(`${item}.com`));
  if (brand) addRisk(`Possible ${brand} impersonation`, 25);

  return scanResult(normalizedUrl, domain, riskScore, reasons);

  function addRisk(reason: string, score: number) {
    reasons.push(reason);
    riskScore += score;
  }
}

function scanResult(normalizedUrl: string, domain: string, riskScore: number, reasons: string[]) {
  const score = clamp(riskScore, 0, 100);
  const status = scoreToLevel(score);
  return {
    normalizedUrl,
    domain,
    riskScore: score,
    status,
    reasons,
    layers: {
      layer1: layer(status, reasons[0] || "No active blacklist match in preview scanner."),
      layer2: layer(status === "Phishing" ? "Warning" : status, reasons.join("; ") || "Domain structure looks normal."),
      layer3: layer(normalizedUrl.startsWith("https://") ? "Safe" : "Warning", normalizedUrl.startsWith("https://") ? "HTTPS URL provided." : "HTTPS was not present."),
      layer4: layer(status, `Preview heuristic score: ${score}/100.`),
      layer5: layer(status === "Safe" ? "Safe" : "Warning", reasons.length ? "Behavioral indicators need manual verification." : "No obvious behavioral indicators."),
    },
    forensics: {
      input_url: normalizedUrl,
      normalized_url: normalizedUrl,
      final_url: normalizedUrl,
      redirect_chain: [{ url: normalizedUrl, status: 200 }],
      redirect_count: 0,
      domain,
      root_domain: domain,
      ip_address: "Unavailable in Netlify preview",
      scan_time: new Date().toISOString(),
    },
  };
}

function layer(status: ScanStatus, message: string) {
  return { status, message, description: message };
}

function normalizeUrl(value: string) {
  const trimmed = value.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

function extractUrls(text: string) {
  return Array.from(new Set(text.match(/https?:\/\/[^\s"'<>]+/gi) || []));
}

function parseSender(text: string) {
  const match = text.match(/from:\s*([^<\s]+@[^>\s]+)/i) || text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  const email = match?.[1] || match?.[0] || "";
  const domain = email.includes("@") ? email.split("@").pop() || "" : "";
  return { email, domain, risk_level: domain ? "low" : "unknown", issues: [] };
}

function detectBrandClaim(text: string) {
  const lower = text.toLowerCase();
  const claimed = BRANDS.find((brand) => lower.includes(brand));
  if (!claimed) {
    return { is_impersonation: false };
  }
  const sender = parseSender(text).domain;
  return {
    is_impersonation: Boolean(sender && !sender.includes(claimed)),
    claimed_brand: claimed,
    sender_domain: sender || "unknown",
  };
}

function buildExplanations(level: ScanStatus, urlCount: number, urgency: string[]) {
  const explanations = [`${urlCount} URL(s) found in the email.`];
  if (urgency.length) explanations.push(`Urgency or credential language detected: ${urgency.join(", ")}.`);
  if (level === "Safe") explanations.push("No high-risk preview indicators were found.");
  return explanations;
}

function detectScripts(text: string) {
  const findings = [];
  if (/<script[\s>]/i.test(text)) findings.push("Embedded JavaScript");
  if (/powershell|cmd\.exe|wscript|eval\(/i.test(text)) findings.push("Suspicious execution keyword");
  return findings;
}

async function safeReadText(file: File) {
  if (file.size > 2_000_000) {
    return "";
  }
  try {
    return await file.text();
  } catch {
    return "";
  }
}

function estimateEntropy(text: string) {
  if (!text) return 0;
  const counts = new Map<string, number>();
  for (const char of text) counts.set(char, (counts.get(char) || 0) + 1);
  return Number(Array.from(counts.values()).reduce((sum, count) => {
    const p = count / text.length;
    return sum - p * Math.log2(p);
  }, 0).toFixed(2));
}

function extension(filename: string) {
  const index = filename.lastIndexOf(".");
  return index >= 0 ? filename.slice(index + 1) : "";
}

function scoreToLevel(score: number): ScanStatus {
  if (score >= 65) return "Phishing";
  if (score >= 25) return "Warning";
  return "Safe";
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function json(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
