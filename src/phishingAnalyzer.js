const PHISHING_KEYWORDS = [
  "verify",
  "password",
  "urgent",
  "suspended",
  "bank",
  "wallet",
  "reset",
  "security alert",
  "login",
  "confirm",
  "account",
  "2fa",
  "one-time code"
];

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "rebrand.ly"
]);

function clamp(value, min = 0, max = 1) {
  return Math.min(max, Math.max(min, value));
}

function toConfidence(riskScore) {
  // Confidence is stronger near extremes, weaker around midpoint.
  const distance = Math.abs(riskScore - 0.5);
  return clamp(0.55 + distance * 0.8);
}

function normalizeInput(text) {
  return String(text || "").trim();
}

function isIpHost(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function looksLikePunycode(hostname) {
  return hostname.includes("xn--");
}

function hasSuspiciousTld(hostname) {
  const suspiciousTlds = [".zip", ".top", ".click", ".gq", ".tk", ".ml", ".xyz"];
  return suspiciousTlds.some((tld) => hostname.endsWith(tld));
}

function countSubdomains(hostname) {
  if (!hostname) {
    return 0;
  }

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return 0;
  }

  return parts.length - 2;
}

function scoreUrl(urlInput) {
  const detected = [];
  let risk = 0.08;
  const url = normalizeInput(urlInput);

  let parsed;
  try {
    parsed = new URL(url);
  } catch (_error) {
    return {
      ok: false,
      error: "Please provide a valid URL (including http:// or https://)."
    };
  }

  const protocol = parsed.protocol;
  const hostname = parsed.hostname.toLowerCase();
  const hostAndPath = `${hostname}${parsed.pathname.toLowerCase()}`;

  if (protocol !== "https:") {
    risk += 0.22;
    detected.push("not_https");
  }

  if (isIpHost(hostname)) {
    risk += 0.28;
    detected.push("ip_address_host");
  }

  if (SHORTENER_DOMAINS.has(hostname)) {
    risk += 0.2;
    detected.push("shortened_url");
  }

  if (countSubdomains(hostname) >= 3) {
    risk += 0.14;
    detected.push("excessive_subdomains");
  }

  if (hasSuspiciousTld(hostname)) {
    risk += 0.17;
    detected.push("suspicious_tld");
  }

  if (looksLikePunycode(hostname)) {
    risk += 0.12;
    detected.push("punycode_domain");
  }

  if (url.length > 90) {
    risk += 0.12;
    detected.push("long_url");
  }

  if (/@/.test(url)) {
    risk += 0.2;
    detected.push("contains_at_symbol");
  }

  if (/[-_]{2,}/.test(hostname)) {
    risk += 0.08;
    detected.push("obfuscated_delimiters");
  }

  const keywordHits = PHISHING_KEYWORDS.filter((keyword) => hostAndPath.includes(keyword));
  if (keywordHits.length > 0) {
    risk += Math.min(0.3, keywordHits.length * 0.07);
    detected.push(...keywordHits.map((word) => `keyword:${word.replace(/\s+/g, "_")}`));
  }

  const riskScore = clamp(risk);
  return {
    ok: true,
    result: {
      is_phishing: riskScore >= 0.55,
      confidence: toConfidence(riskScore),
      risk_score: riskScore,
      analyzed_url: url,
      features_detected: detected
    }
  };
}

function scoreText(textInput) {
  const text = normalizeInput(textInput);
  const lowered = text.toLowerCase();
  const detectedKeywords = [];
  let risk = 0.05;

  for (const keyword of PHISHING_KEYWORDS) {
    if (lowered.includes(keyword)) {
      detectedKeywords.push(keyword);
    }
  }

  if (detectedKeywords.length > 0) {
    risk += Math.min(0.42, detectedKeywords.length * 0.08);
  }

  if (/\b(click here|act now|limited time|immediately|urgent action)\b/i.test(text)) {
    risk += 0.18;
    detectedKeywords.push("urgency_phrase");
  }

  if (/\b(ssn|social security|credit card|debit card|cvv|pin)\b/i.test(text)) {
    risk += 0.2;
    detectedKeywords.push("sensitive_data_request");
  }

  if (/https?:\/\//i.test(text) && /\b(login|verify|reset|account)\b/i.test(text)) {
    risk += 0.14;
    detectedKeywords.push("link_with_account_prompt");
  }

  if (/(\$|usd|bitcoin|btc|gift card)/i.test(text) && /\b(send|transfer|pay)\b/i.test(text)) {
    risk += 0.16;
    detectedKeywords.push("payment_pressure_pattern");
  }

  const riskScore = clamp(risk);
  return {
    is_phishing: riskScore >= 0.55,
    confidence: toConfidence(riskScore),
    risk_score: riskScore,
    analyzed_text: text.slice(0, 1500),
    detected_keywords: [...new Set(detectedKeywords)]
  };
}

module.exports = {
  scoreText,
  scoreUrl
};