const OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const FEED_REFRESH_MS = 15 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 6500;

let feedCache = {
  fetchedAt: 0,
  entries: new Set(),
  hosts: new Set()
};

function normalizeUrl(url) {
  return String(url || "").trim();
}

function normalizeForExactMatch(url) {
  return normalizeUrl(url).replace(/\/+$/, "");
}

function parseHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_error) {
    return null;
  }
}

async function refreshFeedIfNeeded() {
  const now = Date.now();
  if (now - feedCache.fetchedAt < FEED_REFRESH_MS && feedCache.entries.size > 0) {
    return;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(OPENPHISH_FEED_URL, {
      method: "GET",
      signal: controller.signal,
      headers: {
        "User-Agent": "PhishSentry/1.0"
      }
    });

    if (!response.ok) {
      throw new Error(`OpenPhish HTTP ${response.status}`);
    }

    const text = await response.text();
    const entries = new Set();
    const hosts = new Set();

    for (const line of text.split(/\r?\n/)) {
      const value = normalizeUrl(line);
      if (!value || !/^https?:\/\//i.test(value)) {
        continue;
      }

      entries.add(normalizeForExactMatch(value));
      const host = parseHost(value);
      if (host) {
        hosts.add(host);
      }
    }

    feedCache = {
      fetchedAt: now,
      entries,
      hosts
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function lookupThreatIntel(urlInput) {
  const normalized = normalizeUrl(urlInput);
  const exact = normalizeForExactMatch(normalized);
  const host = parseHost(normalized);

  try {
    await refreshFeedIfNeeded();
  } catch (error) {
    return {
      provider: "openphish",
      status: "error",
      error: error?.message || "OpenPhish lookup failed"
    };
  }

  if (feedCache.entries.has(exact)) {
    return {
      provider: "openphish",
      status: "malicious",
      match_type: "exact_url",
      reference: OPENPHISH_FEED_URL
    };
  }

  if (host && feedCache.hosts.has(host)) {
    return {
      provider: "openphish",
      status: "malicious",
      match_type: "hostname",
      reference: OPENPHISH_FEED_URL
    };
  }

  return {
    provider: "openphish",
    status: "unknown",
    reference: OPENPHISH_FEED_URL
  };
}

module.exports = {
  lookupThreatIntel
};