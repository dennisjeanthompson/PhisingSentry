const express = require("express");
const path = require("path");
const { scoreText, scoreUrl } = require("./src/phishingAnalyzer");
const { lookupThreatIntel } = require("./src/threatIntel");

const app = express();
const PORT = process.env.PORT || 3000;
const staticDir = path.join(__dirname, "phishsentry_app", "frontend_dist");

app.disable("x-powered-by");
app.use(express.json({ limit: "500kb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "phishsentry-api",
    timestamp: new Date().toISOString()
  });
});

app.post("/api/analyze-url", async (req, res) => {
  const url = typeof req.body?.url === "string" ? req.body.url : "";
  if (!url.trim()) {
    return res.status(400).json({ error: "Request body must include a non-empty url string." });
  }

  const scored = scoreUrl(url);
  if (!scored.ok) {
    return res.status(400).json({ error: scored.error });
  }

  const intel = await lookupThreatIntel(url);
  const base = scored.result;
  const combinedFeatures = [...base.features_detected];

  let riskScore = base.risk_score;
  let confidence = base.confidence;
  let isPhishing = base.is_phishing;

  if (intel.status === "malicious") {
    riskScore = Math.max(riskScore, 0.98);
    confidence = Math.max(confidence, 0.99);
    isPhishing = true;
    combinedFeatures.push("threat_intel:openphish_match");
  }

  return res.json({
    ...base,
    is_phishing: isPhishing,
    confidence,
    risk_score: riskScore,
    features_detected: [...new Set(combinedFeatures)],
    threat_intel: intel
  });
});

app.post("/api/analyze-text", (req, res) => {
  const text = typeof req.body?.text === "string" ? req.body.text : "";
  if (!text.trim()) {
    return res.status(400).json({ error: "Request body must include a non-empty text string." });
  }

  return res.json(scoreText(text));
});

app.use(express.static(staticDir));

app.get("*", (_req, res) => {
  res.sendFile(path.join(staticDir, "index.html"));
});

app.use((err, _req, res, _next) => {
  console.error("Unhandled server error:", err);
  res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`PhishSentry running on http://localhost:${PORT}`);
});