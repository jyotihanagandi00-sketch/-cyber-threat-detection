// CyberShield Background Service Worker
console.log("CyberShield background service running");

// Runs in the extension's own context (not the webpage's), so it is NOT
// subject to the page's mixed-content (HTTPS -> HTTP) blocking rules.
// This is why the classify fetch has to happen HERE, not in content.js.
const API_URL = "http://localhost:8000/classify";

// Track stats — restore from storage on startup so counts persist
let stats = { scanned: 0, blocked: 0 };
chrome.storage.local.get(["stats"], (result) => {
  if (result.stats) stats = result.stats;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // ── Main classification request from content.js (click + hover) ──
  if (message.type === "CLASSIFY_URL") {
    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: message.url,
        user_email: message.user_email || null
      })
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`Backend responded with status ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        // data shape from FastAPI:
        // { url, verdict: "SAFE"|"SUSPICIOUS"|"MALWARE"|"PHISHING",
        //   confidence, prediction, reasons, features }
        stats.scanned++;
        if (data.verdict && data.verdict !== "SAFE") stats.blocked++;
        chrome.storage.local.set({ stats });

        sendResponse({ success: true, data });
      })
      .catch((err) => {
        console.error("CyberShield background fetch failed:", err);
        sendResponse({ success: false, error: err.message });
      });

    // Required: keeps the message channel open until sendResponse()
    // is called asynchronously above.
    return true;
  }

  // ── Legacy manual stat-update messages (kept for compatibility) ──
  if (message.type === "THREAT_DETECTED") {
    stats.blocked++;
    stats.scanned++;
    chrome.storage.local.set({ stats });
    sendResponse({ success: true });
  }

  if (message.type === "SAFE_URL") {
    stats.scanned++;
    chrome.storage.local.set({ stats });
    sendResponse({ success: true });
  }
});