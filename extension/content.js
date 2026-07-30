// CyberShield Content Script
// Runs on every webpage and intercepts link clicks

const API_URL = "http://localhost:8000/classify";

// Trusted domains — never block these
const WHITELIST = [
  "google.com", "youtube.com", "github.com",
  "stackoverflow.com", "wikipedia.org", "microsoft.com",
  "apple.com", "amazon.com", "facebook.com", "twitter.com",
  "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
  "geeksforgeeks.org", "w3schools.com", "mozilla.org",
  "python.org", "npmjs.com", "pypi.org", "docs.python.org",
  "medium.com", "dev.to", "kaggle.com", "coursera.org",
  "udemy.com", "edx.org", "khanacademy.org", "leetcode.com","whatsapp.com", "web.whatsapp.com",
  // Local dev — prevents CyberShield from scanning its own backend's
  // Swagger docs / API pages (e.g. 127.0.0.1:8000/docs), which would
  // otherwise get flagged as malware just for containing a raw IP.
  "localhost", "127.0.0.1"
];

function isTrusted(url) {
  try {
    const hostname = new URL(url).hostname.replace("www.", "");
    return WHITELIST.some(domain =>
      hostname === domain || hostname.endsWith("." + domain)
    );
  } catch { return false; }
}

// ── Load the user's saved email once, keep it in memory ──
let userEmail = null;
chrome.storage.sync.get(["cybershield_user_email"], (result) => {
  userEmail = result.cybershield_user_email || null;
});
// Keep it updated if the user changes it in the popup while browsing
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "sync" && changes.cybershield_user_email) {
    userEmail = changes.cybershield_user_email.newValue || null;
  }
});

// Intercept all link clicks
document.addEventListener("click", function(e) {
  const link = e.target.closest("a");
  if (!link || !link.href) return;

  const url = link.href;

  // Skip internal browser links
  if (url.startsWith("javascript:") ||
      url.startsWith("mailto:") ||
      url.startsWith("#") ||
      url === window.location.href) return;

  // Skip trusted domains
  if (isTrusted(url)) {
    window.location.href = url;
    return;
  }

  // Block the click while we check
  e.preventDefault();
  e.stopPropagation();

  // Show checking indicator
  showCheckingBadge(link);

  // Ask the background service worker to classify the URL.
  // (Must go through background.js — a content script cannot fetch()
  // an http:// URL from an https:// page; the browser blocks it.)
  chrome.runtime.sendMessage(
    { type: "CLASSIFY_URL", url: url, user_email: userEmail },
    (response) => {
      removeCheckingBadge();

      if (chrome.runtime.lastError || !response || !response.success) {
        console.warn("CyberShield classify failed:",
          chrome.runtime.lastError ? chrome.runtime.lastError.message : response && response.error);
        // If the API is unreachable, let the user proceed normally
        window.location.href = url;
        return;
      }

      const result = response.data;
      if (result.verdict === "SAFE") {
        window.location.href = url;
      } else {
        showWarningPage(url, result);
      }
    }
  );
}, true);

// ── Show a small "Checking..." badge near the link ──
function showCheckingBadge(link) {
  removeCheckingBadge();
  const badge = document.createElement("span");
  badge.id = "cybershield-checking";
  badge.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #1F4E79;
    color: white;
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 13px;
    font-family: Arial, sans-serif;
    z-index: 999999;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  `;
  badge.textContent = "🛡️ CyberShield checking...";
  document.body.appendChild(badge);
}

function removeCheckingBadge() {
  const badge = document.getElementById("cybershield-checking");
  if (badge) badge.remove();
}

// ── Show full warning page ──
function showWarningPage(url, result) {
  const verdictColor = result.verdict === "MALICIOUS" ? "#C00000" : "#C07000";

  const reasons = result.reasons
    .map(r => `<li style="margin:6px 0;">⚠️ ${r}</li>`)
    .join("");

  const warningHTML = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>CyberShield — Threat Detected</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: Arial, sans-serif;
          background: #0a0a0a;
          color: white;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
        }
        .card {
          background: #1a1a1a;
          border: 2px solid ${verdictColor};
          border-radius: 12px;
          padding: 40px;
          max-width: 600px;
          width: 100%;
          text-align: center;
          box-shadow: 0 0 40px ${verdictColor}44;
        }
        .shield { font-size: 64px; margin-bottom: 16px; }
        .verdict {
          font-size: 32px;
          font-weight: bold;
          color: ${verdictColor};
          margin-bottom: 8px;
          letter-spacing: 0.1em;
        }
        .confidence {
          font-size: 16px;
          color: #aaa;
          margin-bottom: 24px;
        }
        .url-box {
          background: #111;
          border: 1px solid #333;
          border-radius: 6px;
          padding: 12px 16px;
          font-size: 13px;
          color: #888;
          word-break: break-all;
          margin-bottom: 24px;
          text-align: left;
        }
        .reasons {
          background: #111;
          border: 1px solid ${verdictColor}44;
          border-radius: 6px;
          padding: 16px 20px;
          text-align: left;
          margin-bottom: 28px;
        }
        .reasons h3 {
          color: ${verdictColor};
          font-size: 14px;
          margin-bottom: 10px;
          letter-spacing: 0.08em;
        }
        .reasons ul {
          list-style: none;
          font-size: 14px;
          color: #ccc;
          padding: 0;
        }
        .buttons {
          display: flex;
          gap: 12px;
          justify-content: center;
          flex-wrap: wrap;
        }
        .btn-back {
          background: #2E75B6;
          color: white;
          border: none;
          padding: 12px 28px;
          border-radius: 6px;
          font-size: 15px;
          cursor: pointer;
          font-weight: bold;
        }
        .btn-proceed {
          background: transparent;
          color: #666;
          border: 1px solid #444;
          padding: 12px 28px;
          border-radius: 6px;
          font-size: 15px;
          cursor: pointer;
        }
        .btn-back:hover { background: #1F4E79; }
        .btn-proceed:hover { color: #999; border-color: #666; }
        .powered {
          margin-top: 24px;
          font-size: 11px;
          color: #444;
          letter-spacing: 0.1em;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="shield">🛡️</div>
        <div class="verdict">${result.verdict} DETECTED</div>
        <div class="confidence">
          AI Confidence: <strong style="color:${verdictColor}">
          ${result.confidence}%</strong>
        </div>
        <div class="url-box">
          <strong style="color:#555;font-size:11px;">BLOCKED URL:</strong><br>
          ${url}
        </div>
        <div class="reasons">
          <h3>WHY THIS WAS FLAGGED:</h3>
          <ul>${reasons}</ul>
        </div>
        <div class="buttons">
          <button class="btn-back" onclick="history.back()">
            ← Go Back to Safety
          </button>
          <button class="btn-proceed"
            onclick="window.location.href='${url}'">
            Proceed Anyway (Risky)
          </button>
        </div>
        <div class="powered">
          POWERED BY CYBERSHIELD AI • 95.41% ACCURACY
        </div>
      </div>
    </body>
    </html>
  `;

  // Replace current page with warning
  document.open();
  document.write(warningHTML);
  document.close();
}

// ── HOVER DETECTION (lives at top level — separate from the click handler) ──
let hoverTimer = null;
let hoverPopup = null;
let lastHoveredUrl = null;

document.addEventListener("mouseover", function(e) {
  const link = e.target.closest("a");
  if (!link || !link.href) return;

  // Ignore re-triggers from moving between child elements of the same link
  if (link.contains(e.relatedTarget)) return;

  const url = link.href;

  if (
    url.startsWith("javascript:") ||
    url.startsWith("mailto:") ||
    url.startsWith("#")
  ) {
    return;
  }

  clearTimeout(hoverTimer);
  hoverTimer = setTimeout(() => checkUrlOnHover(link, url), 400);
});

document.addEventListener("mouseout", function(e) {
  const link = e.target.closest("a");
  if (!link) return;

  // Ignore if we're still inside the same link (moving between its children)
  if (link.contains(e.relatedTarget)) return;

  clearTimeout(hoverTimer);
  removeHoverPopup();
});

function checkUrlOnHover(link, url) {
  if (url === lastHoveredUrl) return;
  lastHoveredUrl = url;

  // Same fix as the click handler: go through background.js instead of
  // fetching directly from the content script.
  chrome.runtime.sendMessage(
    { type: "CLASSIFY_URL", url: url, user_email: userEmail },
    (response) => {
      if (chrome.runtime.lastError) {
        console.warn("CyberShield hover check failed:", chrome.runtime.lastError.message);
        return;
      }
      if (!response || !response.success) {
        console.warn("CyberShield hover check failed:", response && response.error);
        return;
      }
      const result = response.data;
      if (result.verdict) {
        showHoverPopup(link, result);
      }
    }
  );
}

function showHoverPopup(link, result) {
  removeHoverPopup();

  const verdictColor = result.verdict === "MALICIOUS" ? "#C00000" : "#C07000";

  const rect = link.getBoundingClientRect();

  hoverPopup = document.createElement("div");
  hoverPopup.id = "cybershield-hover-popup";
  hoverPopup.style.cssText = `
    position: fixed;
    top: ${rect.bottom + 6}px;
    left: ${rect.left}px;
    background: #1a1a1a;
    color: white;
    border: 1px solid ${verdictColor};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
    font-family: Arial, sans-serif;
    z-index: 2147483647;
    max-width: 280px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.4);
    pointer-events: none;
  `;

  // Safe verdicts get a green check instead of a warning triangle
  const icon = result.verdict === "SAFE" ? "✅" : "⚠️";

  hoverPopup.innerHTML = `
    <strong style="color:${verdictColor};">${icon} ${result.verdict}</strong>
    <div style="color:#aaa; margin-top:2px;">
      Confidence: ${result.confidence}%
    </div>
  `;
  document.body.appendChild(hoverPopup);
}

function removeHoverPopup() {
  if (hoverPopup) {
    hoverPopup.remove();
    hoverPopup = null;
  }
  lastHoveredUrl = null;
}
// ── END HOVER DETECTION ──────────────────────────────────────