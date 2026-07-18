// CyberShield Background Service Worker
console.log("CyberShield background service running");

// Track stats
let stats = { scanned: 0, blocked: 0 };

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "THREAT_DETECTED") {
    stats.blocked++;
    stats.scanned++;
    chrome.storage.local.set({ stats });
  }
  if (message.type === "SAFE_URL") {
    stats.scanned++;
    chrome.storage.local.set({ stats });
  }
  sendResponse({ success: true });
});