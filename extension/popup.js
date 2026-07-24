// CyberShield popup logic — stats display + per-user email for alerts

// ── Load scan stats (moved here from the old inline <script> — Chrome blocks inline JS) ──
chrome.storage.local.get("stats", (data) => {
  if (data.stats) {
    document.getElementById("scanned").textContent = data.stats.scanned || 0;
    document.getElementById("blocked").textContent = data.stats.blocked || 0;
  }
});

// ── Load & save the user's email for personalized threat alerts ──
const emailInput = document.getElementById("emailInput");
const saveBtn = document.getElementById("saveBtn");
const emailStatus = document.getElementById("emailStatus");

chrome.storage.sync.get(["cybershield_user_email"], (result) => {
  if (result.cybershield_user_email) {
    emailInput.value = result.cybershield_user_email;
  }
});

saveBtn.addEventListener("click", () => {
  const email = emailInput.value.trim();

  if (!email || !email.includes("@") || !email.includes(".")) {
    emailStatus.textContent = "⚠️ Please enter a valid email";
    emailStatus.className = "error";
    return;
  }

  chrome.storage.sync.set({ cybershield_user_email: email }, () => {
    emailStatus.textContent = "✅ Saved! Alerts will go here.";
    emailStatus.className = "saved";
    setTimeout(() => { emailStatus.textContent = ""; }, 2500);
  });
});