import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ── Config — loaded from environment variables (never hardcode secrets!) ──
# SENDER_EMAIL/SENDER_PASSWORD are your app's Gmail account that actually sends the mail.
# RECEIVER_EMAIL is the fallback/admin address used only if no per-user email is provided.
SENDER_EMAIL    = os.environ.get("CYBERSHIELD_SENDER_EMAIL")
SENDER_PASSWORD = os.environ.get("CYBERSHIELD_SENDER_PASSWORD")
RECEIVER_EMAIL  = os.environ.get("CYBERSHIELD_RECEIVER_EMAIL")


def send_threat_alert(url: str, verdict: str,
                      confidence: float, reasons: list,
                      recipient: str | None = None):
    # Use the per-user email if one was provided (from the extension), otherwise fall back
    to_email = recipient if recipient else RECEIVER_EMAIL

    if not SENDER_EMAIL or not SENDER_PASSWORD or not to_email:
        print("⚠️ Email alert skipped — missing sender credentials or recipient email.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 CyberShield Alert — {verdict} Detected!"
        msg["From"]    = SENDER_EMAIL
        msg["To"]      = to_email

        html = f"""
        <html><body style="font-family:Arial,sans-serif;
          background:#06090f;color:#c8dff4;padding:30px;">
          <div style="max-width:600px;margin:0 auto;
            background:#0a1220;border:1px solid #C00000;
            border-radius:12px;padding:30px;">
            <h1 style="color:#C00000;margin-bottom:8px;">
              🛡️ CYBERSHIELD THREAT ALERT
            </h1>
            <p style="color:#4a6580;font-size:12px;
              margin-bottom:24px;">
              {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
            <table style="width:100%;border-collapse:collapse;">
              <tr style="background:rgba(192,0,0,0.1);">
                <td style="padding:12px;color:#888;
                  font-size:12px;">VERDICT</td>
                <td style="padding:12px;color:#C00000;
                  font-weight:bold;font-size:18px;">{verdict}</td>
              </tr>
              <tr>
                <td style="padding:12px;color:#888;
                  font-size:12px;">CONFIDENCE</td>
                <td style="padding:12px;color:#ffaa00;
                  font-weight:bold;">{confidence}%</td>
              </tr>
              <tr style="background:rgba(255,255,255,0.02);">
                <td style="padding:12px;color:#888;
                  font-size:12px;">BLOCKED URL</td>
                <td style="padding:12px;color:#c8dff4;
                  word-break:break-all;font-size:12px;">{url}</td>
              </tr>
              <tr>
                <td style="padding:12px;color:#888;
                  font-size:12px;">REASONS</td>
                <td style="padding:12px;">
                  {"".join(f'<div style="color:#c8dff4;font-size:12px;margin-bottom:4px;">⚠️ {r}</div>' for r in reasons)}
                </td>
              </tr>
            </table>
            <p style="margin-top:24px;font-size:11px;
              color:#4a6580;text-align:center;">
              POWERED BY CYBERSHIELD AI • 95.41% ACCURACY
            </p>
          </div>
        </body></html>
        """

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email,
                          msg.as_string())

        print(f"✅ Alert email sent to {to_email} for {verdict}: {url}")
        return True

    except Exception as e:
        print(f"❌ Email failed: {e}")
        return False