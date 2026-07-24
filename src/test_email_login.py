import smtplib
from dotenv import load_dotenv
import os

load_dotenv()

EMAIL = os.environ.get("CYBERSHIELD_SENDER_EMAIL")
PASSWORD = os.environ.get("CYBERSHIELD_SENDER_PASSWORD")

print(f"Email loaded: {EMAIL}")
print(f"Password loaded (length check only): {len(PASSWORD) if PASSWORD else 'NONE'} characters")
print(f"Password has spaces: {'yes' if PASSWORD and ' ' in PASSWORD else 'no'}")

try:
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(EMAIL, PASSWORD)
    print("✅ LOGIN SUCCESS — credentials are correct!")
    server.quit()
except Exception as e:
    print(f"❌ LOGIN FAILED: {e}")