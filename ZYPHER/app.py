import os
import re
import base64
import time
import requests
from flask import Flask, render_template, request, jsonify, redirect, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from twilio.twiml.messaging_response import MessagingResponse

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a strong secret key in production

# Gmail API and OAuth2 Config
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for development/testing
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = "gmailapi.json"  # Downloaded from Google Cloud Console

# VirusTotal API Key (replace with your actual key)
VIRUSTOTAL_API_KEY = '3c68ebaaf3413c13d1c9692b2c83ce053a48424f6e4c3e1603df15fc6b7cfeaf'

# Scam detection data
mock_breaches = ['test123@gmail.com', 'scammed@example.com']
scam_keywords = [

    "account locked", "suspended", "unauthorized access", "verify now", "reset your password",
    "payment failed", "invoice overdue", "urgent payment", "claim your reward", "billing issue",
    "congratulations", "you won", "free gift", "claim your prize", "free iPhone", "exclusive deal",
    "you have been hacked", "legal action", "pay or else", "your files are encrypted", "FBI warning",
    "bank statement", "Apple Support", "PayPal Security", "Microsoft Support", "security update",
    "click the link below", "open attachment", "confirm information", "respond now", "act immediately",
    "noreply@", "support@", "admin@", "helpdesk@", "update@", "act now for exclusive offer", "amazing deal awaits", "become a millionaire", "cash bonus available",
    "claim your discount", "double your income", "earn money fast", "exclusive savings",
    "financial freedom now", "get rich quick", "instant cash prize", "limited time offer",
    "make millions today", "money-back guarantee", "no cost investment", "risk-free opportunity",
    "special promotion", "unlock your earnings", "win big today", "your prize awaits",
    "zero cost signup", "100% profit guaranteed", "cash out now", "free money offer",
    "huge savings today", "instant wealth", "no risk investment", "profit now",
    "quick cash solution", "special deal today", "win cash now", "your financial future",
    "easy money maker", "fast cash opportunity", "get paid today", "limited offer discount",
    "money making system", "save big now", "unlock wealth secrets", "your exclusive bonus",
    "act fast", "don’t miss out", "final chance", "hurry now", "last call", "limited spots",
    "only a few left", "time is running out", "urgent action needed", "don’t delay",
    "expires soon", "final reminder", "grab it now", "immediate action required",
    "last opportunity", "offer ends today", "one-time deal", "rush now", "time-sensitive offer",
    "act before it’s gone", "don’t wait", "final hours", "limited availability", "now or never",
    "offer expires tonight", "take action now", "urgent response needed", "while supplies last",
    "countdown started", "don’t miss this chance", "final offer", "hurry up", "last chance offer",
    "one day only", "time’s almost up", "urgent deadline", "act immediately", "don’t let this pass",
    "limited time only", "secure your spot now", "cure your illness", "instant weight loss",
    "miracle health solution", "natural remedy", "rapid fat burner", "revolutionary diet",
    "secret health formula", "boost your energy", "eliminate pain fast", "miracle cure",
    "anti-aging secret", "health breakthrough", "lose weight now", "medical miracle",
    "natural weight loss", "pain-free solution", "reverse aging", "secret to health",
    "ultimate detox", "weight loss miracle", "cure all diseases", "fast health fix",
    "instant relief", "miracle supplement", "rapid recovery", "super health boost",
    "ultimate weight loss", "youth formula", "health secret revealed", "lose pounds fast",
    "miracle pill", "rapid slimming", "super detox plan", "ultimate health fix",
    "weight loss secret", "cure in days", "fast fitness solution", "health revolution",
    "instant health boost", "miracle fat loss", "account compromised", "critical security alert",
    "device infected", "fix your computer", "malware detected", "secure your account",
    "system compromised", "update your software", "virus alert", "your device is at risk",
    "critical update needed", "hack attempt detected", "protect your data", "secure your device",
    "system error found", "update your security", "virus removal needed", "your account is at risk",
    "critical system error", "device security breach", "fix your system now", "malware removal",
    "secure your system", "system update required", "virus scan needed", "your data is at risk",
    "account security issue", "critical virus alert", "device hack detected", "protect your device now",
    "system failure alert", "update your device", "virus infection found", "your system is infected",
    "account breach detected", "critical security update", "device compromised", "fix your device now",
    "security alert issued", "system hack alert", "casino bonus", "free spins", "hit the jackpot",
    "play now and win", "win big at casino", "adult content access", "exclusive casino deal",
    "free casino credits", "instant casino win", "play and win big", "casino prize",
    "free adult access", "jackpot winner", "play free slots", "win at casino", "adult entertainment",
    "casino free play", "instant jackpot", "play to win", "win casino cash", "adult content free",
    "casino special offer", "free slot spins", "jackpot deal", "play casino now", "win gambling prize",
    "adult exclusive offer", "casino win guaranteed", "free gambling bonus", "jackpot opportunity",
    "play adult games", "win casino bonus", "free adult content", "casino instant win",
    "gambling deal", "jackpot cash", "play adult now", "win slots today", "adult special deal",
    "casino free spins", "amazing offer", "best deal ever", "click here now", "exclusive gift",
    "free access", "get it free", "incredible deal", "limited gift", "special gift",
    "unbelievable offer", "click to claim", "free bonus", "get started now", "instant access",
    "no obligation", "special bonus", "claim now", "free trial", "get your gift", "instant deal",
    "no cost offer", "special offer", "click for free", "free signup", "get your prize",
    "instant offer", "no risk offer", "special prize", "click to win", "free deal", "get it now",
    "instant signup", "no cost trial", "special signup", "click for deal", "free gift now",
    "get your deal", "instant prize", "no obligation offer", "special deal now", "action required",
    "final notice", "immediate response", "legal notice", "penalty warning", "respond immediately",
    "urgent legal action", "final warning", "immediate notice", "legal issue", "penalty notice",
    "respond or else", "urgent notice", "action needed now", "final legal notice", "immediate warning",
    "legal action pending", "penalty alert", "respond now or else", "urgent legal issue",
    "action required now", "final penalty notice", "immediate legal action", "legal warning",
    "penalty action", "respond urgently", "urgent penalty notice", "action or penalty",
    "final legal warning", "immediate penalty", "legal action required", "penalty response needed",
    "urgent legal warning", "action or legal issue", "final action notice", "immediate legal notice",
    "legal penalty alert", "respond to legal notice", "urgent action warning", "final penalty alert",
    "buy now", "call now", "don’t miss", "free quote", "guarantee success", "no catch",
    "risk-free trial", "shop now", "sign up free", "take advantage", "win instantly",
    "amazing prize", "best offer", "click below", "free sample", "get now", "instant savings",
    "no hassle", "special discount", "win a prize", "amazing savings", "best price",
    "click to get", "free offer", "get your free", "instant discount", "no risk deal",
    "special savings", "win free", "amazing deal"
]


# -------------------- Routes -------------------- #

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mail-scanner')
def mail_scanner():
    return render_template('mail_scanner.html')

@app.route('/whatsapp-analyzer')
def whatsapp_analyzer():
    return render_template('whatsapp_analyzer.html')

@app.route('/sms-validator')
def sms_validator():
    return render_template('sms_validator.html')

@app.route('/website-checker')
def website_checker():
    return render_template('website_checker.html')

@app.route('/security-tips')
def security_tips():
    return render_template('security_tips.html')

@app.route('/scan-text', methods=['POST'])
def scan_text():
    user_text = request.form.get('text')
    flagged = [word for word in scam_keywords if word.lower() in user_text.lower()]
    if flagged:
        return jsonify({'result': '⚠️ Potential scam detected!', 'flags': flagged})
    else:
        return jsonify({'result': '✅ Message appears clean.', 'flags': []})

@app.route('/scan-url', methods=['POST'])
def scan_url():
    user_url = request.form.get('url')
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": user_url}

    # Step 1: Submit URL
    submit_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    if submit_response.status_code != 200:
        return jsonify({'result': '❌ Failed to submit URL.', 'error': submit_response.text})

    url_id = submit_response.json()["data"]["id"]

    # Step 2: Poll until ready
    for _ in range(10):  # Retry max 10 times
        report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
        report_data = report_response.json()
        if report_data['data']['attributes']['status'] == 'completed':
            stats = report_data['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return jsonify({'result': f'❌ URL flagged as malicious by {malicious} sources.'})
            else:
                return jsonify({'result': '✅ URL appears clean.'})
        time.sleep(2)

    return jsonify({'result': '⚠️ Timed out waiting for analysis.'})

@app.route('/check-breach', methods=['POST'])
def check_breach():
    email = request.form.get('email')
    if email in mock_breaches:
        return jsonify({'result': '⚠️ Your email was found in known breaches.'})
    else:
        return jsonify({'result': '✅ No breach found for this email.'})

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session['credentials'] = creds_to_dict(creds)
    return redirect(url_for('read_inbox'))

@app.route('/read-inbox')
def read_inbox():
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    result = service.users().messages().list(userId='me', maxResults=5).execute()
    messages = result.get('messages', [])

    output = "<h2>Last 5 Emails</h2>"
    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
        snippet = msg_data.get('snippet', '')
        headers = msg_data['payload'].get('headers', [])
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No subject')

        # Scam detection
        if any(word in snippet.lower() for word in scam_keywords):
            verdict = "⚠️ Potential Scam"
        else:
            verdict = "✅ Looks Safe"

        output += f"<p><b>From:</b> {sender}<br><b>Subject:</b> {subject}<br><b>Verdict:</b> {verdict}<br><i>{snippet}</i></p><hr>"

    return output

# @app.route("/whatsapp-hook", methods=["POST"])
# def whatsapp_hook():
#     from_number = request.form.get("From")
#     body = request.form.get("Body")

#     # Scan message for scam keywords
#     flagged = [word for word in scam_keywords if word.lower() in body.lower()]
#     response = MessagingResponse()

#     if flagged:
#         response.message(f"⚠️ Scam detected! Keywords: {', '.join(flagged)}")
#     else:
#         response.message("✅ Your WhatsApp message looks clean.")

#     return str(response)

# ---------------- Helpers ---------------- #

def creds_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

# ---------------- Run App ---------------- #

if __name__ == '__main__':
    app.run(debug=True)