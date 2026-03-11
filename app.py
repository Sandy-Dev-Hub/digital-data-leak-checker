from flask import Flask, render_template, request, redirect, session, jsonify
import re
import psycopg2
from psycopg2.extras import DictCursor
import random
import ai_engine
import os
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_validator import validate_email, EmailNotValidError
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.secret_key = "secret123"

# DATABASE
# Password is URL encoded to handle the "@" symbol safely
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "postgresql://postgres:Vicky%4030110505@db.mqkdjudzlarhhvscjskl.supabase.co:5432/postgres")

def get_db_connection():
    """Returns a connection to the Supabase PostgreSQL database."""
    conn = psycopg2.connect(SUPABASE_DB_URL)
    conn.autocommit = True
    return conn


# ──────────────────────────────────────────────
# AUTOMATED BREACH MONITORING (BACKGROUND JOB)
# ──────────────────────────────────────────────

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

def send_alert_email(to_email, platform, data_leaked):
    """Sends a warning email to a user if their data was in a breach."""
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("[!] SENDER_EMAIL or SENDER_PASSWORD not set in .env. Skipping email.")
        return

    subject = "URGENT: Your data was found in a new breach!"
    body = f"""
    Hello,

    LeakChecker Automated Monitoring has detected that your email ({to_email}) was involved in a recent data breach.

    Breach Details:
    - Platform: {platform}
    - Compromised Data: {data_leaked}

    Please change your password on {platform} immediately and ensure you aren't reusing this password anywhere else.

    Stay safe,
    LeakChecker Security Team
    """

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connecting to Gmail's SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[+] Successfully sent breach alert email to {to_email}")
    except Exception as e:
        print(f"[-] Failed to send email to {to_email}. Error: {e}")

def monitor_breaches():
    """Background task that checks live OSINT APIs for each user's email."""
    print("[*] Running scheduled live breach monitor scan...")

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT email FROM users")
            users = cur.fetchall()
            
            for user in users:
                user_email = user[0]
                
                # Querying the free OSINT LeakCheck API for live data
                response = requests.get(f"https://leakcheck.io/api/public?check={user_email}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # 'success' means they found records
                    if data.get("success") and data.get("sources"):
                        # The free endpoint returns a list of source names (e.g., ["Facebook", "LinkedIn"])
                        breach_sources = data["sources"]
                        
                        for source_obj in breach_sources:
                            # Some APIs return strings, some return dicts. Safe extraction:
                            platform_name = source_obj.get("name") if isinstance(source_obj, dict) else source_obj
                            
                            # Did we already email this user about this specific platform?
                            cur.execute(
                                "SELECT 1 FROM alerts WHERE email=%s AND breach_name=%s", 
                                (user_email, platform_name)
                            )
                            already_alerted = cur.fetchone()

                            if not already_alerted:
                                print(f"[!] NEW LIVE BREACH detected for {user_email} on {platform_name}! Alerting user...")
                                # Send email
                                send_alert_email(user_email, platform_name, "Data leak found in public databases")
                                
                                # Log that we sent the alert so we don't spam them in 60 seconds
                                cur.execute(
                                    "INSERT INTO alerts (email, breach_name) VALUES (%s, %s)", 
                                    (user_email, platform_name)
                                )
                
                else:
                    print(f"[-] OSINT API Rate limited or failed for {user_email}. Status: {response.status_code}")

    except Exception as e:
        print(f"[-] Error during live breach monitoring: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

# Start the background scheduler
scheduler = BackgroundScheduler()
# Runs every 60 seconds for testing/demonstration purposes
scheduler.add_job(func=monitor_breaches, trigger="interval", seconds=60)
scheduler.start()



# EMAIL ANALYSIS
def analyze_email(email):

    score = 0
    reasons = []

    username, domain = email.split("@")

    if domain in ["gmail.com","yahoo.com","hotmail.com", "outlook.com"]:
        score += 10
        reasons.append("Public email provider")

    if re.search(r"\d+", username):
        score += 10
        reasons.append("Email contains numbers")

    if len(username) <= 4:
        score += 20
        reasons.append("Very short email username")
        
    generic_names = ["admin", "test", "user", "info", "contact", "support"]
    if any(name in username.lower() for name in generic_names):
        score += 30
        reasons.append("Generic or high-value username (e.g., admin, info)")

    return score, reasons


# PHONE ANALYSIS
def analyze_phone(phone):

    score = 0
    reasons = []

    if phone.startswith(("9","8","7","6")):
        score += 10
        reasons.append("Common mobile prefix")

    if phone in ["1234567890","9876543210"]:
        score += 30
        reasons.append("Sequential pattern")

    if len(set(phone)) <= 3:
        score += 20
        reasons.append("Low digit diversity")

    if phone == phone[0]*10:
        score += 25
        reasons.append("Repeated digits pattern")
        
    # Catch 3 or more repeated digits anywhere (like 777 or 555)
    if re.search(r"(\d)\1{2,}", phone):
        score += 15
        reasons.append("Contains blocks of repeated numbers")

    return score, reasons


# RISK LEVEL
def get_level(score):

    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    else:
        return "HIGH"


# GENERAL TIPS
def get_general_tips(score):

    if score <= 20:
        return [
        "Use strong passwords",
        "Keep devices updated",
        "Avoid sharing personal information"
        ]

    elif score <= 60:
        return [
        "Enable Two Factor Authentication",
        "Use different passwords",
        "Monitor login activity"
        ]

    else:
        return [
        "Change passwords immediately",
        "Enable security alerts",
        "Check breach databases"
        ]


# EMAIL TIPS
def get_email_tips(score):

    if score <= 10:
        return [
        "Email looks safe",
        "Enable login alerts"
        ]

    else:
        return [
        "Enable Two Factor Authentication",
        "Change password frequently",
        "Avoid using email everywhere"
        ]


# PHONE TIPS
def get_phone_tips(score):

    if score <= 10:
        return [
        "Avoid sharing phone number publicly"
        ]

    else:
        return [
        "Enable spam protection",
        "Never share OTP",
        "Avoid unknown links"
        ]


# HOME PAGE
@app.route("/", methods=["GET","POST"])
def home():

    if request.method == "POST":

        email = request.form["email"]
        phone = request.form["phone"]

        try:
            # Check if email is valid and has a real TLD/domain structure
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            return render_template("home.html",error=str(e))

        if not phone.isdigit() or len(phone)!=10:
            return render_template("home.html",error="Phone must be 10 digits")

        email_score,email_reasons = analyze_email(email)
        phone_score,phone_reasons = analyze_phone(phone)

        # ---------------------------------------------
        # LIVE API BREACH CHECK INJECTION
        # ---------------------------------------------
        try:
            response = requests.get(f"https://leakcheck.io/api/public?check={email}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("sources"):
                    # The email was found in a real, live data breach
                    email_score += 50
                    email_reasons.append(f"CRITICAL: Found in {len(data['sources'])} real Dark Web leaks!")
        except Exception as e:
            print(f"Failed to check live API during home scan: {e}")
        # ---------------------------------------------

        total_score = email_score + phone_score
        level = get_level(total_score)

        general_tips = get_general_tips(total_score)
        email_tips = get_email_tips(email_score)
        phone_tips = get_phone_tips(phone_score)

        # AI-powered explanation and insight (additive — does not replace rule-based scoring)
        ai_explanation = ai_engine.generate_risk_explanation(
            email, phone, email_score, phone_score,
            total_score, level, email_reasons, phone_reasons
        )
        ai_insight = ai_engine.generate_security_insight(
            total_score, level, email_reasons, phone_reasons
        )

        return render_template(
        "home.html",
        email_score=email_score,
        phone_score=phone_score,
        total_score=total_score,
        level=level,
        email_reasons=email_reasons,
        phone_reasons=phone_reasons,
        general_tips=general_tips,
        email_tips=email_tips,
        phone_tips=phone_tips,
        ai_explanation=ai_explanation,
        ai_insight=ai_insight
        )

    return render_template("home.html")


# BREACH CHECKER
@app.route("/breach", methods=["GET","POST"])
def breach():
    breach = None
    safe = False
    error = None

    if request.method == "POST":
        email = request.form["email"].lower()

        try:
            # Validate email structure and domain deliverability
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            error = str(e)
            return render_template("breach.html", breach=breach, safe=safe, error=error)

        try:
            # Querying the live database!
            response = requests.get(f"https://leakcheck.io/api/public?check={email}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("success") and data.get("sources"):
                    # Extract platform names from the response
                    sources = data["sources"]
                    platforms = []
                    for s in sources:
                        name = str(s.get("name") or "Unknown") if isinstance(s, dict) else str(s)
                        # If it looks like a domain, link directly, otherwise do a Google search
                        if "." in name and " " not in name:
                            url = f"https://{name}"
                        else:
                            import urllib.parse
                            query = urllib.parse.quote(f"{name} data breach")
                            url = f"https://www.google.com/search?q={query}"
                        platforms.append({"name": name, "url": url})
                    
                    # The free public API doesn't provide specific years or granular data details, 
                    # so we format it nicely for the UI card
                    breach = {
                        "platforms": platforms,
                        "year": "Live Database Match",
                        "data": "Email / Password (varies by source)"
                    }
                else:
                    # If success is false or sources is empty, the email is safe!
                    safe = True
            else:
                error = "Security API rate limited. Please try again in a few minutes."
                
        except Exception as e:
            error = f"Failed to connect to breach database: {e}"

    return render_template("breach.html", breach=breach, safe=safe, error=error)


# HOW PAGE

@app.route("/how")
def how():
    return render_template("how.html")

@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":

        email=request.form["email"]
        password=request.form["password"]

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE email=%s AND password=%s",
                (email, password)
            )
            user = cur.fetchone()
        conn.close()

        if user:
            session["user"]=user[1]   # store username
            return redirect("/")

        else:
            return render_template("login.html",error="Invalid Login")

    return render_template("login.html")


# REGISTER
@app.route("/register",methods=["GET","POST"])
def register():

    if request.method=="POST":

        username=request.form["username"]
        email=request.form["email"]
        password=request.form["password"]

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users(username,email,password) VALUES(%s,%s,%s)",
                (username, email, password)
            )
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/logout")
def logout():

    session.pop("user",None)

    return redirect("/")


# ──────────────────────────────────────────────
# AI CHATBOT API
# ──────────────────────────────────────────────
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")
    if not user_message.strip():
        return jsonify({"reply": "Please enter a message."})
    reply = ai_engine.chat_response(user_message)
    return jsonify({"reply": reply})


# ──────────────────────────────────────────────
# AI PHISHING ANALYZER
# ──────────────────────────────────────────────
@app.route("/phishing", methods=["GET","POST"])
def phishing():
    result = None
    if request.method == "POST":
        message_text = request.form.get("message", "")
        if message_text.strip():
            result = ai_engine.analyze_phishing(message_text)
    return render_template("phishing.html", result=result)


# ──────────────────────────────────────────────
# PASSWORD SECURITY CHECKER
# ──────────────────────────────────────────────
@app.route("/password-checker")
def password_checker():
    return render_template("password_checker.html")


# ──────────────────────────────────────────────
# AI AWARENESS TRAINER
# ──────────────────────────────────────────────
@app.route("/awareness", methods=["GET","POST"])
def awareness():
    questions = ai_engine.AWARENESS_QUESTIONS
    report = None
    if request.method == "POST":
        answers = []
        for i, q in enumerate(questions):
            answer = request.form.get(f"q{i}", "No")
            answers.append({"question": q, "answer": answer})
        report = ai_engine.generate_awareness_report(answers)
    return render_template("awareness.html", questions=questions, report=report)


if __name__ == "__main__":
    app.run(debug=True)