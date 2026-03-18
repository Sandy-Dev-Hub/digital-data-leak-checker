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

SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "postgresql://postgres:Vicky%4030110505@db.mqkdjudzlarhhvscjskl.supabase.co:5432/postgres")

def get_db_connection():
    conn = psycopg2.connect(SUPABASE_DB_URL)
    conn.autocommit = True
    return conn


SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

def send_alert_email(to_email, platform, data_leaked):
    if not SENDER_EMAIL or not SENDER_PASSWORD:
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
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Error: {e}")

def monitor_breaches():
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT email FROM users")
            users = cur.fetchall()
            
            for user in users:
                user_email = user[0]
                response = requests.get(f"https://leakcheck.io/api/public?check={user_email}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("success") and data.get("sources"):
                        breach_sources = data["sources"]
                        
                        for source_obj in breach_sources:
                            platform_name = source_obj.get("name") if isinstance(source_obj, dict) else source_obj
                            
                            cur.execute(
                                "SELECT 1 FROM alerts WHERE email=%s AND breach_name=%s", 
                                (user_email, platform_name)
                            )
                            already_alerted = cur.fetchone()

                            if not already_alerted:
                                send_alert_email(user_email, platform_name, "Data leak found in public databases")
                                
                                cur.execute(
                                    "INSERT INTO alerts (email, breach_name) VALUES (%s, %s)", 
                                    (user_email, platform_name)
                                )
                
                else:
                    print(f"OSINT API Rate limited or failed for {user_email}. Status: {response.status_code}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

scheduler = BackgroundScheduler()
scheduler.add_job(func=monitor_breaches, trigger="interval", seconds=60)
scheduler.start()



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
        
    if re.search(r"(\d)\1{2,}", phone):
        score += 15
        reasons.append("Contains blocks of repeated numbers")

    return score, reasons


def get_level(score):

    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    else:
        return "HIGH"


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


@app.route("/", methods=["GET","POST"])
def home():

    if request.method == "POST":

        email = request.form["email"]
        phone = request.form["phone"]

        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            return render_template("home.html",error=str(e))

        if not phone.isdigit() or len(phone)!=10:
            return render_template("home.html",error="Phone must be 10 digits")

        email_score,email_reasons = analyze_email(email)
        phone_score,phone_reasons = analyze_phone(phone)

        try:
            response = requests.get(f"https://leakcheck.io/api/public?check={email}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("sources"):
                    email_score += 50
                    email_reasons.append(f"CRITICAL: Found in {len(data['sources'])} real Dark Web leaks!")
        except Exception as e:
            print(f"Error: {e}")

        total_score = email_score + phone_score
        level = get_level(total_score)

        general_tips = get_general_tips(total_score)
        email_tips = get_email_tips(email_score)
        phone_tips = get_phone_tips(phone_score)

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


@app.route("/breach", methods=["GET","POST"])
def breach():
    breach = None
    safe = False
    error = None

    if request.method == "POST":
        email = request.form["email"].lower()

        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized
        except EmailNotValidError as e:
            error = str(e)
            return render_template("breach.html", breach=breach, safe=safe, error=error)

        try:
            response = requests.get(f"https://leakcheck.io/api/public?check={email}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("success") and data.get("sources"):
                    sources = data["sources"]
                    platforms = []
                    for s in sources:
                        name = str(s.get("name") or "Unknown") if isinstance(s, dict) else str(s)
                        if "." in name and " " not in name:
                            url = f"https://{name}"
                        else:
                            import urllib.parse
                            query = urllib.parse.quote(f"{name} data breach")
                            url = f"https://www.google.com/search?q={query}"
                        platforms.append({"name": name, "url": url})
                    
                    breach = {
                        "platforms": platforms,
                        "year": "Live Database Match",
                        "data": "Email / Password (varies by source)"
                    }
                else:
                    safe = True
            else:
                error = "Security API rate limited. Please try again in a few minutes."
                
        except Exception as e:
            error = f"Error: {e}"

    return render_template("breach.html", breach=breach, safe=safe, error=error)


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
            session["user"]=user[1]
            return redirect("/")

        else:
            return render_template("login.html",error="Invalid Login")

    return render_template("login.html")


@app.route("/register",methods=["GET","POST"])
def register():

    if request.method=="POST":

        username=request.form["username"]
        email=request.form["email"]
        password=request.form["password"]

        conn = get_db_connection()
        with conn.cursor() as cur:
            # Check if email already exists
            cur.execute("SELECT 1 FROM users WHERE email=%s", (email,))
            if cur.fetchone():
                conn.close()
                return render_template("register.html", error="Email already exists. Please sign in.")

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


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")
    if not user_message.strip():
        return jsonify({"reply": "Please enter a message."})
    reply = ai_engine.chat_response(user_message)
    return jsonify({"reply": reply})


@app.route("/phishing", methods=["GET","POST"])
def phishing():
    result = None
    if request.method == "POST":
        message_text = request.form.get("message", "")
        if message_text.strip():
            result = ai_engine.analyze_phishing(message_text)
    return render_template("phishing.html", result=result)


@app.route("/password-checker")
def password_checker():
    return render_template("password_checker.html")


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