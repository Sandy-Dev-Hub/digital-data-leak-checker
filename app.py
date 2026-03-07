from flask import Flask, render_template, request, redirect, session
import re
import sqlite3
import random

app = Flask(__name__)
app.secret_key = "secret123"

email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

# DATABASE
def create_db():
    conn = sqlite3.connect("users.db")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT,
    password TEXT
    )
    """)
    conn.close()

create_db()


# EMAIL ANALYSIS
def analyze_email(email):

    score = 0
    reasons = []

    username, domain = email.split("@")

    if domain in ["gmail.com","yahoo.com","hotmail.com"]:
        score += 10
        reasons.append("Public email provider")

    if re.search(r"\d+", username):
        score += 10
        reasons.append("Email contains numbers")

    if len(username) <= 4:
        score += 20
        reasons.append("Very short email username")

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

        if not re.match(email_pattern,email):
            return render_template("home.html",error="Invalid Email")

        if not phone.isdigit() or len(phone)!=10:
            return render_template("home.html",error="Phone must be 10 digits")

        email_score,email_reasons = analyze_email(email)
        phone_score,phone_reasons = analyze_phone(phone)

        total_score = email_score + phone_score
        level = get_level(total_score)

        general_tips = get_general_tips(total_score)
        email_tips = get_email_tips(email_score)
        phone_tips = get_phone_tips(phone_score)

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
        phone_tips=phone_tips
        )

    return render_template("home.html")


# BREACH CHECKER
@app.route("/breach", methods=["GET","POST"])
def breach():

    breach_data = {
        "admin@gmail.com":{"platform":"LinkedIn","year":"2012","data":"Email, Password"},
        "user@gmail.com":{"platform":"Dropbox","year":"2016","data":"Email, Password"},
        "test@yahoo.com":{"platform":"Adobe","year":"2013","data":"Email, Username"}
    }

    breach = None
    safe = False

    if request.method == "POST":

        email = request.form["email"].lower()

        if email in breach_data:
            breach = breach_data[email]

        else:
            platforms = ["Facebook","Instagram","Twitter","Adobe","LinkedIn"]
            years = ["2019","2020","2021","2022"]

            breach = {
                    "platform": random.choice(platforms),
                    "year": random.choice(years),
                    "data": "Email, Password"
}

    return render_template("breach.html", breach=breach, safe=safe)


# HOW PAGE

@app.route("/how")
def how():
    return render_template("how.html")

@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":

        email=request.form["email"]
        password=request.form["password"]

        conn=sqlite3.connect("users.db")

        user=conn.execute(
        "SELECT * FROM users WHERE email=? AND password=?",
        (email,password)
        ).fetchone()

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

        conn=sqlite3.connect("users.db")

        conn.execute(
        "INSERT INTO users(username,email,password) VALUES(?,?,?)",
        (username,email,password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/logout")
def logout():

    session.pop("user",None)

    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)