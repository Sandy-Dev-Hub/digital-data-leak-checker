import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL = "llama-3.1-8b-instant"

client = Groq(api_key=GROQ_API_KEY)


def _call_groq(system_prompt, user_prompt, max_tokens=1024):
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI service unavailable: {str(e)}"


def generate_risk_explanation(email, phone, email_score, phone_score,
                              total_score, level, email_reasons, phone_reasons):
    system_prompt = (
        "You are a senior cybersecurity analyst. The user's email and phone "
        "number have been analyzed by a rule-based risk scoring engine. "
        "Based on the results provided, write a clear, human-readable "
        "explanation (3-5 short paragraphs) covering:\n"
        "1. Why the email or phone may be vulnerable\n"
        "2. What specific patterns triggered higher risk\n"
        "3. What attackers might exploit\n"
        "4. Actionable steps the user can take to improve security\n"
        "Use simple language. Do NOT output markdown headings."
    )

    user_prompt = (
        f"Email analyzed: {email}\n"
        f"Phone analyzed: {phone}\n"
        f"Email risk score: {email_score} — reasons: {', '.join(email_reasons) if email_reasons else 'None detected'}\n"
        f"Phone risk score: {phone_score} — reasons: {', '.join(phone_reasons) if phone_reasons else 'None detected'}\n"
        f"Total risk score: {total_score}\n"
        f"Risk level: {level}"
    )

    return _call_groq(system_prompt, user_prompt)


def generate_security_insight(total_score, level, email_reasons, phone_reasons, breach=None):
    system_prompt = (
        "You are a cybersecurity advisor. Write a concise 2-3 sentence "
        "'Security Insight' summary for the user. Mention specific risks "
        "detected and the potential consequences. Be direct and informative. "
        "Do NOT use markdown. Do NOT repeat generic tips."
    )

    breach_info = ""
    if breach:
        breach_info = (
            f"\nBreach detected — Platform: {breach.get('platform', 'Unknown')}, "
            f"Year: {breach.get('year', 'Unknown')}, Data exposed: {breach.get('data', 'Unknown')}"
        )

    user_prompt = (
        f"Risk level: {level} (score {total_score})\n"
        f"Email issues: {', '.join(email_reasons) if email_reasons else 'None'}\n"
        f"Phone issues: {', '.join(phone_reasons) if phone_reasons else 'None'}"
        f"{breach_info}"
    )

    return _call_groq(system_prompt, user_prompt, max_tokens=256)


def chat_response(user_message):
    system_prompt = (
        "You are LeakChecker AI Assistant.\n"
        "LeakChecker is a FREE cybersecurity awareness platform.\n"
        "Important information about the system:\n"
        "• The platform is completely FREE.\n"
        "• Users can create an account and log in.\n"
        "• Registered users get access to 24/7 email monitoring.\n"
        "• Monitoring alerts users if their email appears in a new breach.\n"
        "• There are NO paid plans or subscriptions.\n"
        "Available tools on the website:\n"
        "1. Breach Checker – Check if an email appears in known data breaches.\n"
        "2. Risk Analyzer – Analyze email and phone exposure risk.\n"
        "3. Phishing Analyzer – Detect suspicious messages.\n"
        "4. Password Strength Checker – Test password security.\n"
        "5. 24/7 Monitoring – Available for logged-in users to monitor their email for breaches.\n"
        "Rules:\n"
        "• Keep responses SHORT and easy to read.\n"
        "• Maximum 2–3 sentences.\n"
        "• Give direct answers only.\n"
        "• Suggest the correct tool on the website when needed.\n"
        "• Avoid long explanations.\n"
        "• Do NOT generate external https links for navigation.\n"
        "• Instead refer to the page name (e.g., Login page, Register page, Breach Checker page, Password Strength Checker page).\n"
        "When users ask about monitoring:\n"
        "• Explain that they need to register and log in.\n"
        "• Guide them to create an account if they are not logged in.\n"
        "Always respond briefly and guide the user to the correct tool."
    )

    return _call_groq(system_prompt, user_message, max_tokens=512)


def analyze_phishing(message_text):
    system_prompt = (
        "You are a phishing detection expert. Analyze the message provided "
        "by the user and classify it as exactly one of:\n"
        "SAFE\nSUSPICIOUS\nLIKELY PHISHING\n\n"
        "Respond in this exact format:\n"
        "Classification: <SAFE|SUSPICIOUS|LIKELY PHISHING>\n"
        "Reasoning: <your detailed analysis>\n\n"
        "Examine: urgency language, suspicious links, impersonation of "
        "known brands, requests for personal data, grammatical errors, "
        "and social engineering tactics."
    )

    return _call_groq(system_prompt, f"Analyze this message:\n\n{message_text}")


AWARENESS_QUESTIONS = [
    "Do you reuse the same password across multiple websites?",
    "Do you verify URLs/links before clicking on them?",
    "Do you use Two-Factor Authentication on your important accounts?",
    "Do you connect to public Wi-Fi without using a VPN?",
    "Do you regularly update your software and apps?",
]


def generate_awareness_report(answers):
    system_prompt = (
        "You are a cybersecurity awareness trainer. The user has answered "
        "a security habits questionnaire. Analyze their answers and produce "
        "a short personalized awareness report (3-4 paragraphs). "
        "Highlight risky habits, praise good ones, and give practical "
        "improvement tips. Be encouraging but honest. Do NOT use markdown headings."
    )

    answers_text = "\n".join(
        [f"Q: {a['question']}\nA: {a['answer']}" for a in answers]
    )

    return _call_groq(system_prompt, f"User's answers:\n\n{answers_text}")
