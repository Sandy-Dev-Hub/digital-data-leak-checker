# LeakChecker — Digital Personal Data Leak Checker

LeakChecker is a cybersecurity awareness web application built with Python and Flask. It helps users understand the possible risks associated with their personal data such as their email addresses and phone numbers. The system analyzes patterns in these details, detects vulnerabilities, and provides a comprehensive risk level along with personalized security recommendations.

## Features

### Core Features
- **Risk Analysis:** Analyzes email addresses and phone numbers for known patterns that can increase exposure risk (e.g., short usernames, sequential numbers, public domains).
- **Risk Scoring:** Calculates separate risk scores for emails and phone numbers, combining them to classify the overall vulnerability as **LOW**, **MEDIUM**, or **HIGH**.
- **Security Recommendations:** Offers general, email-specific, and phone-specific security tips dynamically tailored to the user's calculated risk score.
- **Breach Detection:** A simulated breach database checker that allows users to see if an email address has been compromised in known data breaches, revealing the affected platform, year, and exposed data.
- **User Authentication:** Includes a user registration and login system backed by an SQLite database (`users.db`) using session management.
- **Professional UI/UX:** A sleek, fully responsive dark-themed interface built with custom CSS, utilizing glassmorphism, gradient accents, micro-animations, and modern design principles.

### AI-Powered Features (Groq API — llama3-8b-8192)
- **AI Risk Explanation Engine:** After the rule-based scoring, an AI model generates a human-readable explanation of why the user's data may be at risk, what patterns triggered it, and how to improve.
- **AI Security Insight Generator:** A concise AI-generated summary highlighting the most critical security concerns based on the analysis results.
- **AI Cybersecurity Chatbot:** A floating chat assistant available on every page where users can ask cybersecurity questions and receive educational guidance.
- **AI Phishing Message Analyzer:** A dedicated tool where users can paste suspicious emails or messages and the AI classifies them as SAFE, SUSPICIOUS, or LIKELY PHISHING with reasoning.
- **AI Awareness Trainer:** An interactive 5-question quiz about security habits, after which the AI generates a personalized awareness report.

## Tech Stack

- **Backend:** Python, Flask
- **AI:** Groq API (llama3-8b-8192)
- **Database:** SQLite
- **Frontend:** HTML5, CSS3 (Custom Design System, Vanilla CSS), JavaScript

## Project Structure

```text
.
├── app.py                  # Main Flask application containing routing and core logic
├── ai_engine.py            # Centralized AI module with all Groq API integration functions
├── users.db                # SQLite database for storing registered user credentials
├── README.md               # Project documentation
├── static/                 # Static assets directory
│   ├── style.css           # Comprehensive custom design system and stylesheet
│   ├── logo.png            # Application logo image
│   └── favicon.png         # Website favicon image
└── templates/              # HTML templates rendered by Flask
    ├── base.html           # Shared layout template (navbar, footer, chatbot panel)
    ├── home.html           # Dashboard for risk analysis with AI explanation and insight
    ├── login.html          # User authentication login view
    ├── register.html       # User account creation view
    ├── breach.html         # Data breach database checker view
    ├── how.html            # Detailed breakdown explaining the system workflow
    ├── phishing.html       # AI phishing message analyzer tool
    └── awareness.html      # AI cybersecurity awareness trainer quiz
```

## Installation & Setup

1. **Prerequisites:** Ensure Python 3.x is installed on your system.
2. **Install Dependencies:**
   ```bash
   pip install Flask groq
   ```
3. **Configure AI API Key:**
   Open `ai_engine.py` and replace the placeholder API key with your own Groq API key:
   ```python
   GROQ_API_KEY = "gsk_YOUR_API_KEY_HERE"
   ```
   You can get a free API key at [console.groq.com](https://console.groq.com).
4. **Run the Application:**
   ```bash
   python app.py
   ```
5. **Access the App:**
   Open your browser and navigate to `http://127.0.0.1:5000/`.

## Usage Guide

- **Home Page:** Enter any email and a 10-digit phone number. The system generates a rule-based risk report, followed by an AI explanation and security insight.
- **Breach Checker:** Search the simulated dataset to check if a specific email was involved in a past breach.
- **Phishing Analyzer:** Paste a suspicious email or message and the AI will classify it and explain threat indicators.
- **Awareness Trainer:** Take a 5-question security habits quiz and receive a personalized AI-generated awareness report.
- **Chatbot:** Click the 💬 button (bottom-right corner on any page) to ask cybersecurity questions.
- **How it Works:** Review the step-by-step logic the system uses to determine risk scores.
- **Accounts:** Create an account via Register and sign in for session-aware features.
