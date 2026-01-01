🛡️ TaskMaster – Secure Task Management Application

(Cybersecurity Learning Project)

TaskMaster is a task management web application developed as a hands-on learning project by a cybersecurity student.

The goal of this project goes beyond basic functionality. It is designed to understand real-world web application behaviour, including authentication flow, user input handling, session management, and common security weaknesses, from both a defensive and testing perspective.

This application also serves as a practice target for manual penetration testing, helping to analyse how vulnerabilities such as XSS, SQL Injection, and authentication flaws can emerge in practical systems.

🎯 Project Objectives (Cybersecurity Focus)

This project was built to help achieve the following learning goals:

Understand end-to-end web application workflow

Analyse authentication and session management

Study user input handling and output rendering

Identify and map OWASP Top 10 vulnerabilities

Improve awareness of secure coding practices

Gain confidence in manual web application testing

Create a realistic app for safe vulnerability analysis

🚀 Core Features
🗂 Task Management

Create, update, and delete tasks

Mark tasks as completed or pending

Dashboard-based task status overview

👤 User Authentication

User registration and login system

Forgot-password and password reset functionality

Session-based access control (learning-focused)

📧 Email Functionality

SMTP-based email system

Used to study email workflows and related security risks

Supports account-related actions (reset, notifications)

🧭 User Interface

Simple and clean UI for easy flow analysis

Multiple pages to practise:

DOM inspection

Client-side testing

JavaScript behaviour analysis

🔐 Security Learning Scope

This project is intentionally used to practise and understand:

Input validation and sanitisation

Authentication and authorisation logic

Client-side vs server-side trust boundaries

Session handling behaviour

Common attack vectors, including:

Cross-Site Scripting (XSS)

Broken Authentication

Security Misconfiguration

Mapping application behaviour to the OWASP Top 10

⚠️ Important Note:
This application is developed strictly for educational and learning purposes.
It is not intended for production use.

🛠 Tech Stack

Frontend: HTML, CSS, JavaScript

Backend: Python (Flask)

Database: Local database (learning environment)

Email: SMTP-based email handling

Environment: Local development setup

📂 Project Structure
taskmanager/
│
├── app.py                  # Main Flask application file
│
├── templates/              # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── forgot_password.html
│   ├── privacy.html
│   └── base.html
│
├── static/                 # Static assets
│   ├── css/
│   │   ├── main.css
│   │   └── auth.css
│   │
│   └── js/
│       ├── main.js
│       └── auth.js
│
├── README.md               # Project documentation
└── requirements.txt        # Python dependencies

🧪 Usage for Learning & Testing

This application can be used to practise:

Manual web application testing

Understanding request–response behaviour

Analysing authentication flow

Studying client-side JavaScript handling

Identifying insecure input/output patterns

📌 Disclaimer

This project is created only for learning, experimentation, and skill development.
Any testing should be done locally on this application only.
