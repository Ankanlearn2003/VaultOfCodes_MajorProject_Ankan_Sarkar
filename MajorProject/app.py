#!/usr/bin/env python3
"""
Custom Vulnerable Web Application (Lab Environment)
Author: Ankan Sarkar
Purpose: VaultofCodes Major Project - Option 11
Vulnerabilities Implemented:
  1. Weak Authentication
  2. Reflected Cross-Site Scripting (XSS)
  3. Insecure Direct Object Reference (IDOR) / Parameter Tampering
"""

from flask import Flask, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "vulnerable_lab_secret_key"

# In-memory database of mock user profiles
USERS_DB = {
    1: {
        "id": 1,
        "username": "admin",
        "role": "Administrator",
        "email": "admin@secureshop.local",
        "api_key": "SECRET_API_KEY_ADMIN_9901",
        "salary": "$150,000",
    },
    2: {
        "id": 2,
        "username": "rahul",
        "role": "Developer",
        "email": "rahul@secureshop.local",
        "api_key": "DEV_KEY_RAHUL_1029",
        "salary": "$85,000",
    },
    3: {
        "id": 3,
        "username": "guest",
        "role": "Guest",
        "email": "guest@secureshop.local",
        "api_key": "GUEST_TEMP_KEY_0000",
        "salary": "$0",
    },
}

# Weak User Authentication Store
CREDENTIALS_DB = {
    "admin": "admin123",  # Weak default password
    "rahul": "rahul@123",
    "guest": "guest",
}


HTML_BASE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VOC Hacking Shop - Lab Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f6f9; }
        .container { max-width: 800px; margin: auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; }
        nav { margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ccc; }
        nav a { margin-right: 15px; text-decoration: none; color: #0066cc; font-weight: bold; }
        .card { background: #eef2f7; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .alert { background: #ffe3e3; border: 1px solid #ff0000; padding: 10px; color: #990000; border-radius: 4px; margin-bottom: 15px; }
        .success { background: #e3ffe8; border: 1px solid #00991b; padding: 10px; color: #006611; border-radius: 4px; margin-bottom: 15px; }
        input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
        button { background-color: #0066cc; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/search?q=security">Search Catalog</a>
            <a href="/profile?user_id=3">User Profile</a>
            <a href="/logout">Logout</a>
        </nav>
        {{ content | safe }}
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    content = """
    <h1>Welcome to VOC Vulnerable Shop Lab</h1>
    <p>This is a controlled red team assessment application designed to demonstrate web application vulnerabilities.</p>
    <ul>
        <li><b>Module 1:</b> Authentication System (Weak Credentials)</li>
        <li><b>Module 2:</b> Search Engine (Reflected XSS Vulnerability)</li>
        <li><b>Module 3:</b> Account Dashboard (IDOR / Parameter Tampering Vulnerability)</li>
    </ul>
    """
    return render_template_string(HTML_BASE, content=content)


# VULNERABILITY 1: Weak Authentication & Unprotected Session Handling
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username in CREDENTIALS_DB and CREDENTIALS_DB[username] == password:
            session["user"] = username
            # Assign user_id based on database lookup
            for uid, user_data in USERS_DB.items():
                if user_data["username"] == username:
                    session["user_id"] = uid
                    break
            return redirect(
                url_for("profile", user_id=session.get("user_id", 3))
            )
        else:
            message = '<div class="alert">Invalid credentials provided!</div>'

    content = f"""
    <h2>User Login</h2>
    {message}
    <form method="POST">
        <label>Username:</label>
        <input type="text" name="username" placeholder="Enter username" required>
        <label>Password:</label>
        <input type="password" name="password" placeholder="Enter password" required>
        <button type="submit">Login</button>
    </form>
    """
    return render_template_string(HTML_BASE, content=content)


# VULNERABILITY 2: Reflected Cross-Site Scripting (XSS)
@app.route("/search")
def search():
    query = request.args.get("q", "")

    # INTENTIONAL VULNERABILITY: Raw input dynamic string reflection without htmlspecialchars / sanitization
    results_html = f"""
    <h2>Product Catalog Search</h2>
    <p>Search Results for: <b>{query}</b></p>
    <div class="card">
        <p>No products matched your search term directly. Try searching for 'security' or 'network'.</p>
    </div>
    <form action="/search" method="GET">
        <input type="text" name="q" value="{query}">
        <button type="submit">Search Again</button>
    </form>
    """
    return render_template_string(HTML_BASE, content=results_html)


# VULNERABILITY 3: Insecure Direct Object Reference (IDOR) / Parameter Tampering
@app.route("/profile")
def profile():
    user_id_param = request.args.get("user_id")

    if not user_id_param:
        return redirect(url_for("profile", user_id=3))

    try:
        user_id = int(user_id_param)
    except ValueError:
        user_id = 3

    # INTENTIONAL VULNERABILITY: The server trusts user_id directly from the GET parameter
    # without verifying if session['user_id'] == user_id.
    user_data = USERS_DB.get(
        user_id,
        {
            "username": "Unknown",
            "role": "Guest",
            "email": "N/A",
            "api_key": "N/A",
            "salary": "$0",
        },
    )

    content = f"""
    <h2>User Profile (IDOR Vulnerability Module)</h2>
    <div class="alert">
        <b>Notice:</b> Profile ID loaded via URL parameter: <code>?user_id={user_id}</code>
    </div>
    <div class="card">
        <p><b>User ID:</b> {user_data['id']}</p>
        <p><b>Username:</b> {user_data['username']}</p>
        <p><b>Account Role:</b> {user_data['role']}</p>
        <p><b>Email Address:</b> {user_data['email']}</p>
        <p><b>Private API Key:</b> <mark>{user_data['api_key']}</mark></p>
        <p><b>Internal Compensation Data:</b> {user_data['salary']}</p>
    </div>
    """
    return render_template_string(HTML_BASE, content=content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    print("[+] Starting Vulnerable Web Application on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
