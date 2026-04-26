"""
SHIELD ANALYZER - Security Header Intelligence Engine & Logging Dashboard
Backend: Flask API Server
Author: ShieldAnalyzer Team
"""
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import json
import os
import time
import hashlib
import uuid
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)  # Allow cross-origin requests from frontend

# ─────────────────────────────────────────────
# DATA STORAGE (JSON file-based, no DB needed)
# ─────────────────────────────────────────────
SCAN_HISTORY_FILE = "scan_history.json"
USERS_FILE = "users.json"

def load_json(filepath):
    """Load JSON data from file, return empty dict if not found."""
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def save_json(filepath, data):
    """Save data to JSON file."""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

# ─────────────────────────────────────────────
# SECURITY HEADER DEFINITIONS
# Each header has: description, why it matters, fix example, weight
# ─────────────────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "short": "CSP",
        "weight": 20,
        "category": "XSS Protection",
        "risk": "CRITICAL",
        "danger": "Without CSP, attackers can inject malicious scripts (XSS attacks) into your pages. This allows them to steal cookies, session tokens, redirect users, or mine cryptocurrency using your visitors' browsers.",
        "fix": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "Strict-Transport-Security": {
        "short": "HSTS",
        "weight": 18,
        "category": "Transport Security",
        "risk": "HIGH",
        "danger": "Without HSTS, users who type your URL without 'https://' are vulnerable to SSL-stripping attacks. A man-in-the-middle attacker can intercept the initial HTTP request and downgrade your entire session to plaintext.",
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "X-Frame-Options": {
        "short": "XFO",
        "weight": 12,
        "category": "Clickjacking",
        "risk": "HIGH",
        "danger": "Without this, attackers can embed your website inside an invisible iframe on their malicious site. They overlay it with fake buttons, tricking users into clicking actions on YOUR site unknowingly — this is called Clickjacking.",
        "fix": "X-Frame-Options: DENY  (or SAMEORIGIN if you need iframe on same domain)",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "X-Content-Type-Options": {
        "short": "XCTO",
        "weight": 10,
        "category": "MIME Sniffing",
        "risk": "MEDIUM",
        "danger": "Without this, browsers try to 'guess' file types. An attacker can upload a malicious HTML file disguised as an image. The browser then executes it as HTML, enabling XSS attacks through file uploads.",
        "fix": "X-Content-Type-Options: nosniff",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "Referrer-Policy": {
        "short": "RP",
        "weight": 8,
        "category": "Privacy",
        "risk": "MEDIUM",
        "danger": "Without this, when a user navigates from your site to another, their browser sends your full URL (including sensitive paths/query params) as the Referrer header. This leaks user activity and private URLs to third parties.",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "Permissions-Policy": {
        "short": "PP",
        "weight": 8,
        "category": "Feature Control",
        "risk": "MEDIUM",
        "danger": "Without this, any embedded script or iframe can access powerful browser APIs like camera, microphone, and geolocation without restriction. Malicious third-party scripts could silently activate these sensors.",
        "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(self)",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy"
    },
    "X-XSS-Protection": {
        "short": "XSS",
        "weight": 7,
        "category": "XSS Protection",
        "risk": "LOW",
        "danger": "While modern browsers have CSP, older browsers (IE, legacy Edge) rely on this header to detect and block reflected XSS attacks. Without it, users on older browsers are left unprotected.",
        "fix": "X-XSS-Protection: 1; mode=block",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    },
    "Cache-Control": {
        "short": "CC",
        "weight": 7,
        "category": "Cache Security",
        "risk": "MEDIUM",
        "danger": "Without proper cache directives, sensitive pages (dashboards, user profiles) get cached by browsers or proxy servers. Another user on the same device or network can then view cached authenticated pages.",
        "fix": "Cache-Control: no-store, no-cache, must-revalidate, private",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
    },
    "Cross-Origin-Opener-Policy": {
        "short": "COOP",
        "weight": 5,
        "category": "Isolation",
        "risk": "LOW",
        "danger": "Without COOP, malicious sites opened via window.open() can access your window object (window.opener). This enables cross-origin attacks like stealing focus or observing navigation events.",
        "fix": "Cross-Origin-Opener-Policy: same-origin",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
    },
    "Cross-Origin-Resource-Policy": {
        "short": "CORP",
        "weight": 5,
        "category": "Isolation",
        "risk": "LOW",
        "danger": "Without CORP, other origins can load your resources (images, fonts, scripts) into their pages using <img> or <script> tags. This enables cross-origin information leakage via timing attacks.",
        "fix": "Cross-Origin-Resource-Policy: same-origin",
        "learn_more": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
    }
}

TOTAL_MAX_SCORE = sum(h["weight"] for h in SECURITY_HEADERS.values())

# ─────────────────────────────────────────────
# CORE ANALYSIS ENGINE
# ─────────────────────────────────────────────
def analyze_headers(url):
    """
    Fetch HTTP headers from a URL and analyze security posture.
    Returns a detailed report dict.
    """
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    try:
        start_time = time.time()
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "ShieldAnalyzer/1.0 Security Scanner (+https://shield-analyzer.io)"
            }
        )
        response_time = round((time.time() - start_time) * 1000, 2)
        actual_url = response.url
        status_code = response.status_code
        server_header = response.headers.get("Server", "Not disclosed")
        x_powered_by = response.headers.get("X-Powered-By", None)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

    except requests.exceptions.SSLError:
        return {"error": "SSL certificate error. The site may have an invalid certificate.", "url": url}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to the server. Check if the URL is correct.", "url": url}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out after 10 seconds.", "url": url}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "url": url}

    # ── Analyze each security header ──
    found_headers = []
    missing_headers = []
    total_score = 0

    for header_name, meta in SECURITY_HEADERS.items():
        is_present = header_name.lower() in response_headers
        value = response_headers.get(header_name.lower(), None)

        entry = {
            "name": header_name,
            "short": meta["short"],
            "present": is_present,
            "value": value,
            "weight": meta["weight"],
            "category": meta["category"],
            "risk": meta["risk"],
            "danger": meta["danger"],
            "fix": meta["fix"],
            "learn_more": meta["learn_more"]
        }

        if is_present:
            found_headers.append(entry)
            total_score += meta["weight"]
        else:
            missing_headers.append(entry)

    # ── Calculate Score & Grade ──
    score_percent = round((total_score / TOTAL_MAX_SCORE) * 100)

    if score_percent >= 85:
        grade = "A"
        risk_level = "LOW"
        risk_color = "green"
    elif score_percent >= 65:
        grade = "B"
        risk_level = "MODERATE"
        risk_color = "yellow"
    elif score_percent >= 40:
        grade = "C"
        risk_level = "HIGH"
        risk_color = "orange"
    else:
        grade = "F"
        risk_level = "CRITICAL"
        risk_color = "red"

    # ── Information Disclosure Warnings ──
    info_disclosures = []
    if server_header and server_header != "Not disclosed":
        info_disclosures.append({
            "type": "Server Version Exposed",
            "value": server_header,
            "risk": "Exposing server software/version helps attackers target known vulnerabilities for that version."
        })
    if x_powered_by:
        info_disclosures.append({
            "type": "X-Powered-By Exposed",
            "value": x_powered_by,
            "risk": "Reveals backend technology stack (e.g., PHP/7.4), enabling targeted framework exploits."
        })

    # ── Build Final Report ──
    report = {
        "id": str(uuid.uuid4()),
        "url": actual_url,
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "status_code": status_code,
        "response_time_ms": response_time,
        "score": score_percent,
        "grade": grade,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "total_headers_checked": len(SECURITY_HEADERS),
        "headers_present": len(found_headers),
        "headers_missing": len(missing_headers),
        "found_headers": found_headers,
        "missing_headers": missing_headers,
        "info_disclosures": info_disclosures,
        "server": server_header,
        "is_https": actual_url.startswith("https://")
    }

    return report


def save_scan_to_history(report):
    """Persist scan result to history file, keyed by domain."""
    history = load_json(SCAN_HISTORY_FILE)
    domain = report.get("domain", "unknown")

    if domain not in history:
        history[domain] = []

    # Keep last 10 scans per domain
    history[domain].append({
        "id": report["id"],
        "scanned_at": report["scanned_at"],
        "score": report["score"],
        "grade": report["grade"],
        "risk_level": report["risk_level"],
        "headers_present": report["headers_present"],
        "headers_missing": report["headers_missing"],
        "url": report["url"]
    })
    history[domain] = history[domain][-10:]
    save_json(SCAN_HISTORY_FILE, history)


# ─────────────────────────────────────────────
# AUTH HELPERS (Simple hash-based, no DB)
# ─────────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_users():
    return load_json(USERS_FILE)

def save_users(users):
    save_json(USERS_FILE, users)


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the frontend."""
    return send_from_directory("../frontend", "index.html")

# ── Authentication ──

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    users = get_users()
    if username in users:
        return jsonify({"error": "Username already taken"}), 409

    users[username] = {
        "password_hash": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "scan_count": 0
    }
    save_users(users)
    return jsonify({"message": "Account created!", "username": username}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    users = get_users()
    user = users.get(username)

    if not user or user["password_hash"] != hash_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Return a simple session token (username-based, stateless)
    token = hashlib.sha256(f"{username}:{user['password_hash']}:shield".encode()).hexdigest()
    return jsonify({
        "message": "Login successful",
        "token": token,
        "username": username
    })


# ── Core Scan ──

@app.route("/api/scan", methods=["POST"])
def scan():
    """Scan a single URL and return security analysis."""
    data = request.json
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    report = analyze_headers(url)

    if "error" in report:
        return jsonify(report), 400

    # Save to history
    save_scan_to_history(report)

    return jsonify(report)


# ── Comparison ──

@app.route("/api/compare", methods=["POST"])
def compare():
    """Compare security headers of two URLs side by side."""
    data = request.json
    url1 = data.get("url1", "").strip()
    url2 = data.get("url2", "").strip()

    if not url1 or not url2:
        return jsonify({"error": "Both URLs are required"}), 400

    report1 = analyze_headers(url1)
    report2 = analyze_headers(url2)

    if "error" in report1:
        return jsonify({"error": f"Site 1: {report1['error']}"}), 400
    if "error" in report2:
        return jsonify({"error": f"Site 2: {report2['error']}"}), 400

    # Save both to history
    save_scan_to_history(report1)
    save_scan_to_history(report2)

    # Build comparison matrix
    comparison = []
    all_headers = list(SECURITY_HEADERS.keys())

    for header in all_headers:
        h_lower = header.lower()
        in_site1 = any(h["name"] == header and h["present"] for h in report1["found_headers"])
        in_site2 = any(h["name"] == header and h["present"] for h in report2["found_headers"])

        comparison.append({
            "header": header,
            "short": SECURITY_HEADERS[header]["short"],
            "risk": SECURITY_HEADERS[header]["risk"],
            "site1": in_site1,
            "site2": in_site2,
            "winner": "site1" if in_site1 and not in_site2
                      else "site2" if in_site2 and not in_site1
                      else "tie" if in_site1 and in_site2
                      else "none"
        })

    return jsonify({
        "site1": report1,
        "site2": report2,
        "comparison": comparison,
        "winner": report1["domain"] if report1["score"] > report2["score"]
                  else report2["domain"] if report2["score"] > report1["score"]
                  else "tie"
    })


# ── History ──

@app.route("/api/history/<domain>", methods=["GET"])
def get_history(domain):
    """Get scan history for a specific domain."""
    history = load_json(SCAN_HISTORY_FILE)
    domain_history = history.get(domain, [])
    return jsonify({
        "domain": domain,
        "scans": domain_history,
        "total": len(domain_history)
    })


@app.route("/api/history", methods=["GET"])
def get_all_history():
    """Get all scan history (all domains)."""
    history = load_json(SCAN_HISTORY_FILE)
    result = []
    for domain, scans in history.items():
        if scans:
            latest = scans[-1]
            result.append({
                "domain": domain,
                "latest_scan": latest["scanned_at"],
                "latest_score": latest["score"],
                "latest_grade": latest["grade"],
                "scan_count": len(scans)
            })
    # Sort by latest scan
    result.sort(key=lambda x: x["latest_scan"], reverse=True)
    return jsonify(result)


# ── Batch Scan ──

@app.route("/api/batch-scan", methods=["POST"])
def batch_scan():
    """Scan multiple URLs at once (API integration feature)."""
    data = request.json
    urls = data.get("urls", [])

    if not urls:
        return jsonify({"error": "Provide a list of URLs"}), 400
    if len(urls) > 5:
        return jsonify({"error": "Maximum 5 URLs per batch scan"}), 400

    results = []
    for url in urls:
        url = url.strip()
        if url:
            report = analyze_headers(url)
            if "error" not in report:
                save_scan_to_history(report)
            results.append(report)

    # Sort by score descending
    results.sort(key=lambda x: x.get("score", 0), reverse=True)

    return jsonify({
        "total": len(results),
        "results": results,
        "summary": {
            "average_score": round(sum(r.get("score", 0) for r in results) / len(results)),
            "critical_sites": sum(1 for r in results if r.get("risk_level") == "CRITICAL"),
            "secure_sites": sum(1 for r in results if r.get("risk_level") == "LOW")
        }
    })


# ── Health Check ──

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "online", "version": "1.0.0", "name": "ShieldAnalyzer"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
