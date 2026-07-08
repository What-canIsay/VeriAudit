"""Intentionally vulnerable Flask app (for VeriAudit demo ONLY).

Contains multiple planted vulnerabilities with clear source->sink flows and
web entry points so the reachability gate and evidence chains are exercised.
DO NOT deploy.
"""
import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"  # VULN: CWE-798 hardcoded secret


@app.route("/lookup")
def lookup():
    host = request.args.get("host")
    # VULN: CWE-78 command injection (source: request.args -> sink: subprocess shell=True)
    out = subprocess.check_output("nslookup " + host, shell=True)
    return out


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN: CWE-89 SQL injection (string-formatted query)
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
    return str(cur.fetchall())


@app.route("/download")
def download():
    name = request.args.get("file")
    # VULN: CWE-22 path traversal (user input concatenated into a file path)
    return open("/var/data/" + name).read()


@app.route("/render")
def render():
    tmpl = request.args.get("tmpl", "")
    # VULN: CWE-79 reflected XSS (unescaped reflection)
    return "<div>" + tmpl + "</div>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
