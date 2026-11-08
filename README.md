# VulnLab

A small, deliberately vulnerable Flask web app, built as a personal learning
project while studying for web application penetration testing. It's a
single-user "notes" app with six intentional vulnerabilities hidden in it.

This exists so I could practice finding bugs in something I understand from
the inside, and to write up each one the way a real pentest report would:
what the bug is, how to find it, a proof of concept, and the fix.

**Status:** work in progress — I'm filling in [`VULNERABILITIES.md`](VULNERABILITIES.md)
as I find and confirm each bug myself.

## Running it

Requires Docker.

```bash
git clone <this repo>
cd vulnlab
docker compose up --build
```

Then open `http://localhost:5000`.

Seeded accounts:

| Username | Password |
|---|---|
| alice | alice123 |
| bob | hunter2 |
| admin | SuperSecretAdminPW!2026 |

Without Docker:

```bash
cd app
pip install -r requirements.txt
python app.py
```

## What's in here

A notes app where users can log in, write short notes, search them, and set
a bio on their profile. There's also a "link preview" feature and a file
download endpoint. Six of these features have a real vulnerability behind
them, each marked with a `LAB N` comment in `app/app.py`. Categories, not
spoilers:

- SQL Injection
- Broken Authentication
- Insecure Direct Object Reference (IDOR)
- Stored XSS
- Server-Side Request Forgery (SSRF)
- Path Traversal

Write-ups for each are in [`VULNERABILITIES.md`](VULNERABILITIES.md).

## ⚠️ Ethical use

This app is intentionally broken and should only ever run on `localhost` or
an isolated lab network, against your own instance. Do not deploy it to a
public server or cloud instance with a public IP. Nothing here should be
tried against systems you don't own or don't have explicit written
permission to test.

## Why I built this

I'm starting out in cybersecurity (currently a Cybersecurity Intern, and a
Computer Engineering student). I wanted a project that's genuinely mine —
not a walkthrough of someone else's CTF — to practice the full loop: read
code, spot the bug, exploit it, explain it, fix it.
