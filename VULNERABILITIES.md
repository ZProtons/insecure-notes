# Vulnerability write-ups

Findings from testing my own app, insecure-notes, against itself. Found
independently — I didn't read `app.py` before testing, only afterward to
confirm root cause. Target for all of these: `http://127.0.0.1:5000`,
running locally via `docker compose up`.

---

## 1. SQL Injection — `/search`

**Severity:** High — direct, unauthenticated-to-data-layer injection with no
input validation at all.

**Location:** `GET /search?q=...` (`app/app.py`, `search_notes`)

**Steps to reproduce:**
1. Log in as any user (e.g. `alice` / `alice123`).
2. Go to the dashboard, use the search box, or hit the URL directly:
   `/search?q=' OR '1'='1`

**Proof of concept:**
```
GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<alice's session cookie>
```
Response: returns every note in the database, including notes owned by
`bob` and `admin`, not just the logged-in user's own notes.

**Impact:** The search query is built by directly concatenating the `q`
parameter into a SQL string (`"...WHERE title LIKE '%" + q + "%'"`) instead
of using a parameterized query. This allows an attacker to alter the query
logic entirely — in this case, to read every row in the `notes` table
regardless of ownership. With a more complex payload this could be extended
to read other tables (e.g. `users`, including password hashes) via
`UNION SELECT`.

**Fix:** Use a parameterized query instead of string concatenation:
```python
db.execute("SELECT * FROM notes WHERE title LIKE ?", (f"%{q}%",))
```
Never build SQL strings from user input, even with escaping — parameterized
queries are the actual fix, not a sanitization step.

---

## 2. Insecure Direct Object Reference (IDOR) — `/notes/<id>`

**Severity:** High — any authenticated user can read any other user's
private data, including an admin's.

**Location:** `GET /notes/<note_id>` (`app/app.py`, `view_note`)

**Steps to reproduce:**
1. Log in as `alice` (a non-admin user whose own notes are ids 1–2).
2. Request a note id belonging to another user: `/notes/3`

**Proof of concept:**
```
GET /notes/3 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<alice's session cookie>
```
Response: returns the note titled "Admin reminder" — a note owned by the
`admin` account, containing internal operational information. Alice is
never checked against the note's actual owner.

**Impact:** The route checks only that *a* valid session exists, not that
the session's user owns the requested note. Note ids are sequential
integers, so every note in the system can be enumerated and read by any
logged-in user, including admin-only content.

**Fix:** Check ownership before returning the resource:
```python
note = db.execute(
    "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
    (note_id, user["id"]),
).fetchone()
if note is None:
    abort(404)  # don't reveal whether the note exists for another user
```

---

## 3. Stored XSS — profile bio (`/profile/edit`)

**Severity:** High — persistent, triggers on any visit to the victim's
profile with no interaction beyond viewing the page.

**Location:** `POST /profile/edit`, rendered at `GET /profile/<username>`
(`app/templates/profile.html`)

**Steps to reproduce:**
1. Log in as any user.
2. Go to `/profile/edit` and set the bio to:
   `<script>alert(document.cookie)</script>`
3. Visit `/profile/<your username>` (or have another user visit it).

**Proof of concept:**
```
POST /profile/edit HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<your session cookie>
Content-Type: application/x-www-form-urlencoded

bio=<script>alert(document.cookie)</script>
```
Visiting the resulting profile page executes the script in the browser of
anyone who views it — confirmed by the alert firing and by checking the
page source for the unescaped `<script>` tag.

**Impact:** The bio field is stored as-is and rendered with Jinja's `|safe`
filter, which disables Flask's default auto-escaping. Because this is
*stored* XSS (saved to the database, not reflected from a single request),
every future visitor to that profile — including an admin reviewing user
profiles — would execute the attacker's script. In a real app this could
be used to steal session cookies, perform actions as the victim, or deface
the page.

**Fix:** Remove the `|safe` filter and let Jinja auto-escape the bio by
default:
```
<div class="bio">{{ target['bio'] }}</div>
```
If any HTML formatting in bios is genuinely needed, sanitize with an
allowlist-based library (e.g. `bleach`) server-side before storage, never
trust `|safe` on user-controlled content.

---

## 4. Path Traversal — `/files`

**Severity:** High — arbitrary file read, limited only by the OS
permissions of the process running the app.

**Location:** `GET /files?name=...` (`app/app.py`, `serve_file`)

**Steps to reproduce:**
1. No login required.
2. Request: `/files?name=../../app.py`

**Proof of concept:**
```
GET /files?name=../../app.py HTTP/1.1
Host: 127.0.0.1:5000
```
Response: returns the full source of `app.py`, a file well outside the
intended `static/uploads/` directory. The same technique reaches any file
the server process can read.

**Impact:** The `name` parameter is joined directly onto the uploads
directory path with no validation that the result stays inside that
directory, and the file is read with a plain `open()` call rather than a
framework helper with built-in path-safety checks. An attacker can read
application source code, configuration files, or (depending on OS
permissions) sensitive system files like `/etc/passwd`.

**Fix:** Resolve the final path and verify it's still inside the intended
directory before opening it:
```python
full_path = os.path.realpath(os.path.join(UPLOADS_DIR, name))
if not full_path.startswith(os.path.realpath(UPLOADS_DIR) + os.sep):
    abort(403)
```
Better still, use Flask's `send_from_directory()`, which enforces this
check internally — this app intentionally avoids it to demonstrate the bug.

---

## 5. Server-Side Request Forgery (SSRF) — `/fetch`

**Severity:** Medium (in this app, as tested) — confirmed arbitrary
outbound requests from the server, but does not chain into an auth bypass
in this specific app. Would likely be High on real cloud infrastructure
(see below).

**Location:** `POST /fetch` (`app/app.py`, `fetch_url`)

**Steps to reproduce / proof of concept:**

1. **Unrestricted target confirmed.** Logged in, pointed `/fetch` at
   `169.254.169.254` (the standard AWS/GCP/Azure cloud metadata address):
   ```
   POST /fetch HTTP/1.1
   url=http://169.254.169.254/
   ```
   Result: connection timeout, because this lab isn't running on cloud
   infrastructure. On a real cloud-hosted instance, this exact request
   would typically return instance credentials — this is one of the most
   common high-impact outcomes of SSRF in production. No allowlist or
   denylist on the target host is enforced anywhere in the route.

2. **Tested whether SSRF could bypass the IDOR in finding #2**, by pointing
   `/fetch` at `http://127.0.0.1:5000/notes/3` while logged in as alice in
   my browser. Hypothesis: if the server's outbound request reused my
   session somehow, this would be a full auth bypass chain.
   Result: the response was the **login page**, not the note content. The
   server-side `requests.get()` call is a fresh HTTP request with no
   cookies attached — it does not inherit the browser's session. So this
   specific chain does **not** work in this app.

**Impact:** The server will make an HTTP request to any URL supplied by
the user, with no allowlist, denylist, or restriction on scheme or target
(including internal/private IP ranges). This enables internal network
reconnaissance (probing which internal hosts/ports respond) and, on real
cloud infrastructure, credential theft via the metadata service. It does
not expose session-protected application data in this app, because the
outbound request carries no session state — worth noting precisely because
it's the kind of assumption ("SSRF + IDOR = easy win") that doesn't always
hold and should be tested, not assumed.

**Fix:**
- Maintain an allowlist of permitted destination hosts/schemes rather than
  accepting any URL.
- Explicitly block requests to private/link-local IP ranges
  (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `169.254.0.0/16`), including after any redirect.
- Disable redirect-following on the outbound request, or re-validate the
  target after each redirect.

---

## What I didn't find

I ran `dirb` against `127.0.0.1:5000` and found nothing beyond the app's
own defined routes — no stray debug endpoints, backup files, or `.git`
exposure. Noting this because an empty result is still a result worth
recording, not just the hits.

## Tools used

Browser dev tools, `curl`, manual testing. Burp Suite next — want to get
comfortable with Repeater and Intruder for the next project instead of
hand-writing requests.
