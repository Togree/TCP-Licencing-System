import json
import datetime
import rsa
import sqlite3
import os
from urllib.parse import parse_qs
from http.server import SimpleHTTPRequestHandler, HTTPServer

# Check if RSA keys exist, otherwise generate them
if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
    (public_key, private_key) = rsa.newkeys(512)
    with open("private.pem", "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))
    with open("public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
else:
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

# Database Connection
conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
cursor = conn.cursor()

# Create table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT UNIQUE NOT NULL,
        license_type TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        exp TEXT,
        signature TEXT NOT NULL,
        status TEXT DEFAULT 'active'
    )
""")
conn.commit()


# Generate licence function
def generate_license(client_id, license_type, duration_days):
    """Generates a signed license and stores it in SQLite."""
    issued_at = datetime.datetime.utcnow()
    expiration_date = None if license_type == "Premium" else issued_at + datetime.timedelta(days=duration_days)

    # License data
    license_data = {
        "client_id": client_id,
        "license_type": license_type,
        "issued_at": issued_at.strftime("%Y-%m-%d %H:%M:%S"),
        "exp": "Never" if expiration_date is None else expiration_date.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Convert to JSON and sign
    license_json = json.dumps(license_data)
    signature = rsa.sign(license_json.encode(), private_key, "SHA-256").hex()

    # Store in the database
    try:
        cursor.execute("""
            INSERT INTO licenses (client_id, license_type, issued_at, exp, signature, status)
            VALUES (?, ?, ?, ?, ?, 'active')
        """, (client_id, license_type, license_data["issued_at"], license_data["exp"], signature))
        conn.commit()
        return json.dumps(license_data, indent=4)
    except sqlite3.IntegrityError:
        return "Error: License for this client already exists!"


# Revoke licence function
def revoke_license(client_id):
    """Marks a license as revoked."""
    cursor.execute("UPDATE licenses SET status = 'revoked' WHERE client_id = ?", (client_id,))
    conn.commit()
    return f"License for {client_id} has been revoked."


# Validate licence
def validate_license(client_id, provided_signature):
    """Validates a license using the client-provided signature."""
    cursor.execute("SELECT license_type, issued_at, exp, signature, status FROM licenses WHERE client_id = ?", (client_id,))
    license = cursor.fetchone()

    if not license:
        return {"status": "error", "message": "License not found."}

    license_type, issued_at, exp_date, stored_signature, status = license

    if status == "revoked":
        return {"status": "error", "message": "License is revoked."}

    if license_type != "Premium" and exp_date != "Never":
        expiration = datetime.datetime.strptime(exp_date, "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.utcnow() > expiration:
            return {"status": "error", "message": "License has expired."}

    license_data = {
        "client_id": client_id,
        "license_type": license_type,
        "issued_at": issued_at,
        "exp": exp_date
    }
    license_json = json.dumps(license_data)

    try:
        if provided_signature != stored_signature:
            return {"status": "error", "message": "Signature mismatch."}

        rsa.verify(license_json.encode(), bytes.fromhex(provided_signature), public_key)
        return {"status": "success", "message": "License is valid."}

    except rsa.VerificationError:
        return {"status": "error", "message": "Invalid signature or license tampered with."}


# Reactivate licence function
def reactivate_license(client_id, additional_days):
    """Reactivates an expired/revoked license by extending its validity."""
    cursor.execute("SELECT exp, license_type FROM licenses WHERE client_id = ?", (client_id,))
    license = cursor.fetchone()

    if not license:
        return "Error: License not found."

    exp_date, license_type = license

    if license_type == "Premium":
        return "Premium licenses do not expire."

    if exp_date == "Never":
        return "This license does not have an expiration date."

    new_expiration = datetime.datetime.strptime(exp_date, "%Y-%m-%d %H:%M:%S") + datetime.timedelta(days=additional_days)
    new_exp_str = new_expiration.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("UPDATE licenses SET exp = ?, status = 'active' WHERE client_id = ?", (new_exp_str, client_id))
    conn.commit()
    return f"License for {client_id} reactivated until {new_exp_str}."


# List all licence
def get_all_licenses():
    """Retrieves all licenses from the database."""
    cursor.execute("SELECT client_id, license_type, issued_at, exp, signature, status FROM licenses")
    return cursor.fetchall()


# Render html
class RequestHandler(SimpleHTTPRequestHandler):
    """Handles HTTP GET and POST requests."""

    def do_GET(self):
        """Serves the HTML form and license table."""
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.get_html_form().encode())

    def do_POST(self):
        """Handles license validation via JSON request."""
        if self.path == "/validate_license":  # Ensure it's the correct endpoint
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data)
                client_id = data.get("client_id")
                provided_signature = data.get("signature")

                if not client_id or not provided_signature:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing client_id or signature"}).encode())
                    return

                # Call the validate_license function
                response = validate_license(client_id, provided_signature)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())

            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON format"}).encode())
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())

    def do_POST(self):
        """Handles form submission, license generation, revocation, reactivation, and validation."""
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        data = parse_qs(post_data.decode())

        action = data.get("action", [""])[0]
        client_id = data.get("client_id", [""])[0]

        if action == "generate":
            license_type = data.get("license_type", [""])[0]
            duration_days = int(data.get("duration_days", [30])[0])
            message = generate_license(client_id, license_type, duration_days)
        elif action == "revoke":
            message = revoke_license(client_id)
        elif action == "reactivate":
            additional_days = int(data.get("additional_days", [30])[0])
            message = reactivate_license(client_id, additional_days)
        else:
            message = "Invalid action!"

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(self.get_html_form(message).encode())

    def get_html_form(self, message=""):
        """Returns an HTML form and license table."""
        licenses = get_all_licenses()
        license_table = """
        <h3>Existing Licenses:</h3>
        <table border='1' cellpadding='5' cellspacing='0'>
            <tr>
                <th>Client ID</th>
                <th>License Type</th>
                <th>Signature</th>
                <th>Issued At</th>
                <th>Expires At</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        """
        for license in licenses:
            client_id = license[0]
            license_table += f"""
            <tr>
                <td>{client_id}</td>
                <td>{license[1]}</td>
                <td>{license[4][:32]}...</td>
                <td>{license[2]}</td>
                <td>{license[3]}</td>
                <td>{license[5]}</td>
                <td>
                    <form method="post" style="display:inline;">
                        <input type="hidden" name="client_id" value="{client_id}">
                        <input type="hidden" name="action" value="revoke">
                        <input type="submit" value="Revoke">
                    </form>
                    <form method="post" style="display:inline;">
                        <input type="hidden" name="client_id" value="{client_id}">
                        <input type="hidden" name="action" value="reactivate">
                        <input type="submit" value="Reactivate">
                        <input type="number" name="additional_days" value="30">
                    </form>
                </td>
            </tr>
            """
        license_table += "</table>"

        return f"""
        <html>
        <head><title>License Manager</title></head>
        <body>
            <h2>License Generator</h2>
            <form method="post">
                <label>Client ID:</label><br>
                <input type="text" name="client_id" required><br><br>

                <label>License Type:</label><br>
                <select name="license_type">
                    <option value="Basic">Basic</option>
                    <option value="Pro">Pro</option>
                    <option value="Enterprise">Enterprise</option>
                    <option value="Premium">Premium</option>
                </select><br><br>

                <label>Duration (Days):</label><br>
                <input type="number" name="duration_days" value="90" required><br><br>

                <input type="hidden" name="action" value="generate">
                <input type="submit" value="Generate License">
            </form>
            {f'<h3>Message:</h3><pre>{message}</pre>' if message else ''}
            {license_table}
        </body>
        </html>
        """


# Start the server
server_address = ("", 8000)
httpd = HTTPServer(server_address, RequestHandler)
print("🚀 Server running on http://localhost:8000")
httpd.serve_forever()
