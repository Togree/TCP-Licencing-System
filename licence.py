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
        exp TEXT NOT NULL,
        signature TEXT NOT NULL
    )
""")
conn.commit()


def generate_license(client_id, license_type, duration_days):
    """Generates a signed license and stores it in SQLite."""
    issued_at = datetime.datetime.utcnow()
    expiration_date = issued_at + datetime.timedelta(days=duration_days)

    # License data
    license_data = {
        "client_id": client_id,
        "license_type": license_type,
        "issued_at": issued_at.strftime("%Y-%m-%d %H:%M:%S"),
        "exp": expiration_date.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Convert to JSON and sign
    license_json = json.dumps(license_data)
    signature = rsa.sign(license_json.encode(), private_key, "SHA-256").hex()

    # Store in the database
    try:
        cursor.execute("""
            INSERT INTO licenses (client_id, license_type, issued_at, exp, signature)
            VALUES (?, ?, ?, ?, ?)
        """, (client_id, license_type, license_data["issued_at"], license_data["exp"], signature))
        conn.commit()
        return json.dumps(license_data, indent=4)
    except sqlite3.IntegrityError:
        return "Error: License for this client already exists!"


def get_all_licenses():
    """Retrieves all licenses from the database."""
    cursor.execute("SELECT client_id, license_type, issued_at, exp, signature FROM licenses")
    return cursor.fetchall()


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
        """Handles form submission and license generation."""
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        data = parse_qs(post_data.decode())

        client_id = data.get("client_id", [""])[0]
        license_type = data.get("license_type", [""])[0]
        duration_days = int(data.get("duration_days", [30])[0])

        license_info = generate_license(client_id, license_type, duration_days)

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(self.get_html_form(license_info).encode())

    def get_html_form(self, message=""):
        """Returns an HTML form and license table."""
        licenses = get_all_licenses()
        license_table = """
        <h3>Existing Licenses:</h3>
        <table border='1' cellpadding='5' cellspacing='0'>
            <tr>
                <th>Client ID</th>
                <th>License Type</th>
                <th>Issued At</th>
                <th>Expires At</th>
                <th>Signature</th>
            </tr>
        """
        for license in licenses:
            license_table += f"""
            <tr>
                <td>{license[0]}</td>
                <td>{license[1]}</td>
                <td>{license[2]}</td>
                <td>{license[3]}</td>
                <td>{license[4][:19]}...</td> <!-- Truncate signature for display -->
            </tr>
            """
        license_table += "</table>"

        return f"""
        <html>
        <head><title>License Generator</title></head>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>License Generator</h2>
            <form method="post">
                <label>Client ID (Domain or Name):</label><br>
                <input type="text" name="client_id" required><br><br>

                <label>License Type:</label><br>
                <select name="license_type">
                    <option value="Basic">Basic</option>
                    <option value="Pro">Pro</option>
                    <option value="Enterprise">Enterprise</option>
                </select><br><br>

                <label>Duration (Days):</label><br>
                <input type="number" name="duration_days" value="180" required><br><br>

                <input type="submit" value="Generate License">
            </form>
            {f'<h3>📜 License Details:</h3><pre>{message}</pre>' if message else ''}
            {license_table}
        </body>
        </html>
        """


# Start the server
server_address = ("", 8080)
httpd = HTTPServer(server_address, RequestHandler)
print("🚀 Server running on http://localhost:8080")
httpd.serve_forever()
