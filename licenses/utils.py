import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from licenses.models import License

# Get the absolute path of the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define the keys directory path inside the Django project
KEYS_DIR = os.path.join(BASE_DIR, "keys")

# Define full paths for private and public keys inside "keys/"
RSA_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


def generate_rsa_key_pair():
    """Generate system-wide RSA key pair if they don't exist."""

    # Ensure the keys directory exists
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)  # Create the directory if it doesn't exist

    # Debugging: Print where the keys will be stored
    print(f"🔍 Private Key Path: {RSA_PRIVATE_KEY_PATH}")
    print(f"🔍 Public Key Path: {RSA_PUBLIC_KEY_PATH}")

    if not os.path.exists(RSA_PRIVATE_KEY_PATH) or not os.path.exists(RSA_PUBLIC_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save keys inside the "keys/" directory
        try:
            with open(RSA_PRIVATE_KEY_PATH, "wb") as f:
                f.write(private_pem)
            with open(RSA_PUBLIC_KEY_PATH, "wb") as f:
                f.write(public_pem)

            print(f"✅ RSA Key Pair Generated Successfully! Keys saved in {KEYS_DIR}")
        except Exception as e:
            print(f"❌ Error saving keys: {e}")
    else:
        print(f"⚠️ RSA Key Pair Already Exists in {KEYS_DIR}.")


def load_rsa_keys():
    """Load RSA private and public keys from files."""
    if not os.path.exists(RSA_PRIVATE_KEY_PATH) or not os.path.exists(RSA_PUBLIC_KEY_PATH):
        raise FileNotFoundError("RSA key pair not found! Run `generate_rsa_key_pair()` first.")

    with open(RSA_PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
        public_key = private_key.public_key()

    return private_key, public_key


def generate_license(client_id, license_type, exp=None):
    """
    Generate a signed license for a client.

    :param client_id: Unique identifier for the client.
    :param license_type: Type of license (e.g., 'pro', 'enterprise').
    :param exp: Expiry date (optional).
    :return: License object.
    """
    private_key, _ = load_rsa_keys()  # Load system-wide private key

    # Create license data
    license_data = {
        "client_id": client_id,
        "license_type": license_type,
        "issued_at": str(datetime.utcnow()),  # Use UTC timestamp
        "exp": str(exp) if exp else None
    }

    # Convert to JSON string
    license_json = json.dumps(license_data, separators=(',', ':'))

    # Sign the license data
    signature = private_key.sign(
        license_json.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Encode signature in base64 for easy storage
    signature_b64 = base64.b64encode(signature).decode()

    # Save to the database
    license_obj = License.objects.create(
        client_id=client_id,
        license_type=license_type,
        exp=exp,
        signature=signature_b64
    )

    return license_obj


def verify_license(license_obj):
    """
    Verify a license by checking its signature.

    :param license_obj: License object from the database.
    :return: True if valid, False otherwise.
    """
    _, public_key = load_rsa_keys()  # Load system-wide public key

    # Reconstruct the original license data
    license_data = {
        "client_id": license_obj.client_id,
        "license_type": license_obj.license_type,
        "issued_at": str(license_obj.issued_at),
        "exp": str(license_obj.exp) if license_obj.exp else None
    }

    # Convert to JSON
    license_json = json.dumps(license_data, separators=(',', ':'))

    try:
        # Decode the stored signature from base64
        signature_bytes = base64.b64decode(license_obj.signature)

        # Verify the signature
        public_key.verify(
            signature_bytes,
            license_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return True  # License is valid

    except Exception as e:
        print(f"License verification failed: {e}")
        return False  # License is invalid


# Run this when Django starts to ensure the keys exist
generate_rsa_key_pair()
