import os
import json
import base64
import rsa
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from django.utils.timezone import now, timedelta

from licenses.models import License

# Get the absolute path of the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define the keys directory path inside the Django project
KEYS_DIR = os.path.join(BASE_DIR, "keys") 

# Define full paths for private and public keys inside "keys/"
RSA_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


# Generate key pair
def generate_rsa_key_pair():
    """Generate system-wide RSA key pair if they don't exist."""
    
    # Ensure the keys directory exists
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)  # Create the directory if it doesn't exist

    print(f"Private Key Path: {RSA_PRIVATE_KEY_PATH}")
    print(f"Public Key Path: {RSA_PUBLIC_KEY_PATH}")

    if not os.path.exists(RSA_PRIVATE_KEY_PATH) or not os.path.exists(RSA_PUBLIC_KEY_PATH):
        # Generate a new RSA key pair (512-bit for compatibility with rsa library)
        public_key, private_key = rsa.newkeys(512)

        try:
            with open(RSA_PRIVATE_KEY_PATH, "wb") as f:
                f.write(private_key.save_pkcs1("PEM"))
            with open(RSA_PUBLIC_KEY_PATH, "wb") as f:
                f.write(public_key.save_pkcs1("PEM"))

            print(f"RSA Key Pair Generated Successfully! Keys saved in {KEYS_DIR}")
        except Exception as e:
            print(f"Error saving keys: {e}")
    else:
        print(f"RSA Key Pair Already Exists in {KEYS_DIR}.")
        try:
            with open(RSA_PRIVATE_KEY_PATH, "rb") as f:
                private_key = rsa.PrivateKey.load_pkcs1(f.read())
            with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
                public_key = rsa.PublicKey.load_pkcs1(f.read())

            print("Loaded existing RSA keys successfully.")
        except Exception as e:
            print(f"Error loading existing keys: {e}")


# Load system-wide key pair
def load_rsa_keys():
    """Load RSA private and public keys in the correct format for the rsa library."""
    if not os.path.exists(RSA_PRIVATE_KEY_PATH) or not os.path.exists(RSA_PUBLIC_KEY_PATH):
        raise FileNotFoundError("RSA key pair not found! Run `generate_rsa_key_pair()` first.")

    # Load private key
    with open(RSA_PRIVATE_KEY_PATH, "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    # Load public key
    with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    return private_key, public_key


# Generate licence
def generate_license(client_id, license_type, exp=None, duration_days=None):
    """
    Generate a signed license for a client.

    :param client_id: Unique identifier for the client.
    :param license_type: Type of license (e.g., 'Standard', 'Premium').
    :param exp: Expiration date in ISO format (optional).
    :param duration_days: Number of days until expiration (optional).
    :return: License model instance.
    """
    private_key, _ = load_rsa_keys()  # Ensure this function correctly loads RSA keys
    issued_at = now()

    # Set expiration date
    if exp:
        try:
            expiration_date = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("Invalid date format. Use ISO 8601 format (e.g., '2025-04-21T12:00:00Z').")
    elif duration_days is not None:
        expiration_date = issued_at + timedelta(days=int(duration_days))
    else:
        expiration_date = None  # Handle Premium case where there's no expiration

    # License data for signing
    license_data = {
        "client_id": client_id,
        "license_type": license_type,
        "issued_at": issued_at.strftime("%Y-%m-%d %H:%M:%S"),
        "exp": expiration_date.strftime("%Y-%m-%d %H:%M:%S") if expiration_date else "Never",
    }

    # Convert to JSON and sign
    license_json = json.dumps(license_data, separators=(',', ':'), sort_keys=True)
    print(f"License JSON used for Signing: {license_json}")

    signature = rsa.sign(license_json.encode(), private_key, "SHA-256").hex()
    print(f"Generated Signature (Hex): {signature}")

    # Save to Django database
    license_obj, created = License.objects.update_or_create(
        client_id=client_id,
        defaults={
            "license_type": license_type,
            "issued_at": issued_at,
            "exp": expiration_date if expiration_date else None,
            "signature": signature,
            "status": "active"
        }
    )

    print(f"License stored in Django DB for client {client_id}.")
    return license_obj  # Return the License model instance instead of JSON


# verify licence
def verify_license(client_id, provided_signature):
    """
    Verify a license by checking its signature and expiration.

    :param client_id: The client's unique identifier.
    :param provided_signature: The signature received for verification (hex-encoded).
    :return: Dictionary with status and message.
    """
    try:
        # Load the system-wide public key
        _, public_key = load_rsa_keys()

        # Fetch the license from Django ORM
        try:
            license_obj = License.objects.get(client_id=client_id)
        except License.DoesNotExist:
            return {"status": "error", "message": "License not found."}

        # Check if the license is revoked
        if license_obj.status == "revoked":
            return {"status": "error", "message": "License is revoked."}

        # Check expiration if it's not a Premium license
        if license_obj.license_type != "Premium" and license_obj.exp is not None:
            if now() > license_obj.exp:
                return {"status": "error", "message": "License has expired."}

        # Reconstruct the original license data
        license_data = {
            "client_id": client_id,
            "license_type": license_obj.license_type,
            "issued_at": license_obj.issued_at.strftime("%Y-%m-%d %H:%M:%S"),
            "exp": license_obj.exp.strftime("%Y-%m-%d %H:%M:%S") if license_obj.exp else "Never"
        }
        license_json = json.dumps(license_data, separators=(',', ':'), sort_keys=True).encode()

        # Convert provided signature to bytes
        provided_signature_bytes = bytes.fromhex(provided_signature)

        # Verify the signature using RSA
        try:
            rsa.verify(license_json, provided_signature_bytes, public_key)
            return {"status": "success", "message": "License is valid."}
        except rsa.VerificationError:
            return {"status": "error", "message": "Invalid signature or license tampered with."}

    except Exception as e:
        return {"status": "error", "message": f"License verification failed: {str(e)}"}


# Revoke licence
def revoke_license(client_id):
    """
    Marks a license as revoked in the Django database.
    
    :param client_id: The client's unique identifier.
    :return: Confirmation message.
    """
    try:
        license_obj = License.objects.get(client_id=client_id)
        license_obj.status = "revoked"
        license_obj.save()
        return {"status": "success", "message": f"License for {client_id} has been revoked."}
    except License.DoesNotExist:
        return {"status": "error", "message": "License not found."}


# Reactivate Licence
def reactivate_license(client_id, additional_days):
    """
    Reactivates an expired/revoked license by extending its validity.
    
    :param client_id: The client's unique identifier.
    :param additional_days: Number of days to extend the license.
    :return: Confirmation message.
    """
    try:
        license_obj = License.objects.get(client_id=client_id)
    except License.DoesNotExist:
        return {"status": "error", "message": "License not found."}

    # Premium licenses do not expire
    if license_obj.license_type == "Premium":
        return {"status": "error", "message": "Premium licenses do not expire."}

    # If the license has no expiration date
    if license_obj.exp == "Never":
        return {"status": "error", "message": "This license does not have an expiration date."}

    # Extend the expiration date
    expiration_date = datetime.strptime(license_obj.exp, "%Y-%m-%d %H:%M:%S")
    new_expiration_date = expiration_date + timedelta(days=additional_days)
    license_obj.exp = new_expiration_date.strftime("%Y-%m-%d %H:%M:%S")
    license_obj.status = "active"  # Reactivate the license
    license_obj.save()

    return {
        "status": "success",
        "message": f"License for {client_id} reactivated until {license_obj.exp}."
    }

# Run this when Django starts to ensure the keys exist
generate_rsa_key_pair()
