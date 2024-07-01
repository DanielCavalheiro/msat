import json
import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from components.detector import Detector
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff
from utils.token_utils import token_decoder

if len(sys.argv) != 5:
    print(f"Error: Incorrect number of arguments. Expected {4}, got {len(sys.argv) - 1}.")
    print("Usage: python3 auditor_side.py <shared_password> <file> <vulnerability_to_detect> <output_dir>")
    sys.exit(1)

SHARED_PASSWORD = crypto_stuff.generate_key(sys.argv[1])

FILE = sys.argv[2]
if not os.path.exists(FILE):
    print(f"{FILE} does not exist")
    sys.exit(1)

VULNERABILITY_TO_DETECT = sys.argv[3].upper()

OUTPUT_DIR = sys.argv[4]
if not os.path.exists(OUTPUT_DIR):
    print(f"{OUTPUT_DIR} does not exist")
    sys.exit(1)

try:
    with open(FILE, "r", encoding="utf-8") as f:
        detector = None
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
        encrypted_ds = json.loads(decrypted_data, object_hook=token_decoder)
        detector = Detector(encrypted_ds, SHARED_PASSWORD)

        if VULNERABILITY_TO_DETECT not in ("XSS", "SQLI"):
            sys.exit("Invalid vulnerability type. Please choose between XSS and SQLI.")
        detector.set_vuln_type(VULNERABILITY_TO_DETECT)
        vulnerable_paths = detector.detect_vulnerability()
        encryptor = Encryptor()
        encryptor.encrypt_result(vulnerable_paths, SHARED_PASSWORD, OUTPUT_DIR)

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

print("Auditor side completed successfully!")
print(f"Output file were saved in -> {OUTPUT_DIR}")
