import json
import sys
import os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))
from components.detector import Detector
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff
from utils.token_utils import token_decoder


def main(shared_password, file, vulnerability_to_detect, output_dir):
    shared_password = crypto_stuff.generate_key(shared_password)

    if not os.path.exists(file):
        error = f"{file} does not exist"
        print(error)
        return 0, error

    vulnerability_to_detect = vulnerability_to_detect.upper()

    if not os.path.exists(output_dir):
        error = f"{output_dir} does not exist"
        return 0, error

    try:
        with open(file, "r", encoding="utf-8") as f:
            decrypted_data = crypto_stuff.decrypt_gcm(f.read(), shared_password)
            encrypted_ds = json.loads(decrypted_data, object_hook=token_decoder)
            detector = Detector(encrypted_ds, shared_password)

            if vulnerability_to_detect not in ("XSS", "SQLI"):
                sys.exit("Invalid vulnerability type. Please choose between XSS and SQLI.")
            detector.set_vuln_type(vulnerability_to_detect)
            vulnerable_paths = detector.detect_vulnerability()
            encryptor = Encryptor()
            encryptor.encrypt_result(vulnerable_paths, shared_password, output_dir)

    except Exception as e:
        error = f"Error: {e}"
        print(error)
        return 0, error

    success = f"Auditor side completed successfully!\nOutput file were saved in: {output_dir}/auditor_side_output"
    print(success)
    return 1, success


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(f"Error: Incorrect number of arguments. Expected {4}, got {len(sys.argv) - 1}.")
        print("Usage: python3 auditor_side.py <shared_password> <file> <vulnerability_to_detect> <output_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])


