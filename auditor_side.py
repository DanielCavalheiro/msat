"""Script that uses the output of the clint side to detect vulnerabilities without revealing them"""
import argparse
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
    except ValueError as e:
        error = f"Wrong password or file is corrupted. Error: {e}"
        print(error)
        return 0, error
    except Exception as e:
        error = f"Error: {e}"
        print(error)
        return 0, error

    success = f"Auditor side completed successfully!\nOutput file were saved in: {output_dir}/auditor_side_output"
    print(success)
    return 1, success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the auditor side of the tool. Requires a file outputted by the client side. This script will detect vulnerabilities without revealing them.")
    parser.add_argument("--shared_password", "-shp", help="The shared password used in detection.",
                        required=True)
    parser.add_argument("--file_path", "-f", help="The path to the client side output. If not passed the current directory is scanned for a file called 'client_side_output'", required=False, default="client_side_output")
    parser.add_argument("--vuln_type", "-v", help="The type of vulnerability to detect, either XSS or SQLI.",
                        required=True, choices=["xss", "sqli"])
    parser.add_argument("--output_dir", "-o", help="Optional directory to save the output file. The default is the current directory.",
                        required=False, default=".")
    args = parser.parse_args()

    main(args.shared_password, args.file_path, args.vuln_type.upper(), args.output_dir)


