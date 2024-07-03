"""Script that converts a directory with php code in to an encrypt version of it to be used by the auditor side."""

import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from components.correlator import Correlator
from components.abstractor import Abstractor
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff


def main(secret_password, shared_password, repo_dir, output_dir):

    try:
        if not os.path.exists(repo_dir):
            error = f"{repo_dir} does not exist"
            print(error)
            return 0, error

        if not os.path.exists(output_dir):
            error = f"{output_dir} does not exist"
            return 0, error

        secret_password = crypto_stuff.generate_key(secret_password)
        shared_password = crypto_stuff.generate_key(shared_password)

        data_structure = {}
        lexer = Abstractor()

        found_php_files = False
        for root, dirs, files in os.walk(repo_dir):
            for file in files:
                if file.endswith('.php'):
                    found_php_files = True
                    php_file = os.path.join(root, file)
                    with open(php_file, "r", encoding="utf-8") as data:
                        scope = os.path.basename(php_file)
                        lexer.file_name = scope
                        lexer.input(data.read())
                        lexer.lineno = 1

                        correlator = Correlator(lexer, data_structure, 0, 0, scope, {})
                        correlator.correlate()

        if not found_php_files:
            error = f"No PHP files found in {repo_dir}"
            print(error)
            return 0, error

        encryptor = Encryptor()
        encryptor.encrypt_data_structure(
            data_structure, secret_password, shared_password, output_dir)
    except Exception as e:
        error = f"Error: {e}"
        return 0, error

    success = f"Client side completed successfully!\nOutput file were saved in: {output_dir}/client_side_output"
    print(success)
    return 1, success

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(f"Error: Incorrect number of arguments. Expected {4}, got {len(sys.argv) - 1}.")
        print("Usage: python3 client_side.py <secret_password> <shared_password> <dir> <output_dir>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
