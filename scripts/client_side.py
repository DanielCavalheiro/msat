import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from components.correlator import Correlator
from components.abstractor import Abstractor
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff

if len(sys.argv) != 5:
    print(f"Error: Incorrect number of arguments. Expected {4}, got {len(sys.argv) - 1}.")
    print("Usage: python3 client_side.py <secret_password> <shared_password> <dir> <output_dir>")
    sys.exit(1)

SECRET_PASSWORD = crypto_stuff.generate_key(sys.argv[1])
SHARED_PASSWORD = crypto_stuff.generate_key(sys.argv[2])

DIR = sys.argv[3]
if not os.path.exists(DIR):
    print(f"{DIR} does not exist")
    sys.exit(1)

OUTPUT_DIR = sys.argv[4]
if not os.path.exists(OUTPUT_DIR):
    print(f"{OUTPUT_DIR} does not exist")
    sys.exit(1)

data_structure = {}
lexer = Abstractor()

try:
    for root, dirs, files in os.walk(DIR):
        for file in files:
            if file.endswith('.php'):
                php_file = os.path.join(root, file)
                with open(php_file, "r", encoding="utf-8") as data:
                    scope = os.path.basename(php_file)
                    lexer.file_name = scope
                    lexer.input(data.read())
                    lexer.lineno = 1

                    correlator = Correlator(lexer, data_structure, 0, 0, scope, {})
                    correlator.correlate()

    encryptor = Encryptor()
    encryptor.encrypt_data_structure(
        data_structure, SECRET_PASSWORD, SHARED_PASSWORD, OUTPUT_DIR)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

print("Client side completed successfully!")
print(f"Output file were saved in -> {OUTPUT_DIR}")
