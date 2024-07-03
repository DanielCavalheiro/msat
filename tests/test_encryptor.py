"""Tests the encryptor component individually"""

import os
import utils.crypto_stuff as crypto_stuff
from components.encryptor import Encryptor
from components.abstractor import Abstractor
from components.correlator import Correlator

ENCRYPT_FLAG = True
DIR = "/home/dani/tese/teseProto1"

data_structure = {}
lexer = Abstractor()

found_php_files = False
for root, dirs, files in os.walk(DIR):
    for file in files:
        if file.endswith('.php'):
            found_php_files = True
            php_file = os.path.join(root, file)
            data = open(php_file, "r", encoding="utf-8")
            with data:
                scope = os.path.basename(php_file)
                lexer.file_name = scope
                lexer.input(data.read())

                correlator = Correlator(lexer, data_structure, 0, 0, scope, {})
                correlator.correlate()
if not found_php_files:
    print(f"No PHP files found in {DIR}")
    exit(0)

encryptor = Encryptor(ENCRYPT_FLAG)
SECRET_PASSWORD = crypto_stuff.generate_key("secret_password")
SHARED_PASSWORD = crypto_stuff.generate_key("shared_password")
encryptor.encrypt_data_structure(data_structure, SECRET_PASSWORD, SHARED_PASSWORD)
