import os
import sys
from components.correlator import Correlator
from components.abstractor import Abstractor
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff

ENCRYPT_FLAG = True
SECRET_PASSWORD = crypto_stuff.generate_key(sys.argv[1])
SHARED_PASSWORD = crypto_stuff.generate_key(sys.argv[2])
DIR = sys.argv[3]
OUTPUT_DIR = sys.argv[4]

data_structure = {}
lexer = Abstractor()
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

encryptor = Encryptor(ENCRYPT_FLAG)
print(OUTPUT_DIR)
encryptor.encrypt_data_structure(
    data_structure, SECRET_PASSWORD, SHARED_PASSWORD, OUTPUT_DIR)
