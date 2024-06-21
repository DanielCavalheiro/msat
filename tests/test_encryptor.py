from components.correlator import Correlator
from components.abstractor import Abstractor
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff
import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


FILE = "/home/dani/tese/hollingworth_app/xss6.php"
ENCRYPT_FLAG = True


try:
    data = open(FILE, "r", encoding="utf-8")
except FileNotFoundError:
    print("File not found")
else:
    with data:

        scope = os.path.basename(FILE)
        lexer = Abstractor(scope)
        lexer.input(data.read())

        correlator = Correlator(lexer, {}, 0, 0, scope, {})
        correlator.correlate()

        encryptor = Encryptor(ENCRYPT_FLAG)
        SECRET_PASSWORD = crypto_stuff.generate_key("secret_password")
        SHARED_PASSWORD = crypto_stuff.generate_key("shared_password")
        encryptor.encrypt_data_structure(
            correlator.data_structure, SECRET_PASSWORD, SHARED_PASSWORD)
