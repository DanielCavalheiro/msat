import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from components.abstractor import Abstractor

FILE = "/home/dani/tese/hollingworth_app/xss4.php"

try:
    data = open(FILE, "r", encoding="utf-8")
except FileNotFoundError:
    print("File not found")
else:
    with data:

        lexer = Abstractor()
        lexer.input(data.read())

        while True:
            token = lexer.token()
            if not token:
                break
            print(token)
