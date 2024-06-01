import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from components.correlator import Correlator
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

        correlator = Correlator(lexer, {}, 0, 0, 0, {})
        correlator.correlate()

        data_structure = correlator.data_structure

        for k, vs in data_structure.items():
            print(k)
            for v in vs:
                print("\t - " + str(v))
