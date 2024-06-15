import sys
import os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))
from components.correlator import Correlator
from components.abstractor import Abstractor


FILE = "/home/dani/tese/hollingworth_app/xss3.php"

try:
    data = open(FILE, "r", encoding="utf-8")
except FileNotFoundError:
    print("File not found")
else:
    with data:
        scope = os.path.basename(FILE)
        lexer = Abstractor(scope)
        lexer.input(data.read())

        scope = os.path.basename(FILE)
        correlator = Correlator(lexer, {}, 0, 0, scope, {})
        correlator.correlate()

        data_structure = correlator.data_structure

        for scope, values in data_structure.items():
            print(scope)
            for k, vs in values.items():
                print("\t" + k)
                for v in vs:
                    print("\t\t - " + str(v))
