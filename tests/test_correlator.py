import sys
import os
from components.abstractor import Abstractor
from components.correlator import Correlator

DIR = "/home/dani/tese/hollingworth_app/testing_dir"
data_structure = {}
lexer = Abstractor()
for root, dirs, files in os.walk(DIR):
    for file in files:
        if file.endswith('.php'):
            php_file = os.path.join(root, file)
            data = open(php_file, "r", encoding="utf-8")
            with data:
                scope = os.path.basename(php_file)
                lexer.file_name = scope
                lexer.input(data.read())

                correlator = Correlator(lexer, data_structure, 0, 0, scope, {})
                correlator.correlate()

for scope, values in data_structure.items():
    print(scope)
    for k, vs in values.items():
        print("\t" + k)
        for v in vs:
            print("\t\t - " + str(v))