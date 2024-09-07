"""Tests the correlator component individually"""

import sys
import os
from components.abstractor import Abstractor
from components.correlator import Correlator

DIR = "/home/dani/tese/hollingworth_app/testing_dir"
data_structure = {}
lexer = Abstractor()

found_php_files = False
for root, dirs, files in os.walk(DIR):
    for file in files:
        if file.endswith('.php'):
            found_php_files = True
            php_file = os.path.join(root, file)
            data = open(php_file, "r", encoding="latin-1")
            with data:
                scope = os.path.basename(php_file)
                lexer.file_name = scope
                lexer.input(data.read())
                lexer.lineno = 1

                correlator = Correlator(lexer, data_structure, 0, 0, scope, {}, php_file)
                correlator.correlate()

if not found_php_files:
    print(f"No PHP files found in {DIR}")
    sys.exit(0)

for scope, values in data_structure.items():
    print(scope)
    for k, vs in values.items():
        print("\t" + k)
        for v in vs:
            print("\t\t - " + str(v))