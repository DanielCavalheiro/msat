from lexer import *


def tokenize(file):
    try:
        data = open(file, 'r')
    except FileNotFoundError:
        print("File not found")
    else:
        with data:
            lexer = FilteredLexer(lex.lex())
            lexer.input(data.read())

            while True:
                token = lexer.token()
                if not token:
                    break
                print(token)


if __name__ == '__main__':
    f = "C:/Users/danie/OneDrive/uni/5ºano/tese/hollingworth_app/signup.php"
    tokenize(f)
