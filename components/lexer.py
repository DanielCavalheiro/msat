"""Module for Lexer rules"""

# module: lexer.py
# This module just contains the lexing rules. Adapted from viraptor/phply

import re
import yaml
from ply.lex import TOKEN

states = (
    ('php', 'exclusive'),
    ('quoted', 'exclusive'),
    ('quotedvar', 'exclusive'),
    ('varname', 'exclusive'),
    ('offset', 'exclusive'),
    ('property', 'exclusive'),
    ('heredoc', 'exclusive'),
    ('heredocvar', 'exclusive'),
    ('nowdoc', 'exclusive'),
    ('backticked', 'exclusive'),
    ('backtickedvar', 'exclusive'),
)

# Reserved words
reserved = (  # ECHO was removed from this list
    'ARRAY', 'AS', 'BREAK', 'CASE', 'CLASS', 'CONST', 'CONTINUE', 'DECLARE',
    'DEFAULT', 'DIE', 'DO', 'ELSE', 'ELSEIF', 'EMPTY', 'ENDDECLARE',
    'ENDFOR', 'ENDFOREACH', 'ENDIF', 'ENDSWITCH', 'ENDWHILE', 'EVAL', 'EXIT',
    'EXTENDS', 'FOR', 'FOREACH', 'FUNCTION', 'GLOBAL', 'IF', 'INCLUDE',
    'INCLUDE_ONCE', 'INSTANCEOF', 'ISSET', 'LIST', 'NEW', 'PRINT', 'REQUIRE',
    'REQUIRE_ONCE', 'RETURN', 'STATIC', 'SWITCH', 'UNSET', 'USE', 'VAR',
    'WHILE', 'FINAL', 'INTERFACE', 'IMPLEMENTS', 'PUBLIC', 'PRIVATE',
    'PROTECTED', 'ABSTRACT', 'CLONE', 'TRY', 'CATCH', 'THROW', 'NAMESPACE',
    'FINALLY', 'TRAIT', 'YIELD'
)

# Not used for analysis purposes
filtered = (
    # Invisible characters
    'WHITESPACE',

    # Open and close tags
    'OPEN_TAG', 'OPEN_TAG_WITH_ECHO', 'CLOSE_TAG',

    # Comments
    'COMMENT', 'DOC_COMMENT',

    # Delimiters
    'COMMA',

    # Escaping from HTML
    'INLINE_HTML',

    # Backtick
    'BACKTICK',

)

tokens = reserved + filtered + (
    # # Operators
    # 'PLUS', 'MINUS', 'MUL', 'DIV', 'MOD', 'AND', 'OR', 'NOT', 'XOR', 'SL',
    # 'SR', 'BOOLEAN_AND', 'BOOLEAN_OR', 'BOOLEAN_NOT', 'IS_SMALLER',
    # 'IS_GREATER', 'IS_SMALLER_OR_EQUAL', 'IS_GREATER_OR_EQUAL', 'IS_EQUAL',
    # 'IS_NOT_EQUAL', 'IS_IDENTICAL', 'IS_NOT_IDENTICAL',

    # # Assignment operators
    # 'EQUALS', 'MUL_EQUAL', 'DIV_EQUAL', 'MOD_EQUAL', 'PLUS_EQUAL',
    # 'MINUS_EQUAL', 'SL_EQUAL', 'SR_EQUAL', 'AND_EQUAL', 'OR_EQUAL',
    # 'XOR_EQUAL', 'CONCAT_EQUAL',

    # # Increment/decrement
    # 'INC', 'DEC',

    # All above operators are replaced by the following
    'OPERATOR',

    # Arrows
    'OBJECT_OPERATOR', 'DOUBLE_ARROW', 'DOUBLE_COLON',

    'VARIABLE',

    # Delimiters
    'LPAREN', 'RPAREN', 'LBRACKET', 'RBRACKET', 'LBRACE', 'RBRACE', 'DOLLAR',
    'CONCAT', 'QUESTION', 'COLON', 'SEMI', 'AT', 'NS_SEPARATOR', 'QUOTE',

    # Casts
    'ARRAY_CAST', 'BINARY_CAST', 'BOOL_CAST', 'DOUBLE_CAST', 'INT_CAST',
    'OBJECT_CAST', 'STRING_CAST', 'UNSET_CAST',

    # Identifiers and reserved words
    'DIR', 'FILE', 'LINE', 'FUNC_C', 'CLASS_C', 'METHOD_C', 'NS_C',
    'LOGICAL_AND', 'LOGICAL_OR', 'LOGICAL_XOR',
    'HALT_COMPILER',
    'STRING',
    'LNUMBER', 'DNUMBER', 'NUM_STRING',
    'CONSTANT_ENCAPSED_STRING', 'ENCAPSED_AND_WHITESPACE',
    'DOLLAR_OPEN_CURLY_BRACES', 'STRING_VARNAME', 'CURLY_OPEN',

    # Heredocs
    'START_HEREDOC', 'END_HEREDOC',

    # Nowdocs
    'START_NOWDOC', 'END_NOWDOC',

    # Useful for analysis
    'INPUT', 'XSS_SENS', 'XSS_SANF', 'SQLI_SENS', 'SQLI_SANF',

    # Import (require, include, require_once, include_once)
    'IMPORT'
)


# Newlines


def t_php_WHITESPACE(t):
    r'[ \t\r\n]+'
    t.lexer.lineno += t.value.count("\n")
    return t


def t_php_OBJECT_OPERATOR(t):
    r'->'
    if re.match(r'[A-Za-z_]', peek(t.lexer)):
        t.lexer.push_state('property')
    return t


# Delimeters
t_php_LPAREN = r'\('
t_php_RPAREN = r'\)'
t_php_DOLLAR = r'\$'
t_php_COMMA = r','
t_php_CONCAT = r'\.(?!\d|=)'
t_php_QUESTION = r'\?'
t_php_COLON = r':'
t_php_SEMI = r';'
t_php_AT = r'@'
t_php_NS_SEPARATOR = r'\\'


def t_php_LBRACKET(t):
    r'\['
    t.lexer.push_state('php')
    return t


def t_php_RBRACKET(t):
    r'\]'
    t.lexer.pop_state()
    return t


def t_php_LBRACE(t):
    r'\{'
    t.lexer.push_state('php')
    return t


def t_php_RBRACE(t):
    r'\}'
    t.lexer.pop_state()
    return t


# Casts
t_php_ARRAY_CAST = r'\([ \t]*[Aa][Rr][Rr][Aa][Yy][ \t]*\)'
t_php_BINARY_CAST = r'\([ \t]*[Bb][Ii][Nn][Aa][Rr][Yy][ \t]*\)'
t_php_BOOL_CAST = r'\([ \t]*[Bb][Oo][Oo][Ll]([Ee][Aa][Nn])?[ \t]*\)'
t_php_DOUBLE_CAST = r'\([ \t]*([Rr][Ee][Aa][Ll]|[Dd][Oo][Uu][Bb][Ll][Ee]|[Ff][Ll][Oo][Aa][Tt])[ \t]*\)'
t_php_INT_CAST = r'\([ \t]*[Ii][Nn][Tt]([Ee][Gg][Ee][Rr])?[ \t]*\)'
t_php_OBJECT_CAST = r'\([ \t]*[Oo][Bb][Jj][Ee][Cc][Tt][ \t]*\)'
t_php_STRING_CAST = r'\([ \t]*[Ss][Tt][Rr][Ii][Nn][Gg][ \t]*\)'
t_php_UNSET_CAST = r'\([ \t]*[Uu][Nn][Ss][Ee][Tt][ \t]*\)'


# Comments

def t_php_DOC_COMMENT(t):
    r'/\*\*(.|\n)*?\*/'
    t.lexer.lineno += t.value.count("\n")
    return t


def t_php_COMMENT(t):
    r'/\*(.|\n)*?\*/ | //([^?%\n]|[?%](?!>))*\n? | \#([^?%\n]|[?%](?!>))*\n?'
    t.lexer.lineno += t.value.count("\n")
    return t


# Operators

# t_php_PLUS = r'\+'
# t_php_MINUS = r'-'
# t_php_MUL = r'\*'
# t_php_DIV = r'/'
# t_php_MOD = r'%'
# t_php_AND = r'&'
# t_php_OR = r'\|'
# t_php_NOT = r'~'
# t_php_XOR = r'\^'
# t_php_SL = r'<<'
# t_php_SR = r'>>'
# t_php_BOOLEAN_AND = r'&&'
# t_php_BOOLEAN_OR = r'\|\|'
# t_php_BOOLEAN_NOT = r'!'
# t_php_IS_SMALLER = r'<'
# t_php_IS_GREATER = r'>'
# t_php_IS_SMALLER_OR_EQUAL = r'<='
# t_php_IS_GREATER_OR_EQUAL = r'>='
# t_php_IS_EQUAL = r'=='
# t_php_IS_NOT_EQUAL = r'(!=(?!=))|(<>)'
# t_php_IS_IDENTICAL = r'==='
# t_php_IS_NOT_IDENTICAL = r'!=='
#
# # Assignment operators
# t_php_EQUALS = r'='
# t_php_MUL_EQUAL = r'\*='
# t_php_DIV_EQUAL = r'/='
# t_php_MOD_EQUAL = r'%='
# t_php_PLUS_EQUAL = r'\+='
# t_php_MINUS_EQUAL = r'-='
# t_php_SL_EQUAL = r'<<='
# t_php_SR_EQUAL = r'>>='
# t_php_AND_EQUAL = r'&='
# t_php_OR_EQUAL = r'\|='
# t_php_XOR_EQUAL = r'\^='
# t_php_CONCAT_EQUAL = r'\.='
#
# # Increment/decrement
# t_php_INC = r'\+\+'
# t_php_DEC = r'--'
#
# # Arrows
# t_php_DOUBLE_ARROW = r'=>'
# t_php_DOUBLE_COLON = r'::'


operator_patterns = [
    r'===', r'!==', r'<<=', r'>>=', r'<=', r'>=', r'==', r'(!=(?!=))|(<>)',
    r'\*=', r'/=', r'%=', r'\+=', r'-=',
    r'&=', r'\|=', r'\^=', r'\.=', r'\+\+', r'--', r'=>', r'::',
    r'=', r'\+', r'-', r'\*', r'/', r'%', r'&', r'\|', r'~', r'\^', r'<<', r'>>',
    r'&&', r'\|\|', r'!', r'<', r'>',
]


@TOKEN('|'.join(operator_patterns))
def t_php_OPERATOR(t):
    return t


# Escaping from HTML

def t_OPEN_TAG(t):
    r'<[?%](([Pp][Hh][Pp][ \t\r\n]?)|=)?'
    if '=' in t.value:
        t.type = 'XSS_SENS'  # This is the same as echo statement, so it's a xss sensitive sink
    t.lexer.lineno += t.value.count("\n")
    t.lexer.begin('php')
    return t


def t_php_CLOSE_TAG(t):
    r'[?%]>\r?\n?'
    t.lexer.lineno += t.value.count("\n")
    t.lexer.begin('INITIAL')
    return t


def t_INLINE_HTML(t):
    r'([^<]|<(?![?%]))+'
    t.lexer.lineno += t.value.count("\n")
    return t


# Identifiers and reserved words

reserved_map = {
    '__DIR__': 'DIR',
    '__FILE__': 'FILE',
    '__LINE__': 'LINE',
    '__FUNCTION__': 'FUNC_C',
    '__CLASS__': 'CLASS_C',
    '__METHOD__': 'METHOD_C',
    '__NAMESPACE__': 'NS_C',

    'AND': 'LOGICAL_AND',
    'OR': 'LOGICAL_OR',
    'XOR': 'LOGICAL_XOR',

    '__HALT_COMPILER': 'HALT_COMPILER',
}

tainted_variables = []
with open('../components/knowledge_source.yaml', encoding='utf-8') as file:
    try:
        knowledge = yaml.safe_load(file)

        tainted_variables = knowledge['input']

        vulnerabilities = knowledge['vulnerabilities']
        for vulnerability in vulnerabilities:
            name = vulnerability['name']

            for sink in vulnerability['sensitive_sinks']:
                reserved_map[str(sink).upper()] = (name + '_SENS').upper()

            for sanitizer in vulnerability['sanitization_functions']:
                reserved_map[sanitizer.upper()] = (name + '_SANF').upper()

    except yaml.YAMLError as exc:
        print(exc)

for r in reserved:
    reserved_map[r] = r


def t_php_IMPORT(t):
    r'(include|require|include_once|require_once)\b'
    return t


# Identifier
def t_php_STRING(t):
    r'[A-Za-z_][\w_]*'
    t.type = reserved_map.get(t.value.upper(), 'STRING')

    return t


# Variable
def t_php_VARIABLE(t):
    r'\$[A-Za-z_][\w_]*'
    if t.value in tainted_variables:
        t.type = 'INPUT'
    return t


# Floating literal
def t_php_DNUMBER(t):
    r'(\d*\.\d+|\d+\.\d*)([Ee][+-]?\d+)? | (\d+[Ee][+-]?\d+)'
    return t


# Integer literal
def t_php_LNUMBER(t):
    r'(0b[01]+)|(0x[0-9A-Fa-f]+)|\d+'
    return t


# String literal
def t_php_CONSTANT_ENCAPSED_STRING(t):
    r"'([^\\']|\\(.|\n))*'"
    t.lexer.lineno += t.value.count("\n")
    return t


def t_php_QUOTE(t):
    r'"'
    t.lexer.push_state('quoted')
    return t


def t_quoted_QUOTE(t):
    r'"'
    t.lexer.pop_state()
    return t


def t_quoted_ENCAPSED_AND_WHITESPACE(t):
    r'( [^"\\${] | \\(.|\n) | \$(?![A-Za-z_{]) | \{(?!\$) )+'
    t.lexer.lineno += t.value.count("\n")
    return t


def t_quoted_VARIABLE(t):
    r'\$[A-Za-z_][\w_]*'
    t.lexer.push_state('quotedvar')
    return t


def t_quoted_CURLY_OPEN(t):
    r'\{(?=\$)'
    t.lexer.push_state('php')
    return t


def t_quoted_DOLLAR_OPEN_CURLY_BRACES(t):
    r'\$\{'
    if re.match(r'[A-Za-z_]', peek(t.lexer)):
        t.lexer.push_state('varname')
    else:
        t.lexer.push_state('php')
    return t


def t_quotedvar_QUOTE(t):
    r'"'
    t.lexer.pop_state()
    t.lexer.pop_state()
    return t


def t_quotedvar_LBRACKET(t):
    r'\['
    t.lexer.begin('offset')
    return t


def t_quotedvar_OBJECT_OPERATOR(t):
    r'->(?=[A-Za-z])'
    t.lexer.begin('property')
    return t


def t_quotedvar_ENCAPSED_AND_WHITESPACE(t):
    r'( [^"\\${] | \\(.|\n) | \$(?![A-Za-z_{]) | \{(?!\$) )+'
    t.lexer.lineno += t.value.count("\n")
    t.lexer.pop_state()
    return t


t_quotedvar_VARIABLE = t_php_VARIABLE


def t_quotedvar_CURLY_OPEN(t):
    r'\{(?=\$)'
    t.lexer.begin('php')
    return t


def t_quotedvar_DOLLAR_OPEN_CURLY_BRACES(t):
    r'\$\{'
    if re.match(r'[A-Za-z_]', peek(t.lexer)):
        t.lexer.begin('varname')
    else:
        t.lexer.begin('php')
    return t


def t_varname_STRING_VARNAME(t):
    r'[A-Za-z_][\w_]*'
    return t


t_varname_RBRACE = t_php_RBRACE
t_varname_LBRACKET = t_php_LBRACKET


def t_offset_STRING(t):
    r'[A-Za-z_][\w_]*'
    return t


def t_offset_NUM_STRING(t):
    r'\d+'
    return t


t_offset_VARIABLE = t_php_VARIABLE
t_offset_RBRACKET = t_php_RBRACKET


def t_property_STRING(t):
    r'[A-Za-z_][\w_]*'
    t.lexer.pop_state()
    return t


# Heredocs

def t_php_START_HEREDOC(t):
    r'<<<[ \t]*(?P<label>[A-Za-z_][\w_]*)\r?\n'
    t.lexer.lineno += t.value.count("\n")
    t.lexer.push_state('heredoc')
    t.lexer.heredoc_label = t.lexer.lexmatch.group('label')
    return t


def t_heredoc_END_HEREDOC(t):
    r'(?<=\n)[A-Za-z_][\w_]*'
    if t.value == t.lexer.heredoc_label:
        del t.lexer.heredoc_label
        t.lexer.pop_state()
    else:
        t.type = 'ENCAPSED_AND_WHITESPACE'
    return t


def t_php_START_NOWDOC(t):
    r'''<<<[ \t]*'(?P<label>[A-Za-z_][\w_]*)'\r?\n'''
    t.lexer.lineno += t.value.count("\n")
    t.lexer.push_state('nowdoc')
    t.lexer.nowdoc_label = t.lexer.lexmatch.group('label')
    return t


def t_nowdoc_END_NOWDOC(t):
    r'(?<=\n)[A-Za-z_][\w_]*'
    if t.value == t.lexer.nowdoc_label:
        del t.lexer.nowdoc_label
        t.lexer.pop_state()
    else:
        t.type = 'ENCAPSED_AND_WHITESPACE'
    return t


def t_nowdoc_ENCAPSED_AND_WHITESPACE(t):
    r'[^\n]*\n'
    t.lexer.lineno += t.value.count("\n")
    return t


def t_heredoc_ENCAPSED_AND_WHITESPACE(t):
    r'( [^\n\\${] | \\. | \$(?![A-Za-z_{]) | \{(?!\$) )+\n? | \\?\n'
    t.lexer.lineno += t.value.count("\n")
    return t


def t_heredoc_VARIABLE(t):
    r'\$[A-Za-z_][\w_]*'
    t.lexer.push_state('heredocvar')
    return t


t_heredoc_CURLY_OPEN = t_quoted_CURLY_OPEN
t_heredoc_DOLLAR_OPEN_CURLY_BRACES = t_quoted_DOLLAR_OPEN_CURLY_BRACES


def t_heredocvar_ENCAPSED_AND_WHITESPACE(t):
    r'( [^\n\\${] | \\. | \$(?![A-Za-z_{]) | \{(?!\$) )+\n? | \\?\n'
    t.lexer.lineno += t.value.count("\n")
    t.lexer.pop_state()
    return t


t_heredocvar_LBRACKET = t_quotedvar_LBRACKET
t_heredocvar_OBJECT_OPERATOR = t_quotedvar_OBJECT_OPERATOR
t_heredocvar_VARIABLE = t_quotedvar_VARIABLE
t_heredocvar_CURLY_OPEN = t_quotedvar_CURLY_OPEN
t_heredocvar_DOLLAR_OPEN_CURLY_BRACES = t_quotedvar_DOLLAR_OPEN_CURLY_BRACES


# Backticks
def t_php_BACKTICK(t):
    r"`"
    t.lexer.push_state('backticked')
    return t


def t_backticked_ENCAPSED_AND_WHITESPACE(t):
    r'( [^`\\${] | \\(.|\n) | \$(?![A-Za-z_{]) | \{(?!\$) )+'
    t.lexer.lineno += t.value.count("\n")
    return t


def t_backticked_VARIABLE(t):
    r'\$[A-Za-z_][\w_]*'
    t.lexer.push_state('backtickedvar')
    return t


t_backticked_CURLY_OPEN = t_quoted_CURLY_OPEN
t_backticked_DOLLAR_OPEN_CURLY_BRACES = t_quoted_DOLLAR_OPEN_CURLY_BRACES


def t_backticked_BACKTICK(t):
    r"`"
    t.lexer.pop_state()
    return t


def t_backtickedvar_BACKTICK(t):
    r"`"
    t.lexer.pop_state()
    t.lexer.pop_state()
    return t


t_backtickedvar_LBRACKET = t_quotedvar_LBRACKET
t_backtickedvar_OBJECT_OPERATOR = t_quotedvar_OBJECT_OPERATOR
t_backtickedvar_VARIABLE = t_quotedvar_VARIABLE
t_backtickedvar_CURLY_OPEN = t_quotedvar_CURLY_OPEN
t_backtickedvar_DOLLAR_OPEN_CURLY_BRACES = t_quotedvar_DOLLAR_OPEN_CURLY_BRACES


def t_backtickedvar_ENCAPSED_AND_WHITESPACE(t):
    r'( [^`\\${] | \\(.|\n) | \$(?![A-Za-z_{]) | \{(?!\$) )+'
    t.lexer.lineno += t.value.count("\n")
    t.lexer.pop_state()
    return t


def t_ANY_error(t):
    raise SyntaxError('illegal character', (None, t.lineno, None, t.value))


def peek(lexer):
    try:
        return lexer.lexdata[lexer.lexpos]
    except IndexError:
        return ''
