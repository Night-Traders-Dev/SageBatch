# test_lexer.sage — Unit tests for lexer.sage
import std.testing
from lexer import Lexer
from token import TOK_WORD, TOK_VARIABLE, TOK_NEWLINE, TOK_EOF, TOK_LABEL, TOK_REDIRECT

let t = std.testing

# Test 1: simple ECHO command
let tokens = Lexer("ECHO HELLO\n").tokenize()
t.assert_eq(tokens[0].kind, TOK_WORD,   "first token is WORD")
t.assert_eq(tokens[0].value, "ECHO",   "first token value ECHO")
t.assert_eq(tokens[1].kind, TOK_WORD,   "second token is WORD")
t.assert_eq(tokens[1].value, "HELLO",  "second token value HELLO")
t.assert_eq(tokens[2].kind, TOK_NEWLINE, "newline token")

# Test 2: variable expansion token
let vtok = Lexer("%NAME%").tokenize()
t.assert_eq(vtok[0].kind, TOK_VARIABLE, "variable token")
t.assert_eq(vtok[0].value, "NAME",     "variable name")

# Test 3: label token
let ltok = Lexer(":START\n").tokenize()
t.assert_eq(ltok[0].kind, TOK_LABEL, "label token")
t.assert_eq(ltok[0].value, "START",  "label name")

# Test 4: redirect
let rtok = Lexer("DIR > out.txt\n").tokenize()
t.assert_eq(rtok[2].kind, TOK_REDIRECT, "redirect token")
t.assert_eq(rtok[2].value, ">",         "redirect value")

print "lexer tests passed."
