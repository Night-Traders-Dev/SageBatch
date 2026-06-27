# test_parser.sage — Unit tests for parser.sage
import std.testing
from lexer  import Lexer
from parser import Parser
from ast    import Command, Assignment, GotoNode, LabelNode, IfStatement

let t = std.testing

proc parse(src):
    return Parser(Lexer(src + "\n").tokenize()).parse()

# Test 1: ECHO command
let prog = parse("ECHO Hello World")
t.assert_eq(len(prog.statements), 1, "one statement")
let s = prog.statements[0]
t.assert_eq(s.name, "ECHO", "command name ECHO")

# Test 2: SET assignment
let prog2 = parse("SET FOO=BAR")
let a = prog2.statements[0]
t.assert_eq(a.name, "FOO", "assignment name")
t.assert_eq(a.value, "BAR", "assignment value")

# Test 3: GOTO
let prog3 = parse("GOTO START")
let g = prog3.statements[0]
t.assert_eq(g.target, "START", "goto target")

# Test 4: IF EXIST
let prog4 = parse("IF EXIST foo.txt ECHO found")
let i = prog4.statements[0]
t.assert_eq(i.condition["type"], "EXIST", "if exist condition")

print "parser tests passed."
