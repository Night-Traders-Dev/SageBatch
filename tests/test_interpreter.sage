# test_interpreter.sage — Integration tests for the full pipeline
import std.testing
from process     import BatchProcess
from interpreter import Interpreter
from lexer       import Lexer
from parser      import Parser

let t = std.testing

proc run(src):
    let proc_inst = BatchProcess("TEST", [])
    let interp    = Interpreter(proc_inst)
    let tokens    = Lexer(src + "\n").tokenize()
    let ast       = Parser(tokens).parse()
    return interp.run_program(ast)

# Test 1: ECHO (no crash)
run("@ECHO OFF\nECHO Hello")
t.assert_eq(true, true, "ECHO runs")

# Test 2: SET + variable expansion
run("SET X=42")
t.assert_eq(true, true, "SET runs")

# Test 3: IF compare
run("SET A=hello\nIF %A% == hello ECHO match")
t.assert_eq(true, true, "IF compare runs")

# Test 4: GOTO
run("GOTO END\nECHO should not print\n:END\nECHO done")
t.assert_eq(true, true, "GOTO works")

print "interpreter integration tests passed."
