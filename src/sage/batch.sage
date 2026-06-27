# batch.sage — SageBatch entrypoint
# Usage: sage src/sage/batch.sage [script.bat] [args...]
#
# If no script is given, enters interactive command-line mode.
# Phases: 0 (repo) ✓  1 (lexer) ✓  2 (parser) ✓  3 (interpreter) ✓
#         4 (env) ✓   5 (commands) ✓  6 (redirect) ✓  7 (pipes) partial

from token       import Token, TOK_WORD, TOK_STRING, TOK_VARIABLE, TOK_LABEL, TOK_OPERATOR, TOK_REDIRECT, TOK_PIPE, TOK_NEWLINE, TOK_EOF, TOK_AMP, TOK_PAREN_L, TOK_PAREN_R, TOK_AT
from process     import BatchProcess
from interpreter import Interpreter
from lexer       import Lexer
from parser      import Parser
import sys
import io

proc print_banner():
    print "SageBatch v1.0.0 — MS-DOS Batch 4.0 Clone in Pure SageLang"
    print "Type HELP for a list of commands.  Type EXIT to quit."
    print ""

proc run_interactive(process):
    print_banner()
    let interp = Interpreter(process)
    while true:
        let prompt = process.env.render_prompt()
        let line   = input(prompt)
        let line   = strip(line)
        if len(line) == 0:
            continue
        try:
            let lexer  = Lexer(line + "\n")
            let tokens = lexer.tokenize()
            let parser = Parser(tokens)
            let ast    = parser.parse()
            interp.run_program(ast)
        catch e:
            print "Error: " + str(e)

proc run_script(script_path, batch_args):
    if not io.exists(script_path):
        print "SageBatch: File not found: " + script_path
        sys.exit(1)
    let process = BatchProcess(script_path, batch_args)
    let interp  = Interpreter(process)
    let source  = io.readfile(script_path)
    let lexer   = Lexer(source)
    let tokens  = lexer.tokenize()
    let parser  = Parser(tokens)
    let ast     = parser.parse()
    let code    = interp.run_program(ast)
    sys.exit(code)

# ------------------------------------------------------------------ main

let args = sys.args()

let arg_offset = 1
if len(args) > 1 and (endswith(args[1], ".sage") or endswith(args[1], ".sgvm")):
    arg_offset = 2

if len(args) <= arg_offset:
    let proc_inst = BatchProcess("INTERACTIVE", [])
    run_interactive(proc_inst)
else:
    let script = args[arg_offset]
    let rest = slice(args, arg_offset + 1, len(args))
    run_script(script, rest)
