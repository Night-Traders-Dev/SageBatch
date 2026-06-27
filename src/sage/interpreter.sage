# interpreter.sage — Tree-walking batch interpreter
# Phase 3: Executes a Program AST produced by parser.sage.
# Implements: GOTO jumps, IF conditionals, FOR loops,
# CALL nesting, variable expansion, redirection, and pipes.

from ast      import Program, Command, Assignment, IfStatement, ForStatement
from ast      import LabelNode, GotoNode, CallNode, RedirectNode, PipeNode, BlockNode
from registry import CommandRegistry
from lexer    import Lexer
from parser   import Parser
import io
import sys

# Sentinel exception class for GOTO
class GotoSignal:
    proc init(self, target):
        self.target = target

# Sentinel for EXIT
class ExitSignal:
    proc init(self, code):
        self.code = code

class Interpreter:
    proc init(self, process):
        self.process  = process
        self.ctx      = process.make_context(process.batch_args)
        self.registry = CommandRegistry(self.ctx)
        self.labels   = {}     # name → statement index in flat list
        self.stmts    = []     # flattened statement list for GOTO

    # ------------------------------------------------------------------ label table

    proc build_label_table(self, program):
        self.stmts = program.statements
        let i = 0
        for stmt in self.stmts:
            if type(stmt) == "Instance" and stmt.name != nil:
                # Check if it's a LabelNode by duck-typing
                try:
                    self.labels[upper(stmt.name)] = i
                catch e:
                    nil  # not a label node
            i = i + 1

    # ------------------------------------------------------------------ condition evaluation

    proc eval_condition(self, cond):
        let ctype = cond["type"]
        if ctype == "EXIST":
            let path = self.ctx.vars.expand(cond["value"])
            return self.ctx.fs.exists(path)
        if ctype == "ERRORLEVEL":
            let n = tonumber(cond["value"])
            return self.ctx.env.get_errorlevel() >= n
        if ctype == "COMPARE":
            let left  = self.ctx.vars.expand(cond["left"])
            let right = self.ctx.vars.expand(cond["right"])
            let op    = upper(cond["op"])
            if op == "==":
                return left == right
            if op == "EQU":
                return left == right
            if op == "NEQ":
                return left != right
            if op == "LSS":
                return tonumber(left) < tonumber(right)
            if op == "LEQ":
                return tonumber(left) <= tonumber(right)
            if op == "GTR":
                return tonumber(left) > tonumber(right)
            if op == "GEQ":
                return tonumber(left) >= tonumber(right)
        return false

    # ------------------------------------------------------------------ token arg expansion

    proc expand_args(self, args):
        let out = []
        for arg in args:
            push(out, self.ctx.expand_token(arg))
        return out

    # ------------------------------------------------------------------ execute single node

    proc exec_node(self, node):
        if node == nil:
            return 0

        # LabelNode — no-op at execution time (handled by label table)
        let ntype = type(node)
        try:
            # Assignment: SET VAR=VALUE
            let _ = node.name
            let _ = node.value
            self.ctx.vars.set(node.name, self.ctx.vars.expand(node.value))
            self.ctx.env.set_errorlevel(0)
            return 0
        catch e:
            nil

        try:
            # GotoNode
            let target = node.target
            raise GotoSignal(upper(target))
        catch e:
            if type(e) == "Instance":
                raise e

        try:
            # IfStatement
            let cond   = node.condition
            let result = self.eval_condition(cond)
            if node.negated:
                result = not result
            if result:
                return self.exec_node(node.consequent)
            elif node.alternate != nil:
                return self.exec_node(node.alternate)
            return 0
        catch e:
            if type(e) == "Instance":
                raise e

        try:
            # ForStatement
            let var_name = node.var_name
            let in_list  = node.in_list
            self.ctx.vars.push_scope()
            for tok in in_list:
                let val = self.ctx.expand_token(tok)
                self.ctx.vars.set_local(var_name, val)
                self.exec_node(node.body)
            self.ctx.vars.pop_scope()
            return 0
        catch e:
            if type(e) == "Instance":
                self.ctx.vars.pop_scope()
                raise e

        try:
            # CallNode
            let target = node.target
            let args   = self.expand_args(node.args)
            if node.is_subroutine:
                # CALL :label — jump within same script (push IP, not implemented yet)
                raise GotoSignal(upper(target))
            else:
                # CALL script.bat — nested execution
                self.run_file(target, args)
            return 0
        catch e:
            if type(e) == "Instance":
                raise e

        try:
            # BlockNode
            let stmts = node.statements
            for s in stmts:
                self.exec_node(s)
            return 0
        catch e:
            if type(e) == "Instance":
                raise e

        try:
            # RedirectNode
            let filename = self.ctx.vars.expand(node.filename)
            let old_stdout = self.ctx.stdout
            if node.op == ">":
                io.writefile(filename, "")
                self.ctx.stdout = filename
            elif node.op == ">>":
                self.ctx.stdout = filename
            self.exec_node(node.inner)
            self.ctx.stdout = old_stdout
            return 0
        catch e:
            if type(e) == "Instance":
                raise e

        try:
            # PipeNode: capture left output, feed to right as stdin stub
            self.exec_node(node.left)
            self.exec_node(node.right)
            return 0
        catch e:
            if type(e) == "Instance":
                raise e

        # Command node
        try:
            let name = node.name
            let args = self.expand_args(node.args)
            if self.ctx.echo_on and not node.suppress:
                print self.ctx.env.render_prompt() + name + " " + join(args, " ")
            let code = self.registry.dispatch(name, node.args)
            self.ctx.env.set_errorlevel(code)
            return code
        catch e:
            if type(e) == "Instance":
                raise e
            print "Bad command or file name: " + str(e)
            self.ctx.env.set_errorlevel(1)
            return 1

        return 0

    # ------------------------------------------------------------------ GOTO driver

    proc run_program(self, program):
        self.build_label_table(program)
        let ip = 0
        while ip < len(self.stmts):
            let stmt = self.stmts[ip]
            try:
                self.exec_node(stmt)
                ip = ip + 1
            catch e:
                if type(e) == "Instance":
                    # GotoSignal
                    try:
                        let target = e.target
                        if dicthas(self.labels, target):
                            ip = self.labels[target] + 1
                        else:
                            print "GOTO: Label not found: " + target
                            return 1
                    catch ee:
                        # ExitSignal or real error
                        try:
                            let code = e.code
                            return code
                        catch eee:
                            raise e
                else:
                    raise e
        return 0

    # ------------------------------------------------------------------ run a .BAT file

    proc run_file(self, path, args):
        let source = self.ctx.fs.read_file(path)
        let lexer  = Lexer(source)
        let tokens = lexer.tokenize()
        let parser = Parser(tokens)
        let ast    = parser.parse()
        let sub    = Interpreter(self.process)
        sub.ctx.args = args
        return sub.run_program(ast)
