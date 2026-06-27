# interpreter.sage — Tree-walking batch interpreter
# Phase 3: Executes a Program AST produced by parser.sage.
# Implements: GOTO jumps, IF conditionals, FOR loops,
# CALL nesting, variable expansion, redirection, and pipes.

from ast      import Program, Command, Assignment, IfStatement, ForStatement, LabelNode, GotoNode, CallNode, RedirectNode, PipeNode, BlockNode
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
            if stmt.type == "LabelNode":
                self.labels[upper(stmt.name)] = i
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
        if ctype == "CMP":
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

        let ntype = node.type

        if ntype == "LabelNode":
            return 0

        if ntype == "Assignment":
            let name = node.name
            let is_arith = false
            if startswith(name, "/A "):
                name = strip(slice(name, 3, len(name)))
                is_arith = true
            
            let val = self.ctx.vars.expand(node.value)
            if is_arith:
                # Basic parsing for X+Y
                let plus = -1
                let i = 0
                while i < len(val):
                    if val[i] == "+":
                        plus = i
                        break
                    i = i + 1
                if plus != -1:
                    let left = strip(slice(val, 0, plus))
                    let right = strip(slice(val, plus + 1, len(val)))
                    
                    let left_val = self.ctx.vars.get(left)
                    if left_val != "" and left_val != nil: left = left_val
                    let right_val = self.ctx.vars.get(right)
                    if right_val != "" and right_val != nil: right = right_val
                    
                    let left_num = tonumber(left)
                    let right_num = tonumber(right)
                    val = str(left_num + right_num)
                else:
                    let val_var = self.ctx.vars.get(val)
                    if val_var != "" and val_var != nil: val = val_var
                    val = str(tonumber(val))

            self.ctx.vars.set(name, val)
            self.ctx.env.set_errorlevel(0)
            return 0

        if ntype == "GotoNode":
            return {"__signal": "GOTO", "target": upper(node.target)}

        if ntype == "IfStatement":
            let result = self.eval_condition(node.condition)
            if node.negated:
                result = not result
            if result:
                return self.exec_node(node.consequent)
            elif node.alternate != nil:
                return self.exec_node(node.alternate)
            return 0

        if ntype == "ForStatement":
            self.ctx.vars.push_scope()
            let ret = 0
            for tok in node.in_list:
                let val = self.ctx.expand_token(tok)
                self.ctx.vars.set_local(node.var_name, val)
                ret = self.exec_node(node.body)
                if type(ret) == "dict" and dict_has(ret, "__signal"):
                    break
            self.ctx.vars.pop_scope()
            return ret

        if ntype == "CallNode":
            let args = self.expand_args(node.args)
            if node.is_subroutine:
                return {"__signal": "GOTO", "target": upper(node.target)}
            else:
                return self.run_file(node.target, args)

        if ntype == "BlockNode":
            let ret = 0
            for s in node.statements:
                ret = self.exec_node(s)
                if type(ret) == "dict" and dict_has(ret, "__signal"):
                    return ret
            return ret

        if ntype == "RedirectNode":
            let filename = self.ctx.vars.expand(node.filename)
            let old_stdout = self.ctx.stdout
            if node.op == ">":
                io.writefile(filename, "")
                self.ctx.stdout = filename
            elif node.op == ">>":
                self.ctx.stdout = filename
            let ret = self.exec_node(node.inner)
            self.ctx.stdout = old_stdout
            return ret

        if ntype == "PipeNode":
            let ret1 = self.exec_node(node.left)
            if type(ret1) == "dict" and dict_has(ret1, "__signal"): return ret1
            return self.exec_node(node.right)

        if ntype == "Command":
            let args = self.expand_args(node.args)
            if self.ctx.echo_on and not node.suppress:
                print self.ctx.env.render_prompt() + str(node.name) + " " + join(args, " ")
            let code = self.registry.dispatch(node.name, node.args)
            if type(code) == "dict" and dict_has(code, "__signal"):
                return code
            self.ctx.env.set_errorlevel(code)
            return code

        return 0

    # ------------------------------------------------------------------ GOTO driver

    proc run_program(self, program):
        self.build_label_table(program)
        let ip = 0
        while ip < len(self.stmts):
            let stmt = self.stmts[ip]
            let ret = self.exec_node(stmt)
            if type(ret) == "dict" and dict_has(ret, "__signal"):
                if ret["__signal"] == "GOTO":
                    let target = ret["target"]
                    if dict_has(self.labels, target):
                        ip = self.labels[target] + 1
                        continue
                    else:
                        print "GOTO: Label not found: " + target
                        return 1
                elif ret["__signal"] == "EXIT":
                    return ret["code"]
            
            ip = ip + 1
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
