# process.sage — BatchProcess and CommandContext
# Phase 5 / Phase 7: The execution context that binds together
# environment, varstore, filesystem, stdin/stdout streams, and
# positional arguments for a running batch script.

from environment import Environment
from varstore    import VarStore
from filesystem  import FileSystem
from token       import TOK_VARIABLE, TOK_STRING, TOK_WORD
import sys
import io

class CommandContext:
    proc init(self, env, varstore, fs, batch_args):
        self.env        = env
        self.vars       = varstore
        self.fs         = fs
        self.args       = batch_args    # %0..%9
        self.echo_on    = true
        self.stdout     = nil           # nil = real stdout
        self.stderr     = nil

    proc expand_token(self, tok):
        if tok.kind == TOK_VARIABLE:
            return self.vars.get(tok.value)
        if tok.kind == TOK_STRING or tok.kind == TOK_WORD:
            return self.vars.expand(tok.value)
        return str(tok.value)

    proc shift_args(self):
        if len(self.args) > 0:
            self.args = slice(self.args, 1, len(self.args))

    proc get_arg(self, n):
        if n < len(self.args):
            return self.args[n]
        return ""

    proc write_out(self, text):
        if self.stdout != nil:
            io.appendfile(self.stdout, text + "\n")
        else:
            print text


class BatchProcess:
    proc init(self, script_path, batch_args):
        self.script_path = script_path
        self.env         = Environment()
        self.varstore    = VarStore(self.env)
        self.fs          = FileSystem(self.env)
        self.call_stack  = []      # stack of (script, args, ip) tuples
        self.env.set_var("0", script_path)
        let i = 1
        for arg in batch_args:
            self.env.set_var(str(i), arg)
            i = i + 1
        self.batch_args = batch_args

    proc make_context(self, args):
        return CommandContext(self.env, self.varstore, self.fs, args)

    proc push_call(self, script, args, ip):
        push(self.call_stack, {"script": script, "args": args, "ip": ip})

    proc pop_call(self):
        if len(self.call_stack) > 0:
            return pop(self.call_stack)
        return nil
