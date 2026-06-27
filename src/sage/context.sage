from token       import TOK_VARIABLE, TOK_STRING, TOK_WORD
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
