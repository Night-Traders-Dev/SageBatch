# process.sage — BatchProcess and CommandContext
# Phase 5 / Phase 7: The execution context that binds together
# environment, varstore, filesystem, stdin/stdout streams, and
# positional arguments for a running batch script.

from environment import Environment
from varstore    import VarStore
from filesystem  import FileSystem
from context import CommandContext


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
