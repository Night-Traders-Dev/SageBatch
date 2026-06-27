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
        
        let e = Environment()
        self.env = e
        
        let v = VarStore(e)
        self.varstore = v
        
        let f = FileSystem(e)
        self.fs = f
        
        let arr = []
        self.call_stack  = arr      # stack of (script, args, ip) tuples
        
        let env_ref = self.env
        env_ref.set_var("0", script_path)
        let i = 1
        for arg in batch_args:
            let k = str(i)
            env_ref.set_var(k, arg)
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
