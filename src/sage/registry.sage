# registry.sage — CommandRegistry
# Maps command names to handler procs (internal) or marks
# them as external (to be found on PATH).
# Phase 5: Internal command dispatch table.

from commands import InternalCommands

class CommandRegistry:
    proc init(self, ctx):
        self.ctx       = ctx
        self.internals = {}
        self.ic        = InternalCommands(ctx)
        self._register_builtins()

    proc _register_builtins(self):
        let ic = self.ic
        self.internals["ECHO"]   = proc(args): return ic.cmd_echo(args)
        self.internals["REM"]    = proc(args): return ic.cmd_rem(args)
        self.internals["SET"]    = proc(args): return ic.cmd_set(args)
        self.internals["PAUSE"]  = proc(args): return ic.cmd_pause(args)
        self.internals["CLS"]    = proc(args): return ic.cmd_cls(args)
        self.internals["EXIT"]   = proc(args): return ic.cmd_exit(args)
        self.internals["CD"]     = proc(args): return ic.cmd_cd(args)
        self.internals["MD"]     = proc(args): return ic.cmd_md(args)
        self.internals["RD"]     = proc(args): return ic.cmd_rd(args)
        self.internals["DIR"]    = proc(args): return ic.cmd_dir(args)
        self.internals["TYPE"]   = proc(args): return ic.cmd_type(args)
        self.internals["COPY"]   = proc(args): return ic.cmd_copy(args)
        self.internals["MOVE"]   = proc(args): return ic.cmd_move(args)
        self.internals["DEL"]    = proc(args): return ic.cmd_del(args)
        self.internals["ERASE"]  = proc(args): return ic.cmd_del(args)
        self.internals["REN"]    = proc(args): return ic.cmd_ren(args)
        self.internals["RENAME"] = proc(args): return ic.cmd_ren(args)
        self.internals["SHIFT"]  = proc(args): return ic.cmd_shift(args)
        self.internals["VER"]    = proc(args): return ic.cmd_ver(args)
        self.internals["HELP"]   = proc(args): return ic.cmd_help(args)

    ## Returns true if the command name is a built-in.
    proc is_internal(self, name):
        return dicthas(self.internals, upper(name))

    ## Dispatch to the appropriate handler.
    ## Returns the handler proc, or nil if not internal.
    proc get_handler(self, name):
        let key = upper(name)
        if dicthas(self.internals, key):
            return self.internals[key]
        return nil

    ## Register a user-defined alias or external command override.
    proc register(self, name, handler):
        self.internals[upper(name)] = handler
