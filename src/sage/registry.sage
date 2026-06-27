# registry.sage — CommandRegistry
# Maps command names to handler procs (internal) or marks
# them as external (to be found on PATH).
# Phase 5: Internal command dispatch table.

from commands import InternalCommands
import sys

class CommandRegistry:
    proc init(self, ctx):
        self.ctx       = ctx
        self.ic        = InternalCommands(ctx)

    proc is_internal(self, name):
        let key = upper(name)
        if key == "ECHO" or key == "REM" or key == "SET" or key == "PAUSE" or key == "CLS": return true
        if key == "EXIT" or key == "CD" or key == "MD" or key == "RD" or key == "DIR": return true
        if key == "TYPE" or key == "COPY" or key == "MOVE" or key == "DEL" or key == "ERASE": return true
        if key == "REN" or key == "RENAME" or key == "SHIFT" or key == "VER" or key == "HELP": return true
        if key == "TITLE" or key == "COLOR" or key == "PROMPT": return true
        return false

    proc dispatch(self, name, args):
        let key = upper(name)
        if key == "ECHO": return self.ic.cmd_echo(args)
        if key == "REM": return self.ic.cmd_rem(args)
        if key == "SET": return self.ic.cmd_set(args)
        if key == "PAUSE": return self.ic.cmd_pause(args)
        if key == "CLS": return self.ic.cmd_cls(args)
        if key == "EXIT": return self.ic.cmd_exit(args)
        if key == "CD": return self.ic.cmd_cd(args)
        if key == "MD": return self.ic.cmd_md(args)
        if key == "RD": return self.ic.cmd_rd(args)
        if key == "DIR": return self.ic.cmd_dir(args)
        if key == "TYPE": return self.ic.cmd_type(args)
        if key == "COPY": return self.ic.cmd_copy(args)
        if key == "MOVE": return self.ic.cmd_move(args)
        if key == "DEL": return self.ic.cmd_del(args)
        if key == "ERASE": return self.ic.cmd_del(args)
        if key == "REN": return self.ic.cmd_ren(args)
        if key == "RENAME": return self.ic.cmd_ren(args)
        if key == "SHIFT": return self.ic.cmd_shift(args)
        if key == "VER": return self.ic.cmd_ver(args)
        if key == "HELP": return self.ic.cmd_help(args)
        if key == "TITLE": return self.ic.cmd_title(args)
        if key == "COLOR": return self.ic.cmd_color(args)
        if key == "PROMPT": return self.ic.cmd_prompt(args)

        # External execution
        let cmd = name
        if len(args) > 0:
            cmd = cmd + " " + join(args, " ")
        return sys.exec(cmd)
