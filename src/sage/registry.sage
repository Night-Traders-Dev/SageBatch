# registry.sage — CommandRegistry
# Maps command names to handler procs (internal) or marks
# them as external (to be found on PATH).
# Phase 5: Internal command dispatch table.

from commands import cmd_echo, cmd_rem, cmd_set, cmd_pause, cmd_cls, cmd_exit, cmd_cd, cmd_md, cmd_rd, cmd_dir, cmd_type, cmd_copy, cmd_move, cmd_del, cmd_ren, cmd_shift, cmd_ver, cmd_help, cmd_title, cmd_color, cmd_prompt, cmd_date, cmd_time, cmd_vol, cmd_verify, cmd_pushd, cmd_popd
import sys

class CommandRegistry:
    proc init(self, ctx):
        self.ctx = ctx
        self.handlers = {}
        self.handlers["ECHO"] = cmd_echo
        self.handlers["REM"] = cmd_rem
        self.handlers["SET"] = cmd_set
        self.handlers["PAUSE"] = cmd_pause
        self.handlers["CLS"] = cmd_cls
        self.handlers["EXIT"] = cmd_exit
        self.handlers["CD"] = cmd_cd
        self.handlers["CHDIR"] = cmd_cd
        self.handlers["MD"] = cmd_md
        self.handlers["MKDIR"] = cmd_md
        self.handlers["RD"] = cmd_rd
        self.handlers["RMDIR"] = cmd_rd
        self.handlers["DIR"] = cmd_dir
        self.handlers["TYPE"] = cmd_type
        self.handlers["COPY"] = cmd_copy
        self.handlers["MOVE"] = cmd_move
        self.handlers["DEL"] = cmd_del
        self.handlers["ERASE"] = cmd_del
        self.handlers["REN"] = cmd_ren
        self.handlers["RENAME"] = cmd_ren
        self.handlers["SHIFT"] = cmd_shift
        self.handlers["VER"] = cmd_ver
        self.handlers["HELP"] = cmd_help
        self.handlers["TITLE"] = cmd_title
        self.handlers["COLOR"] = cmd_color
        self.handlers["PROMPT"] = cmd_prompt
        self.handlers["DATE"] = cmd_date
        self.handlers["TIME"] = cmd_time
        self.handlers["VOL"] = cmd_vol
        self.handlers["VERIFY"] = cmd_verify
        self.handlers["PUSHD"] = cmd_pushd
        self.handlers["POPD"] = cmd_popd

    proc is_internal(self, name):
        let key = upper(name)
        return dict_has(self.handlers, key)

    proc dispatch(self, name, args):
        let key = upper(name)
        if dict_has(self.handlers, key):
            let handler = self.handlers[key]
            return handler(self.ctx, args)

        # External execution
        let cmd = name
        if len(args) > 0:
            cmd = cmd + " " + join(args, " ")
        return sys.exec(cmd)
