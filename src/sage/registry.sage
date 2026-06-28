# registry.sage — CommandRegistry
# Maps command names to handler procs (internal) or marks
# them as external (to be found on PATH).
# Phase 5: Internal command dispatch table.

from commands import cmd_echo, cmd_rem, cmd_set, cmd_pause, cmd_cls, cmd_exit, cmd_cd, cmd_md, cmd_rd, cmd_dir, cmd_type, cmd_copy, cmd_move, cmd_del, cmd_ren, cmd_shift, cmd_ver, cmd_help, cmd_title, cmd_color, cmd_prompt, cmd_date, cmd_time, cmd_vol, cmd_verify, cmd_pushd, cmd_popd, cmd_path, cmd_break, cmd_chcp

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
        self.handlers["PATH"] = cmd_path
        self.handlers["BREAK"] = cmd_break
        self.handlers["CHCP"] = cmd_chcp

    proc is_internal(self, name):
        let key = upper(name)
        return dict_has(self.handlers, key)

    proc dispatch(self, name, args):
        let key = upper(name)
        if key == "ECHO": return cmd_echo(self.ctx, args)
        if key == "REM": return cmd_rem(self.ctx, args)
        if key == "SET": return cmd_set(self.ctx, args)
        if key == "PAUSE": return cmd_pause(self.ctx, args)
        if key == "CLS": return cmd_cls(self.ctx, args)
        if key == "EXIT": return cmd_exit(self.ctx, args)
        if key == "CD": return cmd_cd(self.ctx, args)
        if key == "CHDIR": return cmd_cd(self.ctx, args)
        if key == "MD": return cmd_md(self.ctx, args)
        if key == "MKDIR": return cmd_md(self.ctx, args)
        if key == "RD": return cmd_rd(self.ctx, args)
        if key == "RMDIR": return cmd_rd(self.ctx, args)
        if key == "DIR": return cmd_dir(self.ctx, args)
        if key == "TYPE": return cmd_type(self.ctx, args)
        if key == "COPY": return cmd_copy(self.ctx, args)
        if key == "MOVE": return cmd_move(self.ctx, args)
        if key == "DEL": return cmd_del(self.ctx, args)
        if key == "ERASE": return cmd_del(self.ctx, args)
        if key == "REN": return cmd_ren(self.ctx, args)
        if key == "RENAME": return cmd_ren(self.ctx, args)
        if key == "SHIFT": return cmd_shift(self.ctx, args)
        if key == "VER": return cmd_ver(self.ctx, args)
        if key == "HELP": return cmd_help(self.ctx, args)
        if key == "TITLE": return cmd_title(self.ctx, args)
        if key == "COLOR": return cmd_color(self.ctx, args)
        if key == "PROMPT": return cmd_prompt(self.ctx, args)
        if key == "DATE": return cmd_date(self.ctx, args)
        if key == "TIME": return cmd_time(self.ctx, args)
        if key == "VOL": return cmd_vol(self.ctx, args)
        if key == "VERIFY": return cmd_verify(self.ctx, args)
        if key == "PUSHD": return cmd_pushd(self.ctx, args)
        if key == "POPD": return cmd_popd(self.ctx, args)
        if key == "PATH": return cmd_path(self.ctx, args)
        if key == "BREAK": return cmd_break(self.ctx, args)
        if key == "CHCP": return cmd_chcp(self.ctx, args)

        # External execution
        let cmd = name
        if len(args) > 0:
            cmd = cmd + " " + join(args, " ")
        return sys_exec(cmd)
