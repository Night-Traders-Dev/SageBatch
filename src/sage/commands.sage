# commands.sage — Internal command implementations
# Phase 5: All V1 internal commands.
# Each command is a proc that receives (ctx, args) and returns an errorlevel.
# ctx is a CommandContext from process.sage.

class InternalCommands:
    proc init(self, ctx):
        self.ctx = ctx

    # ------------------------------------------------------------------ ECHO

    proc cmd_echo(self, args):
        if len(args) == 0:
            print "ECHO is on"
            return 0
        let line = ""
        for arg in args:
            let val = self.ctx.expand_token(arg)
            if len(line) > 0:
                line = line + " "
            line = line + val
        if upper(strip(line)) == "OFF":
            self.ctx.echo_on = false
            return 0
        if upper(strip(line)) == "ON":
            self.ctx.echo_on = true
            return 0
        print line
        return 0

    # ------------------------------------------------------------------ REM

    proc cmd_rem(self, args):
        return 0   # comment; do nothing

    # ------------------------------------------------------------------ SET

    proc cmd_set(self, args):
        if len(args) == 0:
            # Print all variables
            for k in dict_keys(self.ctx.env.vars):
                print k + "=" + self.ctx.env.vars[k]
            return 0
        return 0   # SET parsing is handled at parser level as Assignment

    # ------------------------------------------------------------------ PAUSE

    proc cmd_pause(self, args):
        print "Press any key to continue . . ."
        input()
        return 0

    # ------------------------------------------------------------------ CLS

    proc cmd_cls(self, args):
        # Emit ANSI clear screen
        print "\033[2J\033[H"
        return 0

    # ------------------------------------------------------------------ EXIT

    proc cmd_exit(self, args):
        let code = 0
        if len(args) > 0:
            code = tonumber(self.ctx.expand_token(args[0]))
        return {"__signal": "EXIT", "code": code}

    # ------------------------------------------------------------------ CD / CHDIR

    proc cmd_cd(self, args):
        if len(args) == 0:
            print self.ctx.env.cwd
            return 0
        let path = self.ctx.expand_token(args[0])
        try:
            self.ctx.env.chdir(path)
            return 0
        catch e:
            print e
            return 1

    # ------------------------------------------------------------------ MD / MKDIR

    proc cmd_md(self, args):
        if len(args) == 0:
            print "MD: Missing directory name"
            return 1
        let path = self.ctx.expand_token(args[0])
        try:
            self.ctx.fs.make_dir(path)
            return 0
        catch e:
            print e
            return 1

    # ------------------------------------------------------------------ RD / RMDIR

    proc cmd_rd(self, args):
        if len(args) == 0:
            print "RD: Missing directory name"
            return 1
        let path = self.ctx.expand_token(args[0])
        try:
            self.ctx.fs.remove_dir(path)
            return 0
        catch e:
            print e
            return 1

    # ------------------------------------------------------------------ DIR

    proc cmd_dir(self, args):
        let path = self.ctx.env.cwd
        if len(args) > 0:
            path = self.ctx.expand_token(args[0])
        let entries = self.ctx.fs.list_dir(path)
        print " Directory of " + path
        print ""
        for entry in entries:
            print entry
        print str(len(entries)) + " file(s)"
        return 0

    # ------------------------------------------------------------------ TYPE

    proc cmd_type(self, args):
        if len(args) == 0:
            print "TYPE: Missing filename"
            return 1
        let path = self.ctx.expand_token(args[0])
        try:
            let content = self.ctx.fs.read_file(path)
            print content
            return 0
        catch e:
            print "TYPE: " + e
            return 1

    # ------------------------------------------------------------------ COPY

    proc cmd_copy(self, args):
        if len(args) < 2:
            print "COPY: Syntax error"
            return 1
        let src = self.ctx.expand_token(args[0])
        let dst = self.ctx.expand_token(args[1])
        try:
            self.ctx.fs.copy_file(src, dst)
            print "        1 file(s) copied."
            return 0
        catch e:
            print "COPY: " + e
            return 1

    # ------------------------------------------------------------------ MOVE

    proc cmd_move(self, args):
        if len(args) < 2:
            print "MOVE: Syntax error"
            return 1
        let src = self.ctx.expand_token(args[0])
        let dst = self.ctx.expand_token(args[1])
        try:
            self.ctx.fs.move_file(src, dst)
            return 0
        catch e:
            print "MOVE: " + e
            return 1

    # ------------------------------------------------------------------ DEL / ERASE

    proc cmd_del(self, args):
        if len(args) == 0:
            print "DEL: Missing filename"
            return 1
        for arg in args:
            let path = self.ctx.expand_token(arg)
            try:
                self.ctx.fs.delete_file(path)
            catch e:
                print "DEL: " + e
                return 1
        return 0

    # ------------------------------------------------------------------ REN / RENAME

    proc cmd_ren(self, args):
        if len(args) < 2:
            print "REN: Syntax error"
            return 1
        let src = self.ctx.expand_token(args[0])
        let dst = self.ctx.expand_token(args[1])
        try:
            self.ctx.fs.rename_file(src, dst)
            return 0
        catch e:
            print "REN: " + e
            return 1

    # ------------------------------------------------------------------ SHIFT

    proc cmd_shift(self, args):
        self.ctx.shift_args()
        return 0

    # ------------------------------------------------------------------ VER

    proc cmd_ver(self, args):
        print "MS-DOS Batch 4.0 (SageBatch v1.0.0)"
        return 0

    # ------------------------------------------------------------------ HELP

    proc cmd_help(self, args):
        print "SageBatch internal commands:"
        print "  ECHO SET REM PAUSE CLS EXIT CD MD RD DIR TYPE COPY MOVE DEL REN SHIFT VER"
        print "  IF FOR GOTO CALL"
        return 0
