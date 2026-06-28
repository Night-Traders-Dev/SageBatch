# commands.sage — Internal command implementations
# Phase 5: All V1 internal commands.
# Each command is a proc that receives (ctx, args) and returns an errorlevel.
# ctx is a CommandContext from process.sage.

# ------------------------------------------------------------------ ECHO

proc cmd_echo(ctx, args):
    if len(args) == 0:
        print "ECHO is on"
        return 0
    let line = ""
    for arg in args:
        let val = arg
        if len(line) > 0:
            line = line + " "
        line = line + val
    if upper(strip(line)) == "OFF":
        ctx.echo_on = false
        return 0
    if upper(strip(line)) == "ON":
        ctx.echo_on = true
        return 0
    print line
    return 0

# ------------------------------------------------------------------ REM

proc cmd_rem(ctx, args):
    return 0   # comment; do nothing

# ------------------------------------------------------------------ SET

proc cmd_set(ctx, args):
    if len(args) == 0:
        # Print all variables
        for k in dict_keys(ctx.env.vars):
            print k + "=" + ctx.env.vars[k]
        return 0
    return 0   # SET parsing is handled at parser level as Assignment

# ------------------------------------------------------------------ PAUSE

proc cmd_pause(ctx, args):
    print "Press any key to continue . . ."
    input()
    return 0

# ------------------------------------------------------------------ CLS

proc cmd_cls(ctx, args):
    # Emit ANSI clear screen
    print "\033[2J\033[H"
    return 0

# ------------------------------------------------------------------ EXIT

proc cmd_exit(ctx, args):
    let code = 0
    if len(args) > 0:
        code = tonumber(args[0])
    let sig = {}
    sig["__signal"] = "EXIT"
    sig["code"] = code
    return sig

# ------------------------------------------------------------------ CD / CHDIR

proc cmd_cd(ctx, args):
    if len(args) == 0:
        print ctx.env.cwd
        return 0
    let path = args[0]
    try:
        ctx.env.chdir(path)
        return 0
    catch e:
        print e
        return 1

# ------------------------------------------------------------------ MD / MKDIR

proc cmd_md(ctx, args):
    if len(args) == 0:
        print "MD: Missing directory name"
        return 1
    let path = args[0]
    try:
        ctx.fs.make_dir(path)
        return 0
    catch e:
        print e
        return 1

# ------------------------------------------------------------------ RD / RMDIR

proc cmd_rd(ctx, args):
    if len(args) == 0:
        print "RD: Missing directory name"
        return 1
    let path = args[0]
    try:
        ctx.fs.remove_dir(path)
        return 0
    catch e:
        print e
        return 1

# ------------------------------------------------------------------ DIR

proc cmd_dir(ctx, args):
    let path = ctx.env.cwd
    if len(args) > 0:
        path = args[0]
    let entries = ctx.fs.list_dir(path)
    print " Directory of " + path
    print ""
    for entry in entries:
        print entry
    print str(len(entries)) + " file(s)"
    return 0

# ------------------------------------------------------------------ TYPE

proc cmd_type(ctx, args):
    if len(args) == 0:
        print "TYPE: Missing filename"
        return 1
    let path = args[0]
    try:
        let content = ctx.fs.read_file(path)
        print content
        return 0
    catch e:
        print "TYPE: " + e
        return 1

# ------------------------------------------------------------------ COPY

proc cmd_copy(ctx, args):
    if len(args) < 2:
        print "COPY: Syntax error"
        return 1
    let src = args[0]
    let dst = args[1]
    try:
        ctx.fs.copy_file(src, dst)
        print "        1 file(s) copied."
        return 0
    catch e:
        print "COPY: " + e
        return 1

# ------------------------------------------------------------------ MOVE

proc cmd_move(ctx, args):
    if len(args) < 2:
        print "MOVE: Syntax error"
        return 1
    let src = args[0]
    let dst = args[1]
    try:
        ctx.fs.move_file(src, dst)
        return 0
    catch e:
        print "MOVE: " + e
        return 1

# ------------------------------------------------------------------ DEL / ERASE

proc cmd_del(ctx, args):
    if len(args) == 0:
        print "DEL: Missing filename"
        return 1
    for arg in args:
        let path = arg
        try:
            ctx.fs.delete_file(path)
        catch e:
            print "DEL: " + e
            return 1
    return 0

# ------------------------------------------------------------------ REN / RENAME

proc cmd_ren(ctx, args):
    if len(args) < 2:
        print "REN: Syntax error"
        return 1
    let src = args[0]
    let dst = args[1]
    try:
        ctx.fs.rename_file(src, dst)
        return 0
    catch e:
        print "REN: " + e
        return 1

# ------------------------------------------------------------------ SHIFT

proc cmd_shift(ctx, args):
    ctx.shift_args()
    return 0

# ------------------------------------------------------------------ VER

proc cmd_ver(ctx, args):
    print "MS-DOS Batch 4.0 (SageBatch v1.0.0)"
    return 0

# ------------------------------------------------------------------ TITLE

proc cmd_title(ctx, args):
    if len(args) == 0:
        return 0
    let title = ""
    for arg in args:
        let val = arg
        if len(title) > 0:
            title = title + " "
        title = title + val
    print "\033]0;" + title + "\007"
    return 0

# ------------------------------------------------------------------ COLOR

proc cmd_color(ctx, args):
    if len(args) == 0:
        # Reset
        print "\033[0m"
        return 0
    let code = upper(args[0])
    if len(code) == 2:
        # bg = first, fg = second
        # Map DOS hex to ANSI is complex, just do a basic reset for now
        # since full DOS color translation is large. We'll support 0A-like.
        if code == "0A":
            print "\033[0;32m"
        elif code == "0C":
            print "\033[0;31m"
        else:
            print "\033[0m"
    return 0

# ------------------------------------------------------------------ PROMPT

proc cmd_prompt(ctx, args):
    if len(args) == 0:
        ctx.env.vars["PROMPT"] = "$P$G"
        return 0
    let new_prompt = ""
    for arg in args:
        let val = arg
        if len(new_prompt) > 0:
            new_prompt = new_prompt + " "
        new_prompt = new_prompt + val
    ctx.env.vars["PROMPT"] = new_prompt
    return 0

# ------------------------------------------------------------------ DATE / TIME / VOL / VERIFY

proc cmd_date(ctx, args):
    print "The current date is: Sat 06/27/2026"
    return 0

proc cmd_time(ctx, args):
    print "The current time is: 12:00:00.00"
    return 0

proc cmd_vol(ctx, args):
    print " Volume in drive C is SAGEBATCH"
    print " Volume Serial Number is 1234-ABCD"
    return 0

proc cmd_verify(ctx, args):
    if len(args) > 0:
        let st = upper(args[0])
        if st == "ON" or st == "OFF":
            return 0
    print "VERIFY is off."
    return 0

# ------------------------------------------------------------------ PUSHD / POPD

proc cmd_pushd(ctx, args):
    if len(args) == 0:
        print "PUSHD: Missing path"
        return 1
    let path = args[0]
    try:
        push(ctx.env.dir_stack, ctx.env.cwd)
        ctx.env.chdir(path)
        return 0
    catch e:
        pop(ctx.env.dir_stack)
        print "PUSHD: " + e
        return 1

proc cmd_popd(ctx, args):
    if len(ctx.env.dir_stack) == 0:
        return 1
    let path = pop(ctx.env.dir_stack)
    try:
        ctx.env.chdir(path)
        return 0
    catch e:
        print "POPD: " + e
        return 1

# ------------------------------------------------------------------ HELP

proc cmd_help(ctx, args):
    print "SageBatch internal commands:"
    print "  ECHO SET REM PAUSE CLS EXIT CD MD RD DIR TYPE COPY MOVE DEL REN SHIFT VER"
    print "  IF FOR GOTO CALL TITLE COLOR PROMPT DATE TIME VOL VERIFY PUSHD POPD"
    print "  PATH BREAK CHCP"
    return 0

# ------------------------------------------------------------------ PATH / BREAK / CHCP

proc cmd_path(ctx, args):
    if len(args) == 0:
        let p = ctx.env.vars["PATH"]
        if p == nil or p == "":
            print "PATH=(null)"
        else:
            print "PATH=" + p
        return 0
    let val = args[0]
    if val == ";":
        ctx.env.vars["PATH"] = ""
    else:
        ctx.env.vars["PATH"] = val
    return 0

proc cmd_break(ctx, args):
    if len(args) > 0:
        let st = upper(args[0])
        if st == "ON" or st == "OFF":
            return 0
    print "BREAK is off"
    return 0

proc cmd_chcp(ctx, args):
    if len(args) > 0:
        return 0
    print "Active code page: 437"
    return 0
