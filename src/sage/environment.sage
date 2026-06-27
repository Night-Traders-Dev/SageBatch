# environment.sage — DOS-like environment block
# Phase 4: Manages PATH, TEMP, PROMPT, COMSPEC, ERRORLEVEL,
#          current directory, search paths, and process state.

import sys
import io

class Environment:
    proc init(self):
        self.vars        = {}    # string → string
        self.errorlevel  = 0
        self.cwd         = "/"  # current working directory
        self._init_defaults()

    proc _init_defaults(self):
        self.vars["PATH"]    = sys.getenv("PATH")
        self.vars["TEMP"]    = sys.getenv("TEMP")
        self.vars["COMSPEC"] = "BATCH.SAGE"
        self.vars["PROMPT"]  = "$P$G"
        self.vars["PATHEXT"] = ".BAT;.SAG;.EXE;.COM"

    proc set_var(self, name, value):
        self.vars[upper(name)] = value

    proc get_var(self, name):
        if dicthas(self.vars, upper(name)):
            return self.vars[upper(name)]
        return ""

    proc del_var(self, name):
        dictdelete(self.vars, upper(name))

    proc expand(self, text):
        let result = ""
        let i = 0
        while i < len(text):
            let ch = text[i]
            if ch == "%":
                let j = i + 1
                while j < len(text) and text[j] != "%":
                    j = j + 1
                if j < len(text):
                    let vname = slice(text, i + 1, j)
                    result = result + self.get_var(vname)
                    i = j + 1
                else:
                    result = result + ch
                    i = i + 1
            else:
                result = result + ch
                i = i + 1
        return result

    proc set_errorlevel(self, level):
        self.errorlevel = level
        self.vars["ERRORLEVEL"] = str(level)

    proc get_errorlevel(self):
        return self.errorlevel

    proc chdir(self, path):
        if io.isdir(path):
            self.cwd = path
            self.vars["CD"] = path
        else:
            raise "CD: Directory not found: " + path

    proc render_prompt(self):
        let p = self.get_var("PROMPT")
        let p = replace(p, "$P", self.cwd)
        let p = replace(p, "$G", ">")
        let p = replace(p, "$L", "<")
        let p = replace(p, "$N", "C")
        let p = replace(p, "$Q", "=")
        let p = replace(p, "$$", "$")
        return p
