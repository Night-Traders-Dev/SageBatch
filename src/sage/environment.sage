# environment.sage — DOS-like environment block
# Phase 4: Manages PATH, TEMP, PROMPT, COMSPEC, ERRORLEVEL,
#          current directory, search paths, and process state.

import sys
import io

class Environment:
    proc init(self):
        let d = {}
        self.vars        = d    # string → string
        self.errorlevel  = 0
        self.cwd         = "/"  # current working directory
        self._init_defaults()

    proc _init_defaults(self):
        let p1 = sys.getenv("PATH")
        let k_path = "PATH"
        self.vars[k_path] = p1
        
        let p2 = sys.getenv("TEMP")
        let k_temp = "TEMP"
        self.vars[k_temp] = p2
        
        let v1 = "BATCH.SAGE"
        let k_comspec = "COMSPEC"
        self.vars[k_comspec] = v1
        
        let v2 = "$P$G"
        let k_prompt = "PROMPT"
        self.vars[k_prompt] = v2
        
        let v3 = ".BAT;.SAG;.EXE;.COM"
        let k_pathext = "PATHEXT"
        self.vars[k_pathext] = v3

    proc set_var(self, name, value):
        let uname = upper(name)
        let v = self.vars
        v[uname] = value

    proc get_var(self, name):
        let uname = upper(name)
        let v = self.vars
        if dict_has(v, uname):
            return v[uname]
        return ""

    proc del_var(self, name):
        let uname = upper(name)
        let v = self.vars
        dict_delete(v, uname)

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
