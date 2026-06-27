# varstore.sage — Variable store with FOR-loop variable scoping
# Extends Environment.vars with layered scope support
# so FOR loop variables (%A) don't leak into global scope.

class VarStore:
    proc init(self, env):
        self.env    = env       # base Environment
        let d = {}
        let arr = [d]
        self.scopes = arr       # stack of dicts; scopes[0] is innermost

    proc push_scope(self):
        let arr = self.scopes
        let d = {}
        push(arr, d)

    proc pop_scope(self):
        let arr = self.scopes
        if len(arr) > 1:
            pop(arr)

    proc set_local(self, name, value):
        let arr = self.scopes
        let idx = len(arr) - 1
        let d = arr[idx]
        let uname = upper(name)
        d[uname] = value

    proc get(self, name):
        let arr = self.scopes
        let i = len(arr) - 1
        let uname = upper(name)
        while i >= 0:
            let d = arr[i]
            if dict_has(d, uname):
                return d[uname]
            i = i - 1
        let e = self.env
        return e.get_var(name)

    proc set(self, name, value):
        let e = self.env
        e.set_var(name, value)

    proc expand(self, text):
        let result = ""
        let i = 0
        let pct = "%"
        while i < len(text):
            let ch = text[i]
            if ch == pct:
                let j = i + 1
                while j < len(text):
                    let ch2 = text[j]
                    if ch2 == pct:
                        break
                    j = j + 1
                if j < len(text):
                    let vname = slice(text, i + 1, j)
                    result = result + self.get(vname)
                    i = j + 1
                else:
                    result = result + ch
                    i = i + 1
            else:
                result = result + ch
                i = i + 1
        return result
