# varstore.sage — Variable store with FOR-loop variable scoping
# Extends Environment.vars with layered scope support
# so FOR loop variables (%A) don't leak into global scope.

class VarStore:
    proc init(self, env):
        self.env    = env       # base Environment
        self.scopes = [{}]      # stack of dicts; scopes[0] is innermost

    proc push_scope(self):
        push(self.scopes, {})

    proc pop_scope(self):
        if len(self.scopes) > 1:
            pop(self.scopes)

    proc set_local(self, name, value):
        self.scopes[len(self.scopes) - 1][upper(name)] = value

    proc get(self, name):
        # Search scopes innermost-first
        let i = len(self.scopes) - 1
        while i >= 0:
            if dicthas(self.scopes[i], upper(name)):
                return self.scopes[i][upper(name)]
            i = i - 1
        return self.env.get_var(name)

    proc set(self, name, value):
        # Write to environment (global)
        self.env.set_var(name, value)

    ## Like env.expand but checks scoped vars first.
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
                    result = result + self.get(vname)
                    i = j + 1
                else:
                    result = result + ch
                    i = i + 1
            else:
                result = result + ch
                i = i + 1
        return result
