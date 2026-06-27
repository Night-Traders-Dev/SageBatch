# token.sage — Token type definitions for the BatchSage lexer
# Phase 1: Lexer token contract

# Token type constants
let TOK_WORD       = "WORD"       # bare word / command name
let TOK_STRING     = "STRING"     # double-quoted string
let TOK_VARIABLE   = "VARIABLE"   # %VAR% or !VAR!
let TOK_LABEL      = "LABEL"      # :LABEL
let TOK_OPERATOR   = "OPERATOR"   # ==, NEQ, LSS, GTR, etc.
let TOK_REDIRECT   = "REDIRECT"   # > >> < 2>
let TOK_PIPE       = "PIPE"       # |
let TOK_NEWLINE    = "NEWLINE"    # end of logical line
let TOK_EOF        = "EOF"        # end of source
let TOK_AMP        = "AMP"        # & (command separator)
let TOK_PAREN_L    = "PAREN_L"    # (
let TOK_PAREN_R    = "PAREN_R"    # )
let TOK_AT         = "AT"         # @ prefix (suppress echo)

class Token:
    proc init(self, kind, value, line):
        self.kind  = kind
        self.value = value
        self.line  = line

    proc __str__(self):
        return "Token(" + self.kind + ", " + str(self.value) + ", line=" + str(self.line) + ")"
