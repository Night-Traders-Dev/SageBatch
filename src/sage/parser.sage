# parser.sage — Batch 4.0 recursive-descent parser
# Phase 2: Consumes the token stream produced by lexer.sage and
# produces an AST using node types from ast.sage.
#
# Grammar summary:
#   program      := statement* EOF
#   statement    := ( label | goto | call | if | for | assignment
#                   | redirect | pipe | command ) NEWLINE*
#   label        := LABEL
#   goto         := GOTO WORD
#   call         := CALL WORD args*
#   if           := IF [NOT] condition statement [ELSE statement]
#   for          := FOR WORD IN list DO statement
#   assignment   := SET WORD=value
#   redirect     := statement REDIRECT WORD
#   pipe         := statement PIPE statement
#   command      := WORD args*

from token import TOK_WORD, TOK_STRING, TOK_VARIABLE, TOK_LABEL
from token import TOK_OPERATOR, TOK_REDIRECT, TOK_PIPE, TOK_NEWLINE
from token import TOK_EOF, TOK_AMP, TOK_PAREN_L, TOK_PAREN_R, TOK_AT
from ast import Program, Command, Assignment, IfStatement, ForStatement
from ast import LabelNode, GotoNode, CallNode, RedirectNode, PipeNode, BlockNode

class Parser:
    proc init(self, tokens):
        self.tokens = tokens
        self.pos    = 0

    # ------------------------------------------------------------------ helpers

    proc peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return nil

    proc peek_kind(self):
        let t = self.peek()
        if t != nil:
            return t.kind
        return TOK_EOF

    proc advance(self):
        let t = self.tokens[self.pos]
        self.pos = self.pos + 1
        return t

    proc expect(self, kind):
        let t = self.advance()
        if t.kind != kind:
            raise "Parse error: expected " + kind + " got " + t.kind + " at line " + str(t.line)
        return t

    proc skip_newlines(self):
        while self.peek_kind() == TOK_NEWLINE:
            self.advance()

    proc at_end(self):
        return self.peek_kind() == TOK_EOF

    ## Collect remaining value tokens on this logical line.
    proc collect_args(self):
        let args = []
        while self.peek_kind() != TOK_NEWLINE and self.peek_kind() != TOK_EOF
              and self.peek_kind() != TOK_REDIRECT and self.peek_kind() != TOK_PIPE
              and self.peek_kind() != TOK_AMP and self.peek_kind() != TOK_PAREN_R:
            push(args, self.advance())
        return args

    ## Parse a block: ( statement* )
    proc parse_block(self):
        let line = self.peek().line
        self.expect(TOK_PAREN_L)
        self.skip_newlines()
        let stmts = []
        while self.peek_kind() != TOK_PAREN_R and not self.at_end():
            let s = self.parse_statement()
            if s != nil:
                push(stmts, s)
            self.skip_newlines()
        self.expect(TOK_PAREN_R)
        return BlockNode(stmts, line)

    # ------------------------------------------------------------------ statement dispatch

    proc parse_statement(self):
        self.skip_newlines()
        if self.at_end():
            return nil

        let suppress = false
        if self.peek_kind() == TOK_AT:
            self.advance()
            suppress = true

        let t = self.peek()
        if t == nil:
            return nil

        if t.kind == TOK_LABEL:
            return self.parse_label()

        if t.kind == TOK_PAREN_L:
            return self.parse_block()

        if t.kind != TOK_WORD:
            # Unknown token on a line start — treat as bare command
            return self.parse_command(suppress)

        let kw = t.value  # already uppercased by lexer

        if kw == "REM":
            return self.parse_rem()
        if kw == "GOTO":
            return self.parse_goto()
        if kw == "CALL":
            return self.parse_call(suppress)
        if kw == "IF":
            return self.parse_if(suppress)
        if kw == "FOR":
            return self.parse_for(suppress)
        if kw == "SET":
            return self.parse_set(suppress)
        if kw == "ECHO" or kw == "PAUSE" or kw == "CLS" or kw == "EXIT"
           or kw == "CD" or kw == "MD" or kw == "RD" or kw == "DIR"
           or kw == "TYPE" or kw == "COPY" or kw == "MOVE" or kw == "DEL"
           or kw == "REN" or kw == "SHIFT" or kw == "VER" or kw == "HELP":
            return self.parse_command(suppress)

        return self.parse_command(suppress)

    # ------------------------------------------------------------------ node parsers

    proc parse_label(self):
        let t = self.advance()
        return LabelNode(t.value, t.line)

    proc parse_rem(self):
        let line = self.peek().line
        self.advance()  # consume REM
        # Skip to end of line
        while self.peek_kind() != TOK_NEWLINE and not self.at_end():
            self.advance()
        return nil   # REM produces no AST node

    proc parse_goto(self):
        let line = self.advance().line  # consume GOTO
        let target = self.expect(TOK_WORD)
        return GotoNode(target.value, line)

    proc parse_call(self, suppress):
        let line = self.advance().line  # consume CALL
        let is_sub = false
        let t = self.peek()
        if t != nil and t.kind == TOK_LABEL:
            is_sub = true
            self.advance()
            return CallNode(t.value, self.collect_args(), is_sub, line)
        let target = self.expect(TOK_WORD)
        return CallNode(target.value, self.collect_args(), false, line)

    proc parse_if(self, suppress):
        let line = self.advance().line  # consume IF
        let negated = false
        if self.peek_kind() == TOK_WORD and self.peek().value == "NOT":
            self.advance()
            negated = true

        let condition = self.parse_condition()
        let consequent = self.parse_statement()
        let alternate = nil
        if self.peek_kind() == TOK_WORD and self.peek().value == "ELSE":
            self.advance()
            alternate = self.parse_statement()
        return IfStatement(negated, condition, consequent, alternate, line)

    proc parse_condition(self):
        let t = self.peek()
        if t == nil:
            raise "Parse error: expected condition"
        let kw = t.value

        if kw == "EXIST":
            self.advance()
            let path = self.advance()
            return {"type": "EXIST", "path": path.value}

        if kw == "DEFINED":
            self.advance()
            let vname = self.advance()
            return {"type": "DEFINED", "name": vname.value}

        if kw == "ERRORLEVEL":
            self.advance()
            let level = self.advance()
            return {"type": "ERRORLEVEL", "level": level.value}

        # String comparison: left op right
        let left = self.advance()
        let op   = self.advance()   # == EQU NEQ LSS GTR LEQ GEQ
        let right = self.advance()
        return {"type": "CMP", "left": left.value, "op": op.value, "right": right.value}

    proc parse_for(self, suppress):
        let line = self.advance().line  # consume FOR
        let flags = {}
        # Optional switches: /F /D /R /L
        while self.peek_kind() == TOK_WORD and startswith(self.peek().value, "/"):
            let sw = self.advance().value
            flags[sw] = true
        let var_tok = self.advance()   # %A
        self.expect(TOK_WORD)          # IN
        self.expect(TOK_PAREN_L)       # (
        let in_list = []
        while self.peek_kind() != TOK_PAREN_R and not self.at_end():
            push(in_list, self.advance())
        self.expect(TOK_PAREN_R)       # )
        self.expect(TOK_WORD)          # DO
        let body = self.parse_statement()
        let vname = var_tok.value
        if startswith(vname, "%"):
            vname = slice(vname, 1, len(vname))
        return ForStatement(vname, in_list, body, flags, line)

    proc parse_set(self, suppress):
        let line = self.advance().line  # consume SET
        # Collect the entire rest of line as raw text for VAR=VALUE parsing
        let parts = self.collect_args()
        # Rejoin tokens to find the = split
        let raw = ""
        for p in parts:
            raw = raw + p.value
        let eq = find(raw, "=")
        if eq < 0:
            # SET with no = just prints variable
            return Command("SET", parts, suppress, line)
        let vname = slice(raw, 0, eq)
        let vval  = slice(raw, eq + 1, len(raw))
        return Assignment(upper(vname), vval, line)

    proc parse_command(self, suppress):
        let t = self.advance()
        let line = t.line
        let name = t.value
        let args = self.collect_args()
        let cmd = Command(name, args, suppress, line)
        # Peek for redirect or pipe chaining
        if self.peek_kind() == TOK_REDIRECT:
            let op = self.advance()
            let fname = self.advance()
            return RedirectNode(cmd, op.value, fname.value, line)
        if self.peek_kind() == TOK_PIPE:
            self.advance()
            let right = self.parse_statement()
            return PipeNode(cmd, right, line)
        return cmd

    ## ( statement* ) — block node
    proc parse_paren_block(self):
        return self.parse_block()

    # ------------------------------------------------------------------ entry

    proc parse(self):
        let stmts = []
        self.skip_newlines()
        while not self.at_end():
            let s = self.parse_statement()
            if s != nil:
                push(stmts, s)
            self.skip_newlines()
        return Program(stmts)
