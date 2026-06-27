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

    proc current(self):
        return self.tokens[self.pos]

    proc peek_kind(self):
        return self.current().kind

    proc advance(self):
        let t = self.current()
        if self.pos < len(self.tokens) - 1:
            self.pos = self.pos + 1
        return t

    proc expect(self, kind):
        if self.peek_kind() != kind:
            raise "Parse error at line " + str(self.current().line) + ": expected " + kind + " got " + self.peek_kind()
        return self.advance()

    proc skip_newlines(self):
        while self.peek_kind() == TOK_NEWLINE:
            self.advance()

    proc at_end(self):
        return self.peek_kind() == TOK_EOF

    proc is_value_token(self):
        let k = self.peek_kind()
        return k == TOK_WORD or k == TOK_STRING or k == TOK_VARIABLE

    # ------------------------------------------------------------------ arg collection

    proc collect_args(self):
        """ Collect remaining value tokens on this logical line. """
        let args = []
        while self.is_value_token():
            push(args, self.advance())
        return args

    # ------------------------------------------------------------------ condition parsing

    proc parse_condition(self):
        """
        Handles:
          EXIST <file>
          ERRORLEVEL <n>
          <string> == <string>
          <string> EQU <string>   (extended operators)
        """
        let cond = {}
        if self.peek_kind() == TOK_WORD and upper(self.current().value) == "EXIST":
            self.advance()
            let file_tok = self.advance()
            cond["type"]  = "EXIST"
            cond["value"] = file_tok.value
        elif self.peek_kind() == TOK_WORD and upper(self.current().value) == "ERRORLEVEL":
            self.advance()
            let level = self.advance()
            cond["type"]  = "ERRORLEVEL"
            cond["value"] = level.value
        else:
            let left = self.advance()
            let op   = self.advance()
            let right = self.advance()
            cond["type"]  = "COMPARE"
            cond["left"]  = left.value
            cond["op"]    = op.value
            cond["right"] = right.value
        return cond

    # ------------------------------------------------------------------ statement parsers

    proc parse_label(self):
        let tok = self.advance()   # the LABEL token
        return LabelNode(tok.value, tok.line)

    proc parse_goto(self, line):
        self.advance()             # consume GOTO
        let target = self.expect(TOK_WORD)
        return GotoNode(upper(target.value), line)

    proc parse_call(self, line):
        self.advance()             # consume CALL
        let is_sub = false
        let target_tok = self.advance()
        let target = target_tok.value
        if startswith(target, ":"):
            is_sub = true
            target = slice(target, 1, len(target))
        let args = self.collect_args()
        return CallNode(upper(target), args, is_sub, line)

    proc parse_if(self, line, suppress):
        self.advance()             # consume IF
        let negated = false
        if self.peek_kind() == TOK_WORD and upper(self.current().value) == "NOT":
            self.advance()
            negated = true
        let condition = self.parse_condition()
        let consequent = self.parse_statement()
        let alternate = nil
        if self.peek_kind() == TOK_WORD and upper(self.current().value) == "ELSE":
            self.advance()
            alternate = self.parse_statement()
        return IfStatement(negated, condition, consequent, alternate, line)

    proc parse_for(self, line):
        self.advance()             # consume FOR
        # optional switches /F /L /R etc. — store as flags dict
        let flags = {}
        while self.peek_kind() == TOK_WORD and startswith(self.current().value, "/"):
            let flag = self.advance()
            flags[flag.value] = true
        # variable name: %A  (token value is "A" after % stripping by lexer)
        let var_tok = self.advance()
        let var_name = var_tok.value
        # IN
        if self.peek_kind() == TOK_WORD and upper(self.current().value) == "IN":
            self.advance()
        # ( list )
        self.expect(TOK_PAREN_L)
        let in_list = []
        while self.peek_kind() != TOK_PAREN_R and not self.at_end():
            push(in_list, self.advance())
        self.expect(TOK_PAREN_R)
        # DO
        if self.peek_kind() == TOK_WORD and upper(self.current().value) == "DO":
            self.advance()
        let body = self.parse_statement()
        return ForStatement(var_name, in_list, body, flags, line)

    proc parse_set(self, line, suppress):
        self.advance()             # consume SET
        # Expect WORD that contains "="
        let tok = self.advance()
        let raw = tok.value
        let eq  = indexof(raw, "=")
        if eq < 0:
            # SET with no = — print variable or all variables
            return Command("SET", [tok], suppress, line)
        let name = slice(raw, 0, eq)
        let val  = slice(raw, eq + 1, len(raw))
        return Assignment(name, val, line)

    proc parse_block(self):
        """ ( statement* ) """
        let line = self.current().line
        self.expect(TOK_PAREN_L)
        self.skip_newlines()
        let stmts = []
        while self.peek_kind() != TOK_PAREN_R and not self.at_end():
            push(stmts, self.parse_statement())
            self.skip_newlines()
        self.expect(TOK_PAREN_R)
        return BlockNode(stmts, line)

    proc parse_command(self, name_tok, suppress):
        let args = self.collect_args()
        let cmd = Command(name_tok.value, args, suppress, name_tok.line)
        # Check for redirect after command
        if self.peek_kind() == TOK_REDIRECT:
            let op_tok   = self.advance()
            let file_tok = self.advance()
            return RedirectNode(cmd, op_tok.value, file_tok.value, op_tok.line)
        # Check for pipe
        if self.peek_kind() == TOK_PIPE:
            let pipe_line = self.current().line
            self.advance()
            let right = self.parse_statement()
            return PipeNode(cmd, right, pipe_line)
        return cmd

    proc parse_statement(self):
        self.skip_newlines()
        if self.at_end():
            return nil

        let suppress = false
        if self.peek_kind() == TOK_AT:
            self.advance()
            suppress = true

        let line = self.current().line

        # LABEL
        if self.peek_kind() == TOK_LABEL:
            return self.parse_label()

        # PAREN_L — block
        if self.peek_kind() == TOK_PAREN_L:
            return self.parse_block()

        # Keyword dispatch
        if self.peek_kind() == TOK_WORD:
            let word = upper(self.current().value)
            if word == "GOTO":
                return self.parse_goto(line)
            if word == "CALL":
                return self.parse_call(line)
            if word == "IF":
                return self.parse_if(line, suppress)
            if word == "FOR":
                return self.parse_for(line)
            if word == "SET":
                return self.parse_set(line, suppress)
            # Generic command
            let name_tok = self.advance()
            return self.parse_command(name_tok, suppress)

        # Fallback: skip unknown token
        self.advance()
        return nil

    # ------------------------------------------------------------------ entry

    proc parse(self):
        let stmts = []
        self.skip_newlines()
        while not self.at_end():
            let stmt = self.parse_statement()
            if stmt != nil:
                push(stmts, stmt)
            self.skip_newlines()
        return Program(stmts)
