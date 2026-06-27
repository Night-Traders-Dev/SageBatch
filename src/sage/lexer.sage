# lexer.sage — Batch 4.0 lexer (tokenizer)
# Phase 1: Converts raw .BAT source into a flat token stream.
# Handles: WORD, STRING, VARIABLE (%X% and !X!), LABEL (:LBL),
#          REDIRECT (> >> <), PIPE (|), NEWLINE, AMP (&), parens, @.

from token import Token, TOK_WORD, TOK_STRING, TOK_VARIABLE, TOK_LABEL
from token import TOK_OPERATOR, TOK_REDIRECT, TOK_PIPE, TOK_NEWLINE
from token import TOK_EOF, TOK_AMP, TOK_PAREN_L, TOK_PAREN_R, TOK_AT
import string

class Lexer:
    proc init(self, source):
        self.source  = source
        self.pos     = 0
        self.line    = 1
        self.tokens  = []

    # ------------------------------------------------------------------ helpers

    proc peek(self):
        if self.pos < len(self.source):
            return self.source[self.pos]
        return nil

    proc advance(self):
        let ch = self.source[self.pos]
        self.pos = self.pos + 1
        if ch == "\n":
            self.line = self.line + 1
        return ch

    proc match_char(self, expected):
        if self.pos < len(self.source) and self.source[self.pos] == expected:
            self.pos = self.pos + 1
            return true
        return false

    proc skip_whitespace_inline(self):
        # Skip spaces and tabs but NOT newlines
        while self.pos < len(self.source):
            let ch = self.source[self.pos]
            if ch == " " or ch == "\t":
                self.pos = self.pos + 1
            else:
                break

    proc emit(self, kind, value):
        push(self.tokens, Token(kind, value, self.line))

    # ------------------------------------------------------------------ scanners

    proc scan_string(self):
        # Consume opening quote already consumed by caller
        let buf = ""
        while self.pos < len(self.source):
            let ch = self.advance()
            if ch == "\"":
                break
            buf = buf + ch
        self.emit(TOK_STRING, buf)

    proc scan_variable(self, delayed):
        # %VAR% — delayed=false   !VAR! — delayed=true
        let buf = ""
        let closer = "%"
        if delayed:
            closer = "!"
        while self.pos < len(self.source):
            let ch = self.advance()
            if ch == closer:
                break
            buf = buf + ch
        self.emit(TOK_VARIABLE, buf)

    proc scan_word(self, first_char):
        let buf = first_char
        let specials = ">< |&()\"\n\r\t%!"
        while self.pos < len(self.source):
            let ch = self.source[self.pos]
            if contains(specials, ch):
                break
            buf = buf + self.advance()
        self.emit(TOK_WORD, upper(buf))

    proc scan_redirect(self, first_char):
        let buf = first_char
        if self.peek() == ">" or self.peek() == "&":
            buf = buf + self.advance()
        self.emit(TOK_REDIRECT, buf)

    proc scan_comment(self):
        # REM line — skip everything to newline
        while self.pos < len(self.source) and self.source[self.pos] != "\n":
            self.pos = self.pos + 1

    # ------------------------------------------------------------------ main loop

    proc tokenize(self):
        while self.pos < len(self.source):
            let ch = self.advance()

            if ch == "\r":
                continue

            if ch == "\n":
                self.emit(TOK_NEWLINE, "\n")
                continue

            if ch == " " or ch == "\t":
                self.skip_whitespace_inline()
                continue

            if ch == "@":
                self.emit(TOK_AT, "@")
                continue

            if ch == ":":
                # Could be :LABEL or :: comment
                if self.peek() == ":":
                    self.scan_comment()
                else:
                    let buf = ""
                    while self.pos < len(self.source) and self.source[self.pos] != "\n" and self.source[self.pos] != " ":
                        buf = buf + self.advance()
                    self.emit(TOK_LABEL, upper(buf))
                continue

            if ch == "%":
                if self.peek() != nil:
                    self.scan_variable(false)
                continue

            if ch == "!":
                if self.peek() != nil:
                    self.scan_variable(true)
                continue

            if ch == "\"":
                self.scan_string()
                continue

            if ch == "|":
                self.emit(TOK_PIPE, "|")
                continue

            if ch == "&":
                self.emit(TOK_AMP, "&")
                continue

            if ch == "(":
                self.emit(TOK_PAREN_L, "(")
                continue

            if ch == ")":
                self.emit(TOK_PAREN_R, ")")
                continue

            if ch == ">" or ch == "<":
                self.scan_redirect(ch)
                continue

            # Default: bare word
            self.scan_word(ch)

        self.emit(TOK_EOF, nil)
        return self.tokens
