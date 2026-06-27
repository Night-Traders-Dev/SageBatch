# ast.sage — AST node definitions for the BatchSage parser
# Phase 2: Defines the typed node tree that the interpreter walks.
#
# Node hierarchy:
#   Program
#   Command
#   IfStatement
#   ForStatement
#   LabelNode
#   GotoNode
#   CallNode
#   Assignment
#   RedirectNode
#   PipeNode

class Program:
    proc init(self, statements):
        self.statements = statements   # Array of statement nodes


class Command:
    proc init(self, name, args, suppress, line):
        self.name     = name
        self.args     = args
        self.suppress = suppress
        self.line     = line


class Assignment:
    proc init(self, name, value, line):
        self.name  = name
        self.value = value
        self.line  = line


class IfStatement:
    proc init(self, negated, condition, consequent, alternate, line):
        self.negated    = negated
        self.condition  = condition
        self.consequent = consequent   # Statement or block
        self.alternate  = alternate    # nil or statement
        self.line       = line


class ForStatement:
    proc init(self, var_name, in_list, body, flags, line):
        self.var_name = var_name    # e.g. "A"
        self.in_list  = in_list     # array of tokens / glob patterns
        self.body     = body        # statement
        self.flags    = flags       # dict of /F switches etc.
        self.line     = line


class LabelNode:
    proc init(self, name, line):
        self.name = name
        self.line = line


class GotoNode:
    proc init(self, target, line):
        self.target = target
        self.line   = line


class CallNode:
    proc init(self, target, args, is_subroutine, line):
        self.target        = target
        self.args          = args
        self.is_subroutine = is_subroutine
        self.line          = line


class RedirectNode:
    proc init(self, inner, op, filename, line):
        self.inner    = inner
        self.op       = op
        self.filename = filename
        self.line     = line


class PipeNode:
    proc init(self, left, right, line):
        self.left  = left
        self.right = right
        self.line  = line


class BlockNode:
    proc init(self, statements, line):
        self.statements = statements
        self.line       = line
