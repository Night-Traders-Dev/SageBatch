# BatchSage.md
# MS-DOS Batch Clone in Pure Sage

## Project Name

BatchSage

A clean-room implementation of the classic MS-DOS Batch language and command processor written entirely in Sage.

Goals:

- Execute traditional .BAT files
- Teach scripting using classic DOS concepts
- Run legacy educational examples
- Integrate with SageOS
- Provide a modern implementation while preserving DOS behavior

---

# Architecture

BatchSage consists of:

1. Command Processor
2. Batch Interpreter
3. Runtime Environment
4. Compatibility Layer
5. Development Tools

---

# Core Features

## Command Processor

Responsibilities:

- Parse commands
- Execute internal commands
- Execute external programs
- Manage environment variables
- Handle redirection
- Handle pipes

Supported syntax:

```bat
DIR
COPY FILE1.TXT FILE2.TXT
DEL *.TMP
```

---

# Language Features

## Variables

```bat
SET NAME=Jacob
ECHO %NAME%
```

Support:

- SET
- Environment expansion
- Delayed expansion
- Nested expansion

---

## Labels

```bat
:START
ECHO HELLO
GOTO START
```

Implement:

- Label table
- Fast lookup
- Jump validation

---

## Conditional Execution

```bat
IF EXIST TEST.TXT ECHO FOUND
```

Support:

- IF
- NOT
- ERRORLEVEL
- EXIST
- String comparison
- Numeric comparison

---

## Loops

DOS FOR support:

```bat
FOR %%A IN (*.TXT) DO ECHO %%A
```

Implement:

- File iteration
- List iteration
- Variable expansion
- Nested loops

---

## CALL

```bat
CALL OTHER.BAT
```

Implement:

- Nested batch execution
- Return stack
- Argument forwarding

---

## GOTO

```bat
GOTO MENU
```

Implement:

- Label resolution
- Error handling

---

# Internal Commands

Required V1:

- ECHO
- SET
- IF
- FOR
- GOTO
- CALL
- PAUSE
- REM
- SHIFT
- EXIT
- CLS
- CD
- MD
- RD
- COPY
- MOVE
- DEL
- REN
- TYPE
- DIR

---

# Runtime Environment

Implement DOS-like environment:

Environment Block:

```text
PATH
TEMP
PROMPT
COMSPEC
``

Maintain:

- Current directory
- Search paths
- Error levels
- Process state

---

# Parser Design

## Lexer

Token Types:

- WORD
- STRING
- VARIABLE
- LABEL
- OPERATOR
- REDIRECT

Example:

```bat
ECHO %USERNAME%
```

Produces:

WORD(ECHO)
VARIABLE(USERNAME)

---

## Parser

Build AST:

- Program
- Command
- IfStatement
- ForStatement
- Label
- Goto
- Call
- Assignment

---

# Execution Engine

Pipeline:

Source
→ Lexer
→ Parser
→ AST
→ Executor

Interpreter first.

Compiler later.

---

# DOS Compatibility

Target:

MS-DOS 5.0
MS-DOS 6.x
PC-DOS
Windows 95 command interpreter

Behavioral Compatibility:

- ERRORLEVEL
- Variable expansion
- Label processing
- Batch argument handling

---

# Command Line Arguments

Support:

```bat
%0
%1
%2
...
%9
```

And:

```bat
SHIFT
```

---

# File Redirection

Support:

```bat
DIR > FILE.TXT
DIR >> FILE.TXT
TYPE FILE.TXT > OUT.TXT
```

Implement:

- stdout redirection
- append mode
- stderr support later

---

# Pipes

Support:

```bat
DIR | FIND TXT
```

Architecture:

- Pipe buffers
- Process chaining
- Stream interfaces

---

# Sage Runtime Objects

Core classes:

- BatchProcess
- Environment
- CommandContext
- VariableStore
- FileSystem
- CommandRegistry
- ScriptExecutor

---

# SageOS Integration

Future Goals:

- Default scripting language
- Login scripts
- Build scripts
- Package scripts
- Installer scripts

---

# IDE (Optional)

BatchStudio

Features:

- Syntax highlighting
- Script debugger
- Variable watch window
- Step execution
- Error inspector

---

# Test Suite

Required Tests:

- Variable expansion
- IF statements
- FOR loops
- Nested CALL
- GOTO jumps
- Redirection
- Pipes
- Argument passing

---

# Milestones

## Phase 0

Repository setup

## Phase 1

Lexer

## Phase 2

Parser

## Phase 3

Interpreter

## Phase 4

Environment variables

## Phase 5

Internal commands

## Phase 6

File redirection

## Phase 7

Pipes

## Phase 8

DOS compatibility suite

## Phase 9

BatchStudio IDE

---

# Repository Layout

BatchSage/
├── compiler/
├── runtime/
├── commands/
├── filesystem/
├── parser/
├── tests/
├── docs/
├── tools/
└── examples/

---

# Long-Term Vision

BatchSage should be capable of:

- Running most educational DOS batch scripts unmodified
- Serving as a scripting language for SageOS
- Teaching command-line automation
- Providing a bridge between DOS-era scripting and modern Sage development

