# test_env.sage — Unit tests for environment.sage
import std.testing
from environment import Environment

let t = std.testing
let env = Environment()

# Test set/get
env.set_var("FOO", "bar")
t.assert_eq(env.get_var("FOO"), "bar", "set/get var")

# Test case-insensitivity
env.set_var("myvar", "hello")
t.assert_eq(env.get_var("MYVAR"), "hello", "case insensitive")

# Test expand
env.set_var("NAME", "Jacob")
let result = env.expand("Hello %NAME%!")
t.assert_eq(result, "Hello Jacob!", "variable expansion")

# Test ERRORLEVEL
env.set_errorlevel(3)
t.assert_eq(env.get_errorlevel(), 3, "errorlevel set/get")

# Test dir_stack (PUSHD/POPD foundation)
t.assert_eq(len(env.dir_stack), 0, "initial dir_stack empty")
push(env.dir_stack, "/foo")
t.assert_eq(len(env.dir_stack), 1, "dir_stack push")
t.assert_eq(pop(env.dir_stack), "/foo", "dir_stack pop")

print "environment tests passed."
