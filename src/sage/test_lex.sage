import lexer
import token
import io
let src_code = io.readfile("../../benchmarks/nested_loop.bat")
let l = lexer.Lexer()
l.init(src_code)
let toks = l.tokenize()
for i in range(len(toks)):
    let t = toks[i]
    let k = "nil"
    if t.kind != nil: k = t.kind
    let v = "nil"
    if t.value != nil: v = t.value
    print k + " " + v + " " + str(t.line)
