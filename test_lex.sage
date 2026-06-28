import src.sage.lexer as lexer
import io
let src_code = io.readfile("benchmarks/nested_loop.bat")
let l = lexer.Lexer()
l.init(src_code)
let toks = l.tokenize()
for i in range(len(toks)):
    print str(toks[i])
