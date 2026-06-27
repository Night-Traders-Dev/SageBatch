import io
proc main():
    let b = io.readfile("hello.bat")
    print len(b)
main()
