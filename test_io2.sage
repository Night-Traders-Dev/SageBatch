import io
proc main():
    let my_io = io._Io()
    print my_io.exists("hello.bat")
main()
