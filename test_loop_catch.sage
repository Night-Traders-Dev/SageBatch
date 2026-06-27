proc test():
    raise {"a": 1}

proc main():
    print "Start"
    let i = 0
    while i < 10000:
        try:
            test()
        catch e:
            i = i + 1
    print "Done"

main()
