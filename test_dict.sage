proc test():
    raise {"a": 1}

proc main():
    try:
        test()
    catch e:
        if type(e) == "dict":
            print "Caught dict"
        else:
            print "Caught other"

main()
