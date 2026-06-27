import sys
proc main():
    let vars = {}
    vars["TEMP"] = sys.getenv("TEMP")
    print "DONE"
main()
