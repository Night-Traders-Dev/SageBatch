import sys
proc main():
    let a = sys.args()
    print "LEN: " + str(len(a))
    if len(a) > 0:
        print "ARG 0: " + a[0]
    if len(a) > 1:
        print "ARG 1: " + a[1]
main()
