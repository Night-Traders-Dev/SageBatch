class LabelNode:
    proc init(self, name):
        self.name = name

proc main():
    let node = LabelNode("LOOP")
    print type(node)
main()
