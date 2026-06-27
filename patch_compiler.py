import sys

with open("deps/SageLang/core/src/c/compiler.c", "r") as f:
    content = f.read()

target = """        "static SageValue sage_construct(const char* class_name, const char* "\\
        "parent_name, int argc, SageValue* argv) {\\n"\\
        "    sage_gc_pin();\\n"\\
        "    SageValue inst = sage_make_dict();\\n"\\
        "    sage_dict_set(inst.as.dict, \\"__class__\\", "\\
        "sage_string(class_name));\\n"\\
        "    if (parent_name != NULL) sage_dict_set(inst.as.dict, "\\
        "\\"__parent__\\", sage_string(parent_name));\\n"\\
        "    sage_gc_unpin();\\n"\\
        "    const char* current = class_name;\\n"\\
        "    while (current != NULL) {\\n"\\
        "        for (int i = 0; i < sage_method_count; i++) {\\n"\\
        "            if (strcmp(sage_method_table[i].class_name, current) == 0 "\\
        "&&\\n"\\
        "                strcmp(sage_method_table[i].method_name, \\"init\\") == "\\
        "0) {\\n"\\
        "                sage_method_table[i].fn(inst, argc, argv);\\n"\\
        "                return inst;\\n"\\
        "            }\\n"\\
        "        }\\n"\\
        "        current = parent_name;\\n"\\
        "        parent_name = NULL;\\n"\\
        "    }\\n"\\
        "    return inst;\\n"\\
        "}\\n\""""
        
replacement = """        "static SageValue sage_construct(const char* class_name, const char* "\\
        "parent_name, int argc, SageValue* argv) {\\n"\\
        "    sage_gc_pin();\\n"\\
        "    SageValue inst = sage_make_dict();\\n"\\
        "    sage_dict_set(inst.as.dict, \\"__class__\\", "\\
        "sage_string(class_name));\\n"\\
        "    if (parent_name != NULL) sage_dict_set(inst.as.dict, "\\
        "\\"__parent__\\", sage_string(parent_name));\\n"\\
        "    sage_gc_unpin();\\n"\\
        "    SageSlot inst_slot = sage_slot_undefined();\\n"\\
        "    SageSlot* sage_gc_roots[1] = {&inst_slot};\\n"\\
        "    SageGcFrame sage_gc_frame;\\n"\\
        "    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);\\n"\\
        "    sage_define_slot(&inst_slot, inst);\\n"\\
        "    const char* current = class_name;\\n"\\
        "    while (current != NULL) {\\n"\\
        "        for (int i = 0; i < sage_method_count; i++) {\\n"\\
        "            if (strcmp(sage_method_table[i].class_name, current) == 0 "\\
        "&&\\n"\\
        "                strcmp(sage_method_table[i].method_name, \\"init\\") == "\\
        "0) {\\n"\\
        "                sage_method_table[i].fn(inst, argc, argv);\\n"\\
        "                sage_gc_pop_frame(&sage_gc_frame);\\n"\\
        "                return inst;\\n"\\
        "            }\\n"\\
        "        }\\n"\\
        "        current = parent_name;\\n"\\
        "        parent_name = NULL;\\n"\\
        "    }\\n"\\
        "    sage_gc_pop_frame(&sage_gc_frame);\\n"\\
        "    return inst;\\n"\\
        "}\\n\""""

target = target.replace("\\\n", "\n")
replacement = replacement.replace("\\\n", "\n")

content = content.replace(target, replacement)

with open("deps/SageLang/core/src/c/compiler.c", "w") as f:
    f.write(content)
print("PATCHED")
