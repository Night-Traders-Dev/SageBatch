#define _POSIX_C_SOURCE 200809L
#include <math.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <semaphore.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

// Security: Cap entire-file reads to 100MB to prevent memory exhaustion DoS attacks.
#define SAGE_MAX_READ_SIZE (100 * 1024 * 1024)

typedef struct SageValue SageValue;
typedef struct SageGcHeader SageGcHeader;
typedef struct SageGcFrame SageGcFrame;

typedef struct {
    int count;
    int capacity;
    SageValue* elements;
} SageArray;

typedef struct {
    char** keys;
    SageValue* values;
    int count;
    int capacity;
} SageDict;

typedef struct {
    SageValue* elements;
    int count;
} SageTuple;

typedef enum {
    SAGE_TAG_NIL,
    SAGE_TAG_NUMBER,
    SAGE_TAG_BOOL,
    SAGE_TAG_STRING,
    SAGE_TAG_ARRAY,
    SAGE_TAG_DICT,
    SAGE_TAG_TUPLE,
    SAGE_TAG_FUNCTION,
    SAGE_TAG_CLIB,
    SAGE_TAG_POINTER,
    SAGE_TAG_THREAD,
    SAGE_TAG_MUTEX,
    SAGE_TAG_BYTES
} SageTag;

typedef struct {
    unsigned char* data;
    int count;
} SageBytes;

struct SageValue {
    SageTag type;
    union {
        double number;
        int boolean;
        const char* string;
        SageArray* array;
        SageDict* dict;
        SageTuple* tuple;
        void* function;
        void* clib;
        void* pointer;
        void* thread;
        void* mutex;
        SageBytes* bytes;
    } as;
};

typedef struct {
    int defined;
    SageValue value;
} SageSlot;

typedef enum {
    SAGE_GC_STRING,
    SAGE_GC_ARRAY,
    SAGE_GC_DICT,
    SAGE_GC_TUPLE
} SageGcKind;

struct SageGcHeader {
    unsigned char marked;
    unsigned char kind;
    size_t size;
    SageGcHeader* next;
};

struct SageGcFrame {
    SageGcFrame* prev;
    SageSlot** slots;
    int slot_count;
};

typedef struct {
    SageGcHeader* objects;
    SageGcFrame* frames;
    int object_count;
    int collections;
    int pin_count;
    unsigned long bytes_allocated;
    unsigned long bytes_freed;
    unsigned long next_gc_bytes;
    int next_gc_objects;
    int enabled;
} SageGcState;

#define SAGE_GC_MIN_TRIGGER_BYTES 65536UL
#define SAGE_GC_MIN_TRIGGER_OBJECTS 128
static SageGcState sage_gc = {NULL, NULL, 0, 0, 0, 0, 0, SAGE_GC_MIN_TRIGGER_BYTES, SAGE_GC_MIN_TRIGGER_OBJECTS, 1};

#define SAGE_STRING_LEN(v) ((int)(((SageGcHeader*)(v).as.string - 1)->size - 1))

/* Exception handling via setjmp/longjmp */
#define SAGE_MAX_TRY_DEPTH 1024
static jmp_buf sage_try_stack[SAGE_MAX_TRY_DEPTH];
static SageValue sage_exception_value;
static int sage_try_depth = 0;

static void sage_fail(const char* message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

static unsigned long sage_gc_live_bytes(void) {
    return sage_gc.bytes_allocated - sage_gc.bytes_freed;
}

static void sage_gc_recompute_thresholds(unsigned long reclaimed_bytes, int reclaimed_objects) {
    unsigned long live_bytes = sage_gc_live_bytes();
    int live_objects = sage_gc.object_count;
    unsigned long byte_padding = live_bytes / 2;
    int object_padding = live_objects / 2;
    if (byte_padding < (SAGE_GC_MIN_TRIGGER_BYTES / 2)) byte_padding = SAGE_GC_MIN_TRIGGER_BYTES / 2;
    if (object_padding < (SAGE_GC_MIN_TRIGGER_OBJECTS / 2)) object_padding = SAGE_GC_MIN_TRIGGER_OBJECTS / 2;
    if (reclaimed_bytes <= live_bytes / 8) {
        byte_padding /= 2;
        if (byte_padding < (SAGE_GC_MIN_TRIGGER_BYTES / 2)) byte_padding = SAGE_GC_MIN_TRIGGER_BYTES / 2;
    } else if (reclaimed_bytes >= live_bytes) {
        byte_padding *= 2;
    }
    if (reclaimed_objects <= live_objects / 8) {
        object_padding /= 2;
        if (object_padding < (SAGE_GC_MIN_TRIGGER_OBJECTS / 2)) object_padding = SAGE_GC_MIN_TRIGGER_OBJECTS / 2;
    } else if (reclaimed_objects >= live_objects) {
        object_padding *= 2;
    }
    sage_gc.next_gc_bytes = live_bytes + byte_padding;
    if (sage_gc.next_gc_bytes < SAGE_GC_MIN_TRIGGER_BYTES) sage_gc.next_gc_bytes = SAGE_GC_MIN_TRIGGER_BYTES;
    sage_gc.next_gc_objects = live_objects + object_padding;
    if (sage_gc.next_gc_objects < SAGE_GC_MIN_TRIGGER_OBJECTS) sage_gc.next_gc_objects = SAGE_GC_MIN_TRIGGER_OBJECTS;
}

static int sage_gc_try_mark(void* object) {
    if (object == NULL) return 0;
    SageGcHeader* header = ((SageGcHeader*)object) - 1;
    if (header->marked) return 0;
    header->marked = 1;
    return 1;
}

static void sage_gc_mark_value(SageValue value);
extern void sage_gc_mark_program_globals(void);

static void sage_gc_mark_roots(void) {
    sage_gc_mark_program_globals();
    for (SageGcFrame* frame = sage_gc.frames; frame != NULL; frame = frame->prev) {
        if (frame->slots == NULL) continue;
        for (int i = 0; i < frame->slot_count; i++) {
            if (frame->slots[i] != NULL && frame->slots[i]->defined) {
                sage_gc_mark_value(frame->slots[i]->value);
            }
        }
    }
    if (sage_try_depth > 0) sage_gc_mark_value(sage_exception_value);
}

static size_t sage_gc_release_object(SageGcHeader* header) {
    void* object = (void*)(header + 1);
    size_t freed = sizeof(SageGcHeader) + header->size;
    switch ((SageGcKind)header->kind) {
        case SAGE_GC_STRING:
            break;
        case SAGE_GC_ARRAY: {
            SageArray* array = (SageArray*)object;
            free(array->elements);
            break;
        }
        case SAGE_GC_DICT: {
            SageDict* dict = (SageDict*)object;
            for (int i = 0; i < dict->count; i++) {
                if (dict->keys[i] != NULL) {
                    free(dict->keys[i]);
                }
            }
            free(dict->keys);
            free(dict->values);
            break;
        }
        case SAGE_GC_TUPLE: {
            SageTuple* tuple = (SageTuple*)object;
            free(tuple->elements);
            break;
        }
    }
    return freed;
}

static void sage_gc_collect(void) {
    if (!sage_gc.enabled) return;
    unsigned long before_bytes = sage_gc_live_bytes();
    int before_objects = sage_gc.object_count;
    sage_gc_mark_roots();
    SageGcHeader** current = &sage_gc.objects;
    while (*current != NULL) {
        SageGcHeader* header = *current;
        if (!header->marked) {
            *current = header->next;
            sage_gc.object_count--;
            sage_gc.bytes_freed += sage_gc_release_object(header);
            free(header);
        } else {
            header->marked = 0;
            current = &header->next;
        }
    }
    sage_gc.collections++;
    sage_gc_recompute_thresholds(before_bytes - sage_gc_live_bytes(), before_objects - sage_gc.object_count);
}

static int sage_gc_should_collect(size_t incoming_size) {
    if (!sage_gc.enabled || sage_gc.pin_count > 0) return 0;
    if ((sage_gc.object_count + 1) >= sage_gc.next_gc_objects) return 1;
    return sage_gc_live_bytes() + (unsigned long)sizeof(SageGcHeader) + (unsigned long)incoming_size >= sage_gc.next_gc_bytes;
}

static void* sage_gc_alloc(SageGcKind kind, size_t size) {
    if (sage_gc.frames != NULL && sage_gc_should_collect(size)) sage_gc_collect();
    size_t total = sizeof(SageGcHeader) + size;
    SageGcHeader* header = (SageGcHeader*)malloc(total);
    if (header == NULL) sage_fail("Runtime Error: out of memory");
    header->marked = 0;
    header->kind = (unsigned char)kind;
    header->size = size;
    header->next = sage_gc.objects;
    sage_gc.objects = header;
    sage_gc.object_count++;
    sage_gc.bytes_allocated += (unsigned long)total;
    return (void*)(header + 1);
}

static void sage_gc_push_frame(SageGcFrame* frame, SageSlot** slots, int slot_count) {
    frame->prev = sage_gc.frames;
    frame->slots = slots;
    frame->slot_count = slot_count;
    sage_gc.frames = frame;
}

static void sage_gc_pop_frame(SageGcFrame* frame) {
    if (sage_gc.frames == frame) sage_gc.frames = frame->prev;
}

static void sage_gc_pin(void) { sage_gc.pin_count++; }
static void sage_gc_unpin(void) { if (sage_gc.pin_count > 0) sage_gc.pin_count--; }

static SageValue sage_gc_return(SageGcFrame* frame, SageValue value) {
    sage_gc_pop_frame(frame);
    return value;
}

static void sage_gc_shutdown(void) {
    SageGcHeader* object = sage_gc.objects;
    while (object != NULL) {
        SageGcHeader* next = object->next;
        sage_gc.bytes_freed += sage_gc_release_object(object);
        free(object);
        object = next;
    }
    sage_gc.objects = NULL;
    sage_gc.object_count = 0;
}

static void sage_gc_mark_value(SageValue value) {
    switch (value.type) {
        case SAGE_TAG_STRING:
            (void)sage_gc_try_mark((void*)value.as.string);
            return;
        case SAGE_TAG_ARRAY:
            if (sage_gc_try_mark(value.as.array)) {
                for (int i = 0; i < value.as.array->count; i++) sage_gc_mark_value(value.as.array->elements[i]);
            }
            return;
        case SAGE_TAG_DICT:
            if (sage_gc_try_mark(value.as.dict)) {
                for (int i = 0; i < value.as.dict->count; i++) sage_gc_mark_value(value.as.dict->values[i]);
            }
            return;
        case SAGE_TAG_TUPLE:
            if (sage_gc_try_mark(value.as.tuple)) {
                for (int i = 0; i < value.as.tuple->count; i++) sage_gc_mark_value(value.as.tuple->elements[i]);
            }
            return;
        default:
            return;
    }
}

static char* sage_dup_string(const char* text) {
    size_t len = strlen(text);
    char* copy = (char*)malloc(len + 1);
    if (copy == NULL) sage_fail("Runtime Error: out of memory");
    memcpy(copy, text, len + 1);
    return copy;
}

static char* sage_gc_copy_string(const char* text) {
    size_t len = strlen(text);
    char* copy = (char*)sage_gc_alloc(SAGE_GC_STRING, len + 1);
    memcpy(copy, text, len + 1);
    return copy;
}

static SageArray* sage_new_array(void) {
    SageArray* array = (SageArray*)sage_gc_alloc(SAGE_GC_ARRAY, sizeof(SageArray));
    array->count = 0;
    array->capacity = 0;
    array->elements = NULL;
    return array;
}

static SageValue sage_nil(void) { SageValue v; v.type = SAGE_TAG_NIL; v.as.number = 0; return v; }
static SageValue sage_number(double value) { SageValue v; v.type = SAGE_TAG_NUMBER; v.as.number = value; return v; }
static SageValue sage_bool(int value) { SageValue v; v.type = SAGE_TAG_BOOL; v.as.boolean = value ? 1 : 0; return v; }
static SageValue sage_string(const char* value) { SageValue v; v.type = SAGE_TAG_STRING; v.as.string = sage_gc_copy_string(value == NULL ? "" : value); return v; }
static SageValue sage_string_take(char* value) { SageValue v = sage_string(value == NULL ? "" : value); free(value); return v; }
static SageValue sage_array(void) { SageValue v; v.type = SAGE_TAG_ARRAY; v.as.array = sage_new_array(); return v; }
static SageValue sage_function(void* fn) { SageValue v; v.type = SAGE_TAG_FUNCTION; v.as.function = fn; return v; }

static SageValue sage_ffi_open(SageValue libname) {
    if (libname.type != SAGE_TAG_STRING) return sage_nil();
    void* handle = dlopen(libname.as.string, RTLD_NOW);
    if (!handle) return sage_nil();
    SageValue v; v.type = SAGE_TAG_CLIB; v.as.clib = handle; return v;
}
static SageValue sage_ffi_close(SageValue handle) {
    if (handle.type != SAGE_TAG_CLIB) return sage_nil();
    dlclose(handle.as.clib);
    return sage_nil();
}
static SageValue sage_ffi_call(SageValue handle, SageValue name, SageValue ret_type, SageValue args) {
    if (handle.type != SAGE_TAG_CLIB || name.type != SAGE_TAG_STRING || ret_type.type != SAGE_TAG_STRING)
        return sage_nil();
    void* lib_handle = handle.as.clib;
    if (!lib_handle) return sage_nil();
    void* sym = dlsym(lib_handle, name.as.string);
    if (!sym) return sage_nil();
    const char* rt = ret_type.as.string;
    int call_argc = 0;
    SageValue call_argv[4];
    if (args.type == SAGE_TAG_ARRAY) {
        call_argc = args.as.array->count;
        if (call_argc > 3) call_argc = 3;
        for (int i = 0; i < call_argc; i++) call_argv[i] = args.as.array->elements[i];
    }
    #define IS_NUM(v) ((v).type == SAGE_TAG_NUMBER)
    #define IS_STR(v) ((v).type == SAGE_TAG_STRING)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpedantic"
    if (strcmp(rt, "int") == 0) {
        if (call_argc == 0) { int (*fn)(void) = (int(*)(void))sym; return sage_number((double)fn()); }
        if (call_argc == 1 && IS_NUM(call_argv[0])) { int (*fn)(int) = (int(*)(int))sym; return sage_number((double)fn((int)call_argv[0].as.number)); }
        if (call_argc == 1 && IS_STR(call_argv[0])) { int (*fn)(const char*) = (int(*)(const char*))sym; return sage_number((double)fn(call_argv[0].as.string)); }
        if (call_argc == 2 && IS_NUM(call_argv[0]) && IS_NUM(call_argv[1])) { int (*fn)(int,int) = (int(*)(int,int))sym; return sage_number((double)fn((int)call_argv[0].as.number,(int)call_argv[1].as.number)); }
        if (call_argc == 2 && IS_STR(call_argv[0]) && IS_NUM(call_argv[1])) { int (*fn)(const char*,int) = (int(*)(const char*,int))sym; return sage_number((double)fn(call_argv[0].as.string,(int)call_argv[1].as.number)); }
        if (call_argc == 2 && IS_NUM(call_argv[0]) && IS_STR(call_argv[1])) { int (*fn)(int,const char*) = (int(*)(int,const char*))sym; return sage_number((double)fn((int)call_argv[0].as.number,call_argv[1].as.string)); }
        if (call_argc == 3 && IS_NUM(call_argv[0]) && IS_NUM(call_argv[1]) && IS_NUM(call_argv[2])) { int (*fn)(int,int,int) = (int(*)(int,int,int))sym; return sage_number((double)fn((int)call_argv[0].as.number,(int)call_argv[1].as.number,(int)call_argv[2].as.number)); }
        if (call_argc == 3 && IS_NUM(call_argv[0]) && IS_STR(call_argv[1]) && IS_NUM(call_argv[2])) { int (*fn)(int,const char*,int) = (int(*)(int,const char*,int))sym; return sage_number((double)fn((int)call_argv[0].as.number,call_argv[1].as.string,(int)call_argv[2].as.number)); }
    }
    if (strcmp(rt, "void") == 0) {
        if (call_argc == 0) { void (*fn)(void) = (void(*)(void))sym; fn(); return sage_nil(); }
        if (call_argc == 1 && IS_NUM(call_argv[0])) { void (*fn)(int) = (void(*)(int))sym; fn((int)call_argv[0].as.number); return sage_nil(); }
        if (call_argc == 1 && IS_STR(call_argv[0])) { void (*fn)(const char*) = (void(*)(const char*))sym; fn(call_argv[0].as.string); return sage_nil(); }
        if (call_argc == 2 && IS_NUM(call_argv[0]) && IS_NUM(call_argv[1])) { void (*fn)(int,int) = (void(*)(int,int))sym; fn((int)call_argv[0].as.number,(int)call_argv[1].as.number); return sage_nil(); }
    }
    if (strcmp(rt, "double") == 0) {
        if (call_argc == 0) { double (*fn)(void) = (double(*)(void))sym; return sage_number(fn()); }
        if (call_argc == 1 && IS_NUM(call_argv[0])) { double (*fn)(double) = (double(*)(double))sym; return sage_number(fn(call_argv[0].as.number)); }
        if (call_argc == 2 && IS_NUM(call_argv[0]) && IS_NUM(call_argv[1])) { double (*fn)(double,double) = (double(*)(double,double))sym; return sage_number(fn(call_argv[0].as.number,call_argv[1].as.number)); }
        if (call_argc == 3 && IS_NUM(call_argv[0]) && IS_NUM(call_argv[1]) && IS_NUM(call_argv[2])) { double (*fn)(double,double,double) = (double(*)(double,double,double))sym; return sage_number(fn(call_argv[0].as.number,call_argv[1].as.number,call_argv[2].as.number)); }
    }
    if (strcmp(rt, "long") == 0) {
        if (call_argc == 0) { long (*fn)(void) = (long(*)(void))sym; return sage_number((double)fn()); }
        if (call_argc == 1 && IS_NUM(call_argv[0])) { long (*fn)(long) = (long(*)(long))sym; return sage_number((double)fn((long)call_argv[0].as.number)); }
        if (call_argc == 2 && IS_NUM(call_argv[0]) && IS_NUM(call_argv[1])) { long (*fn)(long,long) = (long(*)(long,long))sym; return sage_number((double)fn((long)call_argv[0].as.number,(long)call_argv[1].as.number)); }
    }
    if (strcmp(rt, "string") == 0) {
        if (call_argc == 0) { const char* (*fn)(void) = (const char*(*)(void))sym; const char* r = fn(); return r ? sage_string(r) : sage_nil(); }
        if (call_argc == 1 && IS_STR(call_argv[0])) { const char* (*fn)(const char*) = (const char*(*)(const char*))sym; const char* r = fn(call_argv[0].as.string); return r ? sage_string(r) : sage_nil(); }
        if (call_argc == 1 && IS_NUM(call_argv[0])) { const char* (*fn)(int) = (const char*(*)(int))sym; const char* r = fn((int)call_argv[0].as.number); return r ? sage_string(r) : sage_nil(); }
    }
    #pragma GCC diagnostic pop
    #undef IS_NUM
    #undef IS_STR
    return sage_nil();
}
static SageValue sage_ffi_call_full(SageValue h, SageValue n, SageValue r, SageValue a) { return sage_ffi_call(h,n,r,a); }

static SageValue sage_atomic_new(SageValue val) {
    SageValue* atom = malloc(sizeof(SageValue));
    *atom = val;
    SageValue v; v.type = SAGE_TAG_POINTER; v.as.pointer = atom; return v;
}
static SageValue sage_atomic_load(SageValue atom) {
    if (atom.type != SAGE_TAG_POINTER) return sage_nil();
    return *(SageValue*)atom.as.pointer;
}
static SageValue sage_atomic_store(SageValue atom, SageValue val) {
    if (atom.type != SAGE_TAG_POINTER) return sage_nil();
    *(SageValue*)atom.as.pointer = val;
    return val;
}
static SageValue sage_atomic_add(SageValue atom, SageValue val) { return sage_nil(); }
static SageValue sage_atomic_cas(SageValue atom, SageValue old, SageValue new_val) { return sage_nil(); }
static SageValue sage_atomic_exchange(SageValue atom, SageValue val) { return sage_nil(); }

static SageValue sage_sem_new(SageValue val) {
    sem_t* sem = malloc(sizeof(sem_t));
    sem_init(sem, 0, (unsigned int)val.as.number);
    SageValue v; v.type = SAGE_TAG_POINTER; v.as.pointer = sem; return v;
}
static SageValue sage_sem_wait(SageValue sem) {
    if (sem.type != SAGE_TAG_POINTER) return sage_nil();
    sem_wait((sem_t*)sem.as.pointer);
    return sage_nil();
}
static SageValue sage_sem_post(SageValue sem) {
    if (sem.type != SAGE_TAG_POINTER) return sage_nil();
    sem_post((sem_t*)sem.as.pointer);
    return sage_nil();
}
static SageValue sage_sem_trywait(SageValue sem) {
    if (sem.type != SAGE_TAG_POINTER) return sage_bool(0);
    return sage_bool(sem_trywait((sem_t*)sem.as.pointer) == 0);
}
static SageSlot sage_slot_undefined(void) { SageSlot slot; slot.defined = 0; slot.value = sage_nil(); return slot; }

static SageValue sage_make_dict(void) {
    SageDict* dict = (SageDict*)sage_gc_alloc(SAGE_GC_DICT, sizeof(SageDict));
    dict->keys = NULL;
    dict->values = NULL;
    dict->count = 0;
    dict->capacity = 0;
    SageValue v; v.type = SAGE_TAG_DICT; v.as.dict = dict;
    return v;
}

static void sage_dict_set(SageDict* dict, const char* key, SageValue value) {
    for (int i = 0; i < dict->count; i++) {
        if (strcmp(dict->keys[i], key) == 0) {
            dict->values[i] = value;
            return;
        }
    }
    if (dict->count >= dict->capacity) {
        int cap = dict->capacity == 0 ? 4 : dict->capacity * 2;
        dict->keys = (char**)realloc(dict->keys, sizeof(char*) * (size_t)cap);
        dict->values = (SageValue*)realloc(dict->values, sizeof(SageValue) * (size_t)cap);
        if (dict->keys == NULL || dict->values == NULL) sage_fail("Runtime Error: out of memory");
        dict->capacity = cap;
    }
    dict->keys[dict->count] = sage_dup_string(key);
    dict->values[dict->count] = value;
    dict->count++;
}

static SageValue sage_make_dict_from_entries(int count, const char** keys, const SageValue* values) {
    sage_gc_pin();
    SageValue dict = sage_make_dict();
    for (int i = 0; i < count; i++) {
        sage_dict_set(dict.as.dict, keys[i], values[i]);
    }
    sage_gc_unpin();
    return dict;
}

static SageValue sage_dict_get(SageDict* dict, const char* key) {
    for (int i = 0; i < dict->count; i++) {
        if (strcmp(dict->keys[i], key) == 0) return dict->values[i];
    }
    return sage_nil();
}

static SageValue sage_make_tuple(int count, const SageValue* values) {
    sage_gc_pin();
    SageTuple* tuple = (SageTuple*)sage_gc_alloc(SAGE_GC_TUPLE, sizeof(SageTuple));
    tuple->count = count;
    tuple->elements = (SageValue*)malloc(sizeof(SageValue) * (size_t)count);
    if (tuple->elements == NULL && count > 0) sage_fail("Runtime Error: out of memory");
    for (int i = 0; i < count; i++) tuple->elements[i] = values[i];
    SageValue v; v.type = SAGE_TAG_TUPLE; v.as.tuple = tuple;
    sage_gc_unpin();
    return v;
}

static void sage_raise(SageValue value) {
    if (sage_try_depth > 0) {
        sage_exception_value = value;
        longjmp(sage_try_stack[sage_try_depth - 1], 1);
    }
    fputs("Unhandled exception: ", stderr);
    if (value.type == SAGE_TAG_STRING) fputs(value.as.string, stderr);
    else fputs("(unknown)", stderr);
    fputc('\n', stderr);
    exit(1);
}

static void sage_array_reserve(SageArray* array, int needed) {
    if (array->capacity >= needed) return;
    int capacity = array->capacity == 0 ? 4 : array->capacity;
    while (capacity < needed) capacity *= 2;
    SageValue* elements = (SageValue*)realloc(array->elements, sizeof(SageValue) * (size_t)capacity);
    if (elements == NULL) sage_fail("Runtime Error: out of memory");
    array->elements = elements;
    array->capacity = capacity;
}

static void sage_array_push_raw(SageArray* array, SageValue value) {
    sage_array_reserve(array, array->count + 1);
    array->elements[array->count++] = value;
}

static SageValue sage_make_array(int count, const SageValue* values) {
    sage_gc_pin();
    SageValue array = sage_array();
    for (int i = 0; i < count; i++) {
        sage_array_push_raw(array.as.array, values[i]);
    }
    sage_gc_unpin();
    return array;
}

static int sage_truthy(SageValue value) {
    if (value.type == SAGE_TAG_NIL) return 0;
    if (value.type == SAGE_TAG_BOOL) return value.as.boolean;
    if (value.type == SAGE_TAG_NUMBER) return value.as.number != 0.0;
    if (value.type == SAGE_TAG_STRING) return value.as.string[0] != '\0';
    return 1;
}

static SageValue sage_load_slot(const SageSlot* slot, const char* name) {
    if (!slot->defined) {
        fprintf(stderr, "Runtime Error: Undefined variable '%s'.\n", name);
        exit(1);
    }
    return slot->value;
}

static void sage_define_slot(SageSlot* slot, SageValue value) {
    slot->defined = 1;
    slot->value = value;
}

static SageValue sage_assign_slot(SageSlot* slot, const char* name, SageValue value) {
    if (!slot->defined) {
        fprintf(stderr, "Runtime Error: Undefined variable '%s'.\n", name);
        exit(1);
    }
    slot->value = value;
    return value;
}

static int sage_values_equal(SageValue left, SageValue right) {
    if (left.type != right.type) return 0;
    switch (left.type) {
        case SAGE_TAG_NIL: return 1;
        case SAGE_TAG_NUMBER: return left.as.number == right.as.number;
        case SAGE_TAG_BOOL: return left.as.boolean == right.as.boolean;
        case SAGE_TAG_STRING: return strcmp(left.as.string, right.as.string) == 0;
        case SAGE_TAG_ARRAY: {
            if (left.as.array == right.as.array) return 1;
            if (left.as.array->count != right.as.array->count) return 0;
            for (int i = 0; i < left.as.array->count; i++) {
                if (!sage_values_equal(left.as.array->elements[i], right.as.array->elements[i])) return 0;
            }
            return 1;
        }
        case SAGE_TAG_DICT: return left.as.dict == right.as.dict;
        case SAGE_TAG_TUPLE: {
            if (left.as.tuple == right.as.tuple) return 1;
            if (left.as.tuple->count != right.as.tuple->count) return 0;
            for (int i = 0; i < left.as.tuple->count; i++) {
                if (!sage_values_equal(left.as.tuple->elements[i], right.as.tuple->elements[i])) return 0;
            }
            return 1;
        }
    }
    return 0;
}

static void sage_print_value(SageValue value) {
    switch (value.type) {
        case SAGE_TAG_NUMBER: {
            double d = value.as.number;
            if (d == (double)(long long)d && d >= -1e15 && d <= 1e15)
                printf("%lld", (long long)d);
            else
                printf("%g", d);
            break;
        }
        case SAGE_TAG_BOOL: fputs(value.as.boolean ? "true" : "false", stdout); break;
        case SAGE_TAG_STRING: fputs(value.as.string, stdout); break;
        case SAGE_TAG_ARRAY:
            fputc('[', stdout);
            for (int i = 0; i < value.as.array->count; i++) {
                if (i > 0) fputs(", ", stdout);
                sage_print_value(value.as.array->elements[i]);
            }
            fputc(']', stdout);
            break;
        case SAGE_TAG_DICT:
            fputc('{', stdout);
            for (int i = 0; i < value.as.dict->count; i++) {
                if (i > 0) fputs(", ", stdout);
                printf("\"%s\": ", value.as.dict->keys[i]);
                sage_print_value(value.as.dict->values[i]);
            }
            fputc('}', stdout);
            break;
        case SAGE_TAG_TUPLE:
            fputc('(', stdout);
            for (int i = 0; i < value.as.tuple->count; i++) {
                if (i > 0) fputs(", ", stdout);
                sage_print_value(value.as.tuple->elements[i]);
            }
            fputc(')', stdout);
            break;
        case SAGE_TAG_NIL: fputs("nil", stdout); break;
    }
}

static void sage_print_ln(SageValue value) {
    sage_print_value(value);
    fputc('\n', stdout);
}

static SageValue sage_str(SageValue value) {
    char buffer[64];
    switch (value.type) {
        case SAGE_TAG_STRING: return value;
        case SAGE_TAG_NUMBER: {
            double d = value.as.number;
            if (d == (double)(long long)d && d >= -1e15 && d <= 1e15)
                snprintf(buffer, sizeof(buffer), "%lld", (long long)d);
            else
                snprintf(buffer, sizeof(buffer), "%g", d);
            return sage_string(buffer);
        }
        case SAGE_TAG_BOOL:
            return sage_string(value.as.boolean ? "true" : "false");
        case SAGE_TAG_NIL:
            return sage_string("nil");
        case SAGE_TAG_ARRAY:
            return sage_string("<array>");
        case SAGE_TAG_DICT:
            return sage_string("<dict>");
        case SAGE_TAG_TUPLE:
            return sage_string("<tuple>");
    }
    return sage_string("nil");
}

static SageValue sage_int(SageValue value) {
    if (value.type == SAGE_TAG_NUMBER) return sage_number((double)(long long)value.as.number);
    if (value.type == SAGE_TAG_STRING) return sage_number((double)atof(value.as.string));
    if (value.type == SAGE_TAG_BOOL) return sage_number((double)value.as.boolean);
    return sage_number(0);
}

static SageValue sage_abs(SageValue value) {
    if (value.type == SAGE_TAG_NUMBER) return sage_number(fabs(value.as.number));
    return sage_nil();
}
static SageValue sage_sqrt(SageValue value) {
    if (value.type == SAGE_TAG_NUMBER) return sage_number(sqrt(value.as.number));
    return sage_nil();
}

static SageValue sage_native_random(void) { return sage_number((double)rand() / (double)RAND_MAX); }
static SageValue sage_native_srandom(SageValue seed) { srand((unsigned int)seed.as.number); return sage_nil(); }
static SageValue sage_native_sin(SageValue v) { return sage_number(sin(v.as.number)); }
static SageValue sage_native_cos(SageValue v) { return sage_number(cos(v.as.number)); }
static SageValue sage_native_tan(SageValue v) { return sage_number(tan(v.as.number)); }
static SageValue sage_native_floor(SageValue v) { return sage_number(floor(v.as.number)); }
static SageValue sage_native_ceil(SageValue v) { return sage_number(ceil(v.as.number)); }
static SageValue sage_native_pow(SageValue a, SageValue b) { return sage_number(pow(a.as.number, b.as.number)); }
static SageValue sage_native_exp(SageValue v) { return sage_number(exp(v.as.number)); }
static SageValue sage_native_log(SageValue v) { return sage_number(log(v.as.number)); }
static SageValue sage_native_sqrt(SageValue v) { return sage_number(sqrt(v.as.number)); }

static SageValue sage_native_thread_mutex(void) {
    pthread_mutex_t* m = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(m, NULL);
    SageValue v; v.type = SAGE_TAG_MUTEX; v.as.mutex = m; return v;
}
static SageValue sage_native_thread_lock(SageValue m) {
    if (m.type == SAGE_TAG_MUTEX) pthread_mutex_lock((pthread_mutex_t*)m.as.mutex);
    return sage_nil();
}
static SageValue sage_native_thread_unlock(SageValue m) {
    if (m.type == SAGE_TAG_MUTEX) pthread_mutex_unlock((pthread_mutex_t*)m.as.mutex);
    return sage_nil();
}
static void* sage_thread_wrapper(void* arg) {
    (void)arg;
    return NULL;
}
static SageValue sage_native_thread_spawn(SageValue fn, SageValue arg) {
    pthread_t* t = malloc(sizeof(pthread_t));
    (void)fn; (void)arg;
    pthread_create(t, NULL, sage_thread_wrapper, NULL);
    SageValue v; v.type = SAGE_TAG_THREAD; v.as.thread = t; return v;
}
static SageValue sage_native_thread_sleep(SageValue ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms.as.number / 1000);
    ts.tv_nsec = (long)((ms.as.number - (double)(ts.tv_sec * 1000)) * 1000000);
    nanosleep(&ts, NULL);
    return sage_nil();
}
static SageValue sage_native_thread_id(void) { return sage_number((double)(uintptr_t)pthread_self()); }

static SageValue sage_native_io_readbytes(SageValue path) {
    if (path.type != SAGE_TAG_STRING) return sage_nil();
    FILE* f = fopen(path.as.string, "rb");
    if (!f) return sage_nil();
    if (fseek(f, 0, SEEK_END) == 0) {
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (size < 0 || size > SAGE_MAX_READ_SIZE) { fclose(f); return sage_nil(); }
        unsigned char* data = (unsigned char*)malloc((size_t)size);
        if (data) fread(data, 1, (size_t)size, f);
        fclose(f);
        if (!data) return sage_nil();
        SageBytes* bytes = (SageBytes*)malloc(sizeof(SageBytes));
        bytes->data = data; bytes->count = (int)size;
        SageValue v; v.type = SAGE_TAG_BYTES; v.as.bytes = bytes; return v;
    }
    // Non-seekable file (e.g., /dev/urandom) — read in chunks until EOF
    sage_gc_pin();
    SageValue arr = sage_array();
    unsigned char chunk[4096];
    size_t nread;
    while ((nread = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        for (size_t i = 0; i < nread; i++) {
            sage_array_push_raw(arr.as.array, sage_number((double)chunk[i]));
        }
    }
    fclose(f);
    sage_gc_unpin();
    return arr;
}
static SageValue sage_native_io_readfile(SageValue path) { return sage_native_io_readbytes(path); }
static SageValue sage_native_io_writefile(SageValue path, SageValue data) {
    if (path.type != SAGE_TAG_STRING || data.type != SAGE_TAG_STRING) return sage_nil();
    FILE* f = fopen(path.as.string, "wb");
    if (!f) return sage_nil();
    fwrite(data.as.string, 1, strlen(data.as.string), f);
    fclose(f);
    return sage_bool(1);
}

extern int sage_argc;
extern char** sage_argv;
static SageValue sage_native_sys_args(void) {
    SageValue arr = sage_array();
    for (int i = 0; i < sage_argc; i++) {
        sage_array_push_raw(arr.as.array, sage_string(sage_argv[i]));
    }
    return arr;
}
static SageValue sage_native_sys_getenv(SageValue name) {
    if (name.type != SAGE_TAG_STRING) return sage_nil();
    char* val = getenv(name.as.string);
    return val ? sage_string(val) : sage_nil();
}
static SageValue sage_native_sys_clock(void) { return sage_number((double)clock() / CLOCKS_PER_SEC); }

static SageValue sage_init_native_module(const char* name) {
    /* For now, just return an empty dict; real native modules should be linked */
    return sage_make_dict();
}

static SageValue sage_len(SageValue value) {
    if (value.type == SAGE_TAG_STRING) return sage_number((double)SAGE_STRING_LEN(value));
    if (value.type == SAGE_TAG_ARRAY) return sage_number((double)value.as.array->count);
    if (value.type == SAGE_TAG_DICT) return sage_number((double)value.as.dict->count);
    if (value.type == SAGE_TAG_TUPLE) return sage_number((double)value.as.tuple->count);
    if (value.type == SAGE_TAG_BYTES) return sage_number((double)value.as.bytes->count);
    return sage_nil();
}

static SageValue sage_index(SageValue collection, SageValue index) {
    if (collection.type == SAGE_TAG_ARRAY && index.type == SAGE_TAG_NUMBER) {
        int idx = (int)index.as.number;
        if (idx < 0 || idx >= collection.as.array->count) return sage_nil();
        return collection.as.array->elements[idx];
    }
    if (collection.type == SAGE_TAG_BYTES && index.type == SAGE_TAG_NUMBER) {
        int idx = (int)index.as.number;
        if (idx < 0 || idx >= collection.as.bytes->count) return sage_nil();
        return sage_number((double)collection.as.bytes->data[idx]);
    }
    if (collection.type == SAGE_TAG_DICT && index.type == SAGE_TAG_STRING) {
        return sage_dict_get(collection.as.dict, index.as.string);
    }
    if (collection.type == SAGE_TAG_TUPLE && index.type == SAGE_TAG_NUMBER) {
        int idx = (int)index.as.number;
        if (idx < 0 || idx >= collection.as.tuple->count) return sage_nil();
        return collection.as.tuple->elements[idx];
    }
    if (collection.type == SAGE_TAG_STRING && index.type == SAGE_TAG_NUMBER) {
        int idx = (int)index.as.number;
        int len = SAGE_STRING_LEN(collection);
        if (idx < 0 || idx >= len) return sage_nil();
        char buf[2] = {collection.as.string[idx], '\0'};
        return sage_string(buf);
    }
    return sage_nil();
}

static SageValue sage_slice(SageValue array, SageValue start, SageValue end) {
    if (array.type != SAGE_TAG_ARRAY && array.type != SAGE_TAG_STRING) return sage_nil();
    sage_gc_pin();
    int len = array.type == SAGE_TAG_ARRAY ? array.as.array->count : SAGE_STRING_LEN(array);
    int start_index = 0;
    int end_index = len;
    if (start.type == SAGE_TAG_NUMBER) start_index = (int)start.as.number;
    else if (start.type != SAGE_TAG_NIL) { sage_gc_unpin(); return sage_nil(); }
    if (end.type == SAGE_TAG_NUMBER) end_index = (int)end.as.number;
    else if (end.type != SAGE_TAG_NIL) { sage_gc_unpin(); return sage_nil(); }
    if (start_index < 0) start_index = len + start_index;
    if (end_index < 0) end_index = len + end_index;
    if (start_index < 0) start_index = 0;
    if (end_index > len) end_index = len;
    if (start_index >= end_index) {
        SageValue empty = array.type == SAGE_TAG_ARRAY ? sage_array() : sage_string("");
        sage_gc_unpin(); return empty;
    }
    if (array.type == SAGE_TAG_ARRAY) {
        SageValue result = sage_array();
        for (int i = start_index; i < end_index; i++) {
            sage_array_push_raw(result.as.array, array.as.array->elements[i]);
        }
        sage_gc_unpin();
        return result;
    } else {
        int new_len = end_index - start_index;
        char* buf = malloc(new_len + 1);
        if (buf == NULL) sage_fail("Runtime Error: out of memory");
        memcpy(buf, array.as.string + start_index, new_len);
        buf[new_len] = '\0';
        SageValue result = sage_string_take(buf);
        sage_gc_unpin();
        return result;
    }
}

static SageValue sage_push(SageValue array, SageValue value) {
    if (array.type != SAGE_TAG_ARRAY) return sage_nil();
    sage_array_push_raw(array.as.array, value);
    return sage_nil();
}

static SageValue sage_pop(SageValue array) {
    if (array.type != SAGE_TAG_ARRAY || array.as.array->count == 0) return sage_nil();
    return array.as.array->elements[--array.as.array->count];
}

static SageValue sage_array_extend(SageValue target, SageValue source) {
    if (target.type != SAGE_TAG_ARRAY || source.type != SAGE_TAG_ARRAY) return sage_nil();
    SageArray* dst = target.as.array;
    SageArray* src = source.as.array;
    if (src->count > 0) {
        sage_array_reserve(dst, dst->count + src->count);
        memcpy(dst->elements + dst->count, src->elements, sizeof(SageValue) * (size_t)src->count);
        dst->count += src->count;
    }
    return sage_nil();
}

static SageValue sage_array_reverse(SageValue array) {
    if (array.type != SAGE_TAG_ARRAY) return sage_nil();
    SageArray* src = array.as.array;
    sage_gc_pin();
    SageValue result = sage_array();
    if (src->count > 0) {
        SageArray* dst = result.as.array;
        sage_array_reserve(dst, src->count);
        dst->count = src->count;
        for (int i = 0; i < src->count; i++) {
            dst->elements[i] = src->elements[src->count - 1 - i];
        }
    }
    sage_gc_unpin();
    return result;
}

static SageValue sage_range2(SageValue start, SageValue end) {
    if (start.type != SAGE_TAG_NUMBER || end.type != SAGE_TAG_NUMBER) return sage_nil();
    sage_gc_pin();
    SageValue result = sage_array();
    for (int i = (int)start.as.number; i < (int)end.as.number; i++) {
        sage_array_push_raw(result.as.array, sage_number((double)i));
    }
    sage_gc_unpin();
    return result;
}
static SageValue sage_range3(SageValue start, SageValue end, SageValue step) {
    if (start.type != SAGE_TAG_NUMBER || end.type != SAGE_TAG_NUMBER || step.type != SAGE_TAG_NUMBER) return sage_nil();
    int s = (int)start.as.number, e = (int)end.as.number, st = (int)step.as.number;
    if (st == 0) return sage_nil();
    sage_gc_pin();
    SageValue result = sage_array();
    if (st > 0) {
        for (int i = s; i < e; i += st) {
            sage_array_push_raw(result.as.array, sage_number((double)i));
        }
    } else {
        for (int i = s; i > e; i += st) {
            sage_array_push_raw(result.as.array, sage_number((double)i));
        }
    }
    sage_gc_unpin();
    return result;
}

static SageValue sage_range1(SageValue end) {
    return sage_range2(sage_number(0), end);
}

static SageValue sage_add(SageValue left, SageValue right);
static SageValue sage_sub(SageValue left, SageValue right);
static SageValue sage_mul(SageValue left, SageValue right);
static SageValue sage_div(SageValue left, SageValue right);
static SageValue sage_eq(SageValue left, SageValue right);
static SageValue sage_neq(SageValue left, SageValue right);
static SageValue sage_gt(SageValue left, SageValue right);
static SageValue sage_lt(SageValue left, SageValue right);
static SageValue sage_gte(SageValue left, SageValue right);
static SageValue sage_lte(SageValue left, SageValue right);

static inline SageValue SAGE_ADD(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_number(a.as.number + b.as.number);
    return sage_add(a, b);
}
static inline SageValue SAGE_SUB(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_number(a.as.number - b.as.number);
    return sage_sub(a, b);
}
static inline SageValue SAGE_MUL(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_number(a.as.number * b.as.number);
    return sage_mul(a, b);
}
static inline SageValue SAGE_DIV(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER && b.as.number != 0.0) return sage_number(a.as.number / b.as.number);
    return sage_div(a, b);
}
static inline SageValue SAGE_EQ(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_bool(a.as.number == b.as.number);
    return sage_eq(a, b);
}
static inline SageValue SAGE_NEQ(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_bool(a.as.number != b.as.number);
    return sage_neq(a, b);
}
static inline SageValue SAGE_GT(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_bool(a.as.number > b.as.number);
    return sage_gt(a, b);
}
static inline SageValue SAGE_LT(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_bool(a.as.number < b.as.number);
    return sage_lt(a, b);
}
static inline SageValue SAGE_GTE(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_bool(a.as.number >= b.as.number);
    return sage_gte(a, b);
}
static inline SageValue SAGE_LTE(SageValue a, SageValue b) {
    if (a.type == SAGE_TAG_NUMBER && b.type == SAGE_TAG_NUMBER) return sage_bool(a.as.number <= b.as.number);
    return sage_lte(a, b);
}

static SageValue sage_add(SageValue left, SageValue right) {
    if (left.type == SAGE_TAG_NUMBER && right.type == SAGE_TAG_NUMBER) {
        return sage_number(left.as.number + right.as.number);
    }
    if (left.type == SAGE_TAG_STRING && right.type == SAGE_TAG_STRING) {
        size_t len1 = SAGE_STRING_LEN(left);
        size_t len2 = SAGE_STRING_LEN(right);
        char* result = (char*)malloc(len1 + len2 + 1);
        if (result == NULL) sage_fail("Runtime Error: out of memory");
        memcpy(result, left.as.string, len1);
        memcpy(result + len1, right.as.string, len2 + 1);
        return sage_string_take(result);
    }
    if (left.type == SAGE_TAG_ARRAY && right.type == SAGE_TAG_ARRAY) {
        int total = left.as.array->count + right.as.array->count;
        SageValue result = sage_array();
        result.as.array->count = total;
        result.as.array->capacity = total;
        result.as.array->elements = (SageValue*)malloc(sizeof(SageValue) * total);
        if (result.as.array->elements == NULL) sage_fail("Runtime Error: out of memory");
        memcpy(result.as.array->elements, left.as.array->elements, sizeof(SageValue) * left.as.array->count);
        memcpy(result.as.array->elements + left.as.array->count, right.as.array->elements, sizeof(SageValue) * right.as.array->count);
        return result;
    }
    sage_fail("Runtime Error: Operands must be numbers, strings, or arrays.");
    return sage_nil();
}

static SageValue sage_sub(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number(left.as.number - right.as.number);
}
static SageValue sage_mul(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number(left.as.number * right.as.number);
}
static SageValue sage_div(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    if (right.as.number == 0) return sage_nil();
    return sage_number(left.as.number / right.as.number);
}
static SageValue sage_mod(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    if (right.as.number == 0) return sage_nil();
    return sage_number(fmod(left.as.number, right.as.number));
}
static SageValue sage_eq(SageValue left, SageValue right) { return sage_bool(sage_values_equal(left, right)); }
static SageValue sage_neq(SageValue left, SageValue right) { return sage_bool(!sage_values_equal(left, right)); }
static SageValue sage_gt(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_bool(left.as.number > right.as.number);
}
static SageValue sage_lt(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_bool(left.as.number < right.as.number);
}
static SageValue sage_gte(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_bool(left.as.number >= right.as.number);
}
static SageValue sage_lte(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_bool(left.as.number <= right.as.number);
}
static SageValue sage_not(SageValue value) { return sage_bool(!sage_truthy(value)); }
static SageValue sage_and(SageValue left, SageValue right) { return sage_bool(sage_truthy(left) && sage_truthy(right)); }
static SageValue sage_or(SageValue left, SageValue right) { return sage_bool(sage_truthy(left) || sage_truthy(right)); }
static SageValue sage_bit_not(SageValue value) {
    if (value.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Bitwise NOT operand must be a number.");
    return sage_number((double)(~(long long)value.as.number));
}
static SageValue sage_bit_and(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number((double)(((long long)left.as.number) & ((long long)right.as.number)));
}
static SageValue sage_bit_or(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number((double)(((long long)left.as.number) | ((long long)right.as.number)));
}
static SageValue sage_bit_xor(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number((double)(((long long)left.as.number) ^ ((long long)right.as.number)));
}
static SageValue sage_lshift(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number((double)(((unsigned long long)left.as.number) << ((long long)right.as.number)));
}
static SageValue sage_rshift(SageValue left, SageValue right) {
    if (left.type != SAGE_TAG_NUMBER || right.type != SAGE_TAG_NUMBER) sage_fail("Runtime Error: Operands must be numbers.");
    return sage_number((double)(((unsigned long long)left.as.number) >> ((long long)right.as.number)));
}

static SageValue sage_tonumber(SageValue value) {
    if (value.type == SAGE_TAG_NUMBER) return value;
    if (value.type == SAGE_TAG_STRING) {
        char* end;
        double result = strtod(value.as.string, &end);
        if (end != value.as.string && *end == '\0') return sage_number(result);
    }
    return sage_nil();
}

static SageValue sage_dict_keys_fn(SageValue dict_val) {
    if (dict_val.type != SAGE_TAG_DICT) return sage_array();
    sage_gc_pin();
    SageValue result = sage_array();
    for (int i = 0; i < dict_val.as.dict->count; i++) {
        sage_array_push_raw(result.as.array, sage_string(dict_val.as.dict->keys[i]));
    }
    sage_gc_unpin();
    return result;
}

static SageValue sage_dict_values_fn(SageValue dict_val) {
    if (dict_val.type != SAGE_TAG_DICT) return sage_array();
    sage_gc_pin();
    SageValue result = sage_array();
    for (int i = 0; i < dict_val.as.dict->count; i++) {
        sage_array_push_raw(result.as.array, dict_val.as.dict->values[i]);
    }
    sage_gc_unpin();
    return result;
}

static SageValue sage_dict_has_fn(SageValue dict_val, SageValue key) {
    if (dict_val.type != SAGE_TAG_DICT || key.type != SAGE_TAG_STRING) return sage_bool(0);
    for (int i = 0; i < dict_val.as.dict->count; i++) {
        if (strcmp(dict_val.as.dict->keys[i], key.as.string) == 0) return sage_bool(1);
    }
    return sage_bool(0);
}

static SageValue sage_dict_delete_fn(SageValue dict_val, SageValue key) {
    if (dict_val.type != SAGE_TAG_DICT || key.type != SAGE_TAG_STRING) return sage_nil();
    SageDict* dict = dict_val.as.dict;
    for (int i = 0; i < dict->count; i++) {
        if (strcmp(dict->keys[i], key.as.string) == 0) {
            free(dict->keys[i]);
            for (int j = i; j < dict->count - 1; j++) {
                dict->keys[j] = dict->keys[j + 1];
                dict->values[j] = dict->values[j + 1];
            }
            dict->count--;
            return sage_bool(1);
        }
    }
    return sage_bool(0);
}

static SageValue sage_chr(SageValue v) {
    if (v.type != SAGE_TAG_NUMBER) return sage_nil();
    char buf[2] = { (char)(int)v.as.number, 0 };
    return sage_string(buf);
}

static SageValue sage_ord(SageValue v) {
    if (v.type != SAGE_TAG_STRING || v.as.string == NULL || v.as.string[0] == 0) return sage_nil();
    return sage_number((double)(unsigned char)v.as.string[0]);
}

static SageValue sage_type(SageValue v) {
    switch (v.type) {
        case SAGE_TAG_NIL: return sage_string("nil");
        case SAGE_TAG_NUMBER: return sage_string("number");
        case SAGE_TAG_BOOL: return sage_string("bool");
        case SAGE_TAG_STRING: return sage_string("string");
        case SAGE_TAG_ARRAY: return sage_string("array");
        case SAGE_TAG_DICT: return sage_string("dict");
        default: return sage_string("unknown");
    }
}

static SageValue sage_startswith(SageValue s, SageValue prefix) {
    if (s.type != SAGE_TAG_STRING || prefix.type != SAGE_TAG_STRING) return sage_bool(0);
    return sage_bool(strncmp(s.as.string, prefix.as.string, SAGE_STRING_LEN(prefix)) == 0);
}

static SageValue sage_endswith(SageValue s, SageValue suffix) {
    if (s.type != SAGE_TAG_STRING || suffix.type != SAGE_TAG_STRING) return sage_bool(0);
    size_t slen = SAGE_STRING_LEN(s), suflen = SAGE_STRING_LEN(suffix);
    if (suflen > slen) return sage_bool(0);
    return sage_bool(strcmp(s.as.string + slen - suflen, suffix.as.string) == 0);
}

static SageValue sage_contains(SageValue haystack, SageValue needle) {
    if (haystack.type != SAGE_TAG_STRING || needle.type != SAGE_TAG_STRING) return sage_bool(0);
    return sage_bool(strstr(haystack.as.string, needle.as.string) != NULL);
}

static SageValue sage_indexof(SageValue haystack, SageValue needle) {
    if (haystack.type != SAGE_TAG_STRING || needle.type != SAGE_TAG_STRING) return sage_nil();
    char* found = strstr(haystack.as.string, needle.as.string);
    if (found == NULL) return sage_number(-1);
    return sage_number((double)(found - haystack.as.string));
}

static SageValue sage_string_count(SageValue haystack, SageValue needle) {
    if (haystack.type != SAGE_TAG_STRING || needle.type != SAGE_TAG_STRING) return sage_nil();
    if (SAGE_STRING_LEN(needle) == 0) return sage_number(0);
    size_t count = 0;
    const char* pos = haystack.as.string;
    while ((pos = strstr(pos, needle.as.string)) != NULL) {
        count++;
        pos += SAGE_STRING_LEN(needle);
    }
    return sage_number((double)count);
}

static SageValue sage_string_repeat(SageValue s, SageValue count) {
    if (s.type != SAGE_TAG_STRING || count.type != SAGE_TAG_NUMBER) return sage_nil();
    int n = (int)count.as.number;
    if (n <= 0) return sage_string("");
    size_t slen = SAGE_STRING_LEN(s);
    char* buf = malloc(slen * n + 1);
    if (!buf) return sage_nil();
    for (int i = 0; i < n; i++) memcpy(buf + i * slen, s.as.string, slen);
    buf[slen * n] = '\0';
    SageValue result = sage_string_take(buf);
    return result;
}

static void sage_index_set(SageValue c, SageValue k, SageValue v) {
    if (c.type == SAGE_TAG_ARRAY && k.type == SAGE_TAG_NUMBER) {
        int i = (int)k.as.number;
        if (i >= 0 && i < c.as.array->count) c.as.array->elements[i] = v;
        return;
    }
    if (c.type == SAGE_TAG_DICT && k.type == SAGE_TAG_STRING) {
        SageDict* d = c.as.dict;
        for (int i = 0; i < d->count; i++) {
            if (strcmp(d->keys[i], k.as.string) == 0) { d->values[i] = v; return; }
        }
        if (d->count >= d->capacity) {
            int nc = d->capacity == 0 ? 4 : d->capacity * 2;
            d->keys = realloc(d->keys, sizeof(char*) * nc);
            d->values = realloc(d->values, sizeof(SageValue) * nc);
            d->capacity = nc;
        }
        { size_t l = SAGE_STRING_LEN(k); d->keys[d->count] = malloc(l+1); memcpy(d->keys[d->count], k.as.string, l+1); }
        d->values[d->count] = v;
        d->count++;
    }
}

static SageValue sage_gc_collect_fn(void) {
    sage_gc_collect();
    return sage_nil();
}

static SageValue sage_gc_enable_fn(void) {
    sage_gc.enabled = 1;
    return sage_nil();
}

static SageValue sage_gc_disable_fn(void) {
    sage_gc.enabled = 0;
    return sage_nil();
}

static SageValue sage_gc_stats_fn(void) {
    int next_gc = sage_gc.next_gc_objects - sage_gc.object_count;
    if (next_gc < 0) next_gc = 0;
    return sage_make_dict_from_entries(7,
        (const char*[]){"bytes_allocated", "current_bytes", "num_objects", "collections", "objects_freed", "next_gc", "next_gc_bytes"},
        (SageValue[]){
            sage_number((double)sage_gc.bytes_allocated),
            sage_number((double)sage_gc_live_bytes()),
            sage_number((double)sage_gc.object_count),
            sage_number((double)sage_gc.collections),
            sage_number(0),
            sage_number((double)next_gc),
            sage_number((double)sage_gc.next_gc_bytes)
        });
}

static SageValue sage_gc_collections_fn(void) {
    return sage_number((double)sage_gc.collections);
}

#include <ctype.h>
static SageValue sage_upper(SageValue value) {
    if (value.type != SAGE_TAG_STRING) return sage_nil();
    size_t len = strlen(value.as.string);
    char* result = (char*)malloc(len + 1);
    if (result == NULL) sage_fail("Runtime Error: out of memory");
    for (size_t i = 0; i < len; i++) result[i] = (char)toupper((unsigned char)value.as.string[i]);
    result[len] = '\0';
    return sage_string_take(result);
}
static SageValue sage_lower(SageValue value) {
    if (value.type != SAGE_TAG_STRING) return sage_nil();
    size_t len = strlen(value.as.string);
    char* result = (char*)malloc(len + 1);
    if (result == NULL) sage_fail("Runtime Error: out of memory");
    for (size_t i = 0; i < len; i++) result[i] = (char)tolower((unsigned char)value.as.string[i]);
    result[len] = '\0';
    return sage_string_take(result);
}
static SageValue sage_strip_fn(SageValue value) {
    if (value.type != SAGE_TAG_STRING) return sage_nil();
    const char* s = value.as.string;
    while (*s && isspace((unsigned char)*s)) s++;
    const char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) end--;
    size_t len = (size_t)(end - s);
    char* result = (char*)malloc(len + 1);
    if (result == NULL) sage_fail("Runtime Error: out of memory");
    memcpy(result, s, len);
    result[len] = '\0';
    return sage_string_take(result);
}

static SageValue sage_split_fn(SageValue str_val, SageValue delim_val) {
    if (str_val.type != SAGE_TAG_STRING || delim_val.type != SAGE_TAG_STRING) return sage_array();
    sage_gc_pin();
    const char* s = str_val.as.string;
    const char* delim = delim_val.as.string;
    size_t dlen = strlen(delim);
    SageValue result = sage_array();
    if (dlen == 0) {
        for (size_t i = 0; s[i]; i++) {
            char buf[2] = {s[i], '\0'};
            sage_array_push_raw(result.as.array, sage_string(buf));
        }
        sage_gc_unpin();
        return result;
    }
    const char* start = s;
    const char* found;
    while ((found = strstr(start, delim)) != NULL) {
        size_t len = (size_t)(found - start);
        char* part = (char*)malloc(len + 1);
        if (part == NULL) sage_fail("Runtime Error: out of memory");
        memcpy(part, start, len);
        part[len] = '\0';
        sage_array_push_raw(result.as.array, sage_string_take(part));
        start = found + dlen;
    }
    sage_array_push_raw(result.as.array, sage_string(start));
    sage_gc_unpin();
    return result;
}

static SageValue sage_join_fn(SageValue arr_val, SageValue delim_val) {
    if (arr_val.type != SAGE_TAG_ARRAY || delim_val.type != SAGE_TAG_STRING) return sage_nil();
    SageArray* arr = arr_val.as.array;
    const char* delim = delim_val.as.string;
    size_t dlen = strlen(delim);
    if (arr->count == 0) return sage_string("");
    size_t total = 0;
    for (int i = 0; i < arr->count; i++) {
        if (arr->elements[i].type == SAGE_TAG_STRING) total += strlen(arr->elements[i].as.string);
        if (i > 0) total += dlen;
    }
    char* result = (char*)malloc(total + 1);
    if (result == NULL) sage_fail("Runtime Error: out of memory");
    char* p = result;
    for (int i = 0; i < arr->count; i++) {
        if (i > 0) { memcpy(p, delim, dlen); p += dlen; }
        if (arr->elements[i].type == SAGE_TAG_STRING) {
            size_t len = strlen(arr->elements[i].as.string);
            memcpy(p, arr->elements[i].as.string, len);
            p += len;
        }
    }
    *p = '\0';
    return sage_string_take(result);
}

static SageValue sage_replace_fn(SageValue str_val, SageValue old_val, SageValue new_val) {
    if (str_val.type != SAGE_TAG_STRING || old_val.type != SAGE_TAG_STRING || new_val.type != SAGE_TAG_STRING)
        return sage_nil();
    const char* s = str_val.as.string;
    const char* old_s = old_val.as.string;
    const char* new_s = new_val.as.string;
    size_t old_len = strlen(old_s);
    size_t new_len = strlen(new_s);
    if (old_len == 0) return sage_string(s);
    size_t count = 0;
    const char* tmp = s;
    while ((tmp = strstr(tmp, old_s)) != NULL) { count++; tmp += old_len; }
    size_t result_len = strlen(s) + count * (new_len - old_len);
    char* result = (char*)malloc(result_len + 1);
    if (result == NULL) sage_fail("Runtime Error: out of memory");
    char* p = result;
    while (*s) {
        if (strncmp(s, old_s, old_len) == 0) {
            memcpy(p, new_s, new_len);
            p += new_len;
            s += old_len;
        } else {
            *p++ = *s++;
        }
    }
    *p = '\0';
    return sage_string_take(result);
}

#include <stdint.h>

typedef struct {
    void* ptr;
    size_t size;
    int owned;
} SagePointer;

static SageValue sage_mem_alloc(SageValue size_val) {
    if (size_val.type != SAGE_TAG_NUMBER) { fputs("mem_alloc(): expects number\n", stderr); return sage_nil(); }
    size_t size = (size_t)size_val.as.number;
    if (size == 0 || size > 1024*1024*64) { fputs("mem_alloc(): invalid size\n", stderr); return sage_nil(); }
    SagePointer* sp = (SagePointer*)malloc(sizeof(SagePointer));
    if (sp == NULL) sage_fail("Runtime Error: out of memory");
    sp->ptr = calloc(1, size);
    if (sp->ptr == NULL) { free(sp); sage_fail("Runtime Error: out of memory"); }
    sp->size = size;
    sp->owned = 1;
    SageValue v; v.type = SAGE_TAG_NUMBER; v.as.number = (double)(uintptr_t)sp;
    return v;
}

static SagePointer* sage_as_pointer(SageValue v) {
    if (v.type != SAGE_TAG_NUMBER) return NULL;
    return (SagePointer*)(uintptr_t)v.as.number;
}

static SageValue sage_mem_free(SageValue ptr_val) {
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL) { fputs("mem_free(): expects pointer\n", stderr); return sage_nil(); }
    if (sp->ptr && sp->owned) { free(sp->ptr); sp->ptr = NULL; sp->size = 0; }
    free(sp);
    return sage_nil();
}

static SageValue sage_mem_read(SageValue ptr_val, SageValue off_val, SageValue type_val) {
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL || sp->ptr == NULL || off_val.type != SAGE_TAG_NUMBER || type_val.type != SAGE_TAG_STRING)
        return sage_nil();
    size_t offset = (size_t)off_val.as.number;
    const char* type = type_val.as.string;
    unsigned char* base = (unsigned char*)sp->ptr + offset;
    if (strcmp(type, "byte") == 0) { return sage_number((double)*base); }
    if (strcmp(type, "int") == 0) { int v; memcpy(&v, base, sizeof(int)); return sage_number((double)v); }
    if (strcmp(type, "double") == 0) { double v; memcpy(&v, base, sizeof(double)); return sage_number(v); }
    if (strcmp(type, "string") == 0) { return sage_string((const char*)base); }
    return sage_nil();
}

static SageValue sage_mem_write(SageValue ptr_val, SageValue off_val, SageValue type_val, SageValue val) {
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL || sp->ptr == NULL || off_val.type != SAGE_TAG_NUMBER || type_val.type != SAGE_TAG_STRING)
        return sage_nil();
    size_t offset = (size_t)off_val.as.number;
    const char* type = type_val.as.string;
    unsigned char* base = (unsigned char*)sp->ptr + offset;
    if (strcmp(type, "byte") == 0 && val.type == SAGE_TAG_NUMBER) { *base = (unsigned char)val.as.number; }
    else if (strcmp(type, "int") == 0 && val.type == SAGE_TAG_NUMBER) { int v = (int)val.as.number; memcpy(base, &v, sizeof(int)); }
    else if (strcmp(type, "double") == 0 && val.type == SAGE_TAG_NUMBER) { double v = val.as.number; memcpy(base, &v, sizeof(double)); }
    return sage_nil();
}

static SageValue sage_mem_size(SageValue ptr_val) {
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL) return sage_nil();
    return sage_number((double)sp->size);
}

static SageValue sage_ptr_to_int(SageValue ptr_val) {
    if (ptr_val.type != SAGE_TAG_POINTER) return sage_nil();
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL) return sage_nil();
    return sage_number((double)(uintptr_t)sp->ptr);
}
static SageValue sage_ffi_sym(SageValue handle, SageValue name) {
    if (handle.type != SAGE_TAG_CLIB || name.type != SAGE_TAG_STRING)
        return sage_bool(0);
    void* lib = handle.as.clib;
    if (!lib) return sage_bool(0);
    void* sym = dlsym(lib, name.as.string);
    return sage_bool(sym != NULL);
}
static SageValue sage_ffi_sym_addr(SageValue handle, SageValue name) {
    if (handle.type != SAGE_TAG_CLIB || name.type != SAGE_TAG_STRING)
        return sage_nil();
    void* lib = handle.as.clib;
    if (!lib) return sage_nil();
    void* sym = dlsym(lib, name.as.string);
    if (!sym) return sage_nil();
    return sage_number((double)(uintptr_t)sym);
}
static SageValue sage_addressof(SageValue val) {
    return sage_number((double)(uintptr_t)&val);
}
static SageValue sage_ptr_add(SageValue ptr_val, SageValue offset) {
    if (ptr_val.type != SAGE_TAG_POINTER || offset.type != SAGE_TAG_NUMBER)
        return sage_nil();
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL) return sage_nil();
    SageValue v; v.type = SAGE_TAG_POINTER;
    v.as.pointer = sp;
    sp->ptr = (void*)((uintptr_t)sp->ptr + (intptr_t)offset.as.number);
    return v;
}
static SageValue sage_sizeof(SageValue type_name) {
    if (type_name.type != SAGE_TAG_STRING) return sage_nil();
    const char* tn = type_name.as.string;
    if (strcmp(tn,"char")==0||strcmp(tn,"byte")==0) return sage_number(1);
    if (strcmp(tn,"short")==0) return sage_number(2);
    if (strcmp(tn,"int")==0) return sage_number(4);
    if (strcmp(tn,"long")==0) return sage_number(8);
    if (strcmp(tn,"float")==0) return sage_number(4);
    if (strcmp(tn,"double")==0) return sage_number(8);
    if (strcmp(tn,"ptr")==0) return sage_number(8);
    return sage_nil();
}

static int sage_struct_type_info(const char* type, size_t* out_size, size_t* out_align) {
    if (strcmp(type,"char")==0||strcmp(type,"byte")==0) { *out_size=1; *out_align=1; return 0; }
    if (strcmp(type,"short")==0) { *out_size=sizeof(short); *out_align=sizeof(short); return 0; }
    if (strcmp(type,"int")==0) { *out_size=sizeof(int); *out_align=sizeof(int); return 0; }
    if (strcmp(type,"long")==0) { *out_size=sizeof(long); *out_align=sizeof(long); return 0; }
    if (strcmp(type,"float")==0) { *out_size=sizeof(float); *out_align=sizeof(float); return 0; }
    if (strcmp(type,"double")==0) { *out_size=sizeof(double); *out_align=sizeof(double); return 0; }
    if (strcmp(type,"ptr")==0) { *out_size=sizeof(void*); *out_align=sizeof(void*); return 0; }
    return -1;
}

static SageValue sage_struct_def(SageValue fields) {
    if (fields.type != SAGE_TAG_ARRAY) return sage_nil();
    sage_gc_pin();
    SageValue def = sage_make_dict();
    size_t offset = 0, max_align = 1;
    for (int i = 0; i < fields.as.array->count; i++) {
        SageValue pair = fields.as.array->elements[i];
        if (pair.type != SAGE_TAG_ARRAY || pair.as.array->count < 2) continue;
        if (pair.as.array->elements[0].type != SAGE_TAG_STRING ||
            pair.as.array->elements[1].type != SAGE_TAG_STRING) continue;
        const char* name = pair.as.array->elements[0].as.string;
        const char* type = pair.as.array->elements[1].as.string;
        size_t fsize, falign;
        if (sage_struct_type_info(type, &fsize, &falign) != 0) continue;
        if (falign > max_align) max_align = falign;
        size_t rem = offset % falign;
        if (rem != 0) offset += falign - rem;
        /* store field: "name" -> [offset, type] */
        SageValue field_info = sage_make_array(2, (SageValue[]){
            sage_number((double)offset), sage_string(type)
        });
        sage_dict_set(def.as.dict, name, field_info);
        offset += fsize;
    }
    size_t rem = offset % max_align;
    if (rem != 0) offset += max_align - rem;
    sage_dict_set(def.as.dict, "__size__", sage_number((double)offset));
    sage_dict_set(def.as.dict, "__align__", sage_number((double)max_align));
    sage_gc_unpin();
    return def;
}

static SageValue sage_struct_new(SageValue def) {
    if (def.type != SAGE_TAG_DICT) return sage_nil();
    SageValue size_val = sage_dict_get(def.as.dict, "__size__");
    if (size_val.type != SAGE_TAG_NUMBER) return sage_nil();
    size_t size = (size_t)size_val.as.number;
    SagePointer* sp = (SagePointer*)malloc(sizeof(SagePointer));
    if (sp == NULL) sage_fail("Runtime Error: out of memory");
    sp->ptr = calloc(1, size);
    if (sp->ptr == NULL) { free(sp); sage_fail("Runtime Error: out of memory"); }
    sp->size = size;
    sp->owned = 1;
    SageValue v; v.type = SAGE_TAG_NUMBER; v.as.number = (double)(uintptr_t)sp;
    return v;
}

static SageValue sage_struct_get(SageValue ptr_val, SageValue def, SageValue field_name) {
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL || sp->ptr == NULL || def.type != SAGE_TAG_DICT || field_name.type != SAGE_TAG_STRING)
        return sage_nil();
    SageValue info = sage_dict_get(def.as.dict, field_name.as.string);
    if (info.type != SAGE_TAG_ARRAY || info.as.array->count < 2) return sage_nil();
    size_t offset = (size_t)info.as.array->elements[0].as.number;
    const char* type = info.as.array->elements[1].as.string;
    unsigned char* base = (unsigned char*)sp->ptr + offset;
    if (strcmp(type,"char")==0||strcmp(type,"byte")==0) return sage_number((double)*base);
    if (strcmp(type,"short")==0) { short v; memcpy(&v,base,sizeof(short)); return sage_number((double)v); }
    if (strcmp(type,"int")==0) { int v; memcpy(&v,base,sizeof(int)); return sage_number((double)v); }
    if (strcmp(type,"long")==0) { long v; memcpy(&v,base,sizeof(long)); return sage_number((double)v); }
    if (strcmp(type,"float")==0) { float v; memcpy(&v,base,sizeof(float)); return sage_number((double)v); }
    if (strcmp(type,"double")==0) { double v; memcpy(&v,base,sizeof(double)); return sage_number(v); }
    return sage_nil();
}

static SageValue sage_struct_set(SageValue ptr_val, SageValue def, SageValue field_name, SageValue val) {
    SagePointer* sp = sage_as_pointer(ptr_val);
    if (sp == NULL || sp->ptr == NULL || def.type != SAGE_TAG_DICT || field_name.type != SAGE_TAG_STRING)
        return sage_nil();
    SageValue info = sage_dict_get(def.as.dict, field_name.as.string);
    if (info.type != SAGE_TAG_ARRAY || info.as.array->count < 2) return sage_nil();
    size_t offset = (size_t)info.as.array->elements[0].as.number;
    const char* type = info.as.array->elements[1].as.string;
    unsigned char* base = (unsigned char*)sp->ptr + offset;
    if (val.type != SAGE_TAG_NUMBER) return sage_nil();
    if (strcmp(type,"char")==0||strcmp(type,"byte")==0) { *base = (unsigned char)val.as.number; }
    else if (strcmp(type,"short")==0) { short v=(short)val.as.number; memcpy(base,&v,sizeof(short)); }
    else if (strcmp(type,"int")==0) { int v=(int)val.as.number; memcpy(base,&v,sizeof(int)); }
    else if (strcmp(type,"long")==0) { long v=(long)val.as.number; memcpy(base,&v,sizeof(long)); }
    else if (strcmp(type,"float")==0) { float v=(float)val.as.number; memcpy(base,&v,sizeof(float)); }
    else if (strcmp(type,"double")==0) { double v=val.as.number; memcpy(base,&v,sizeof(double)); }
    return sage_nil();
}

static SageValue sage_struct_size(SageValue def) {
    if (def.type != SAGE_TAG_DICT) return sage_nil();
    return sage_dict_get(def.as.dict, "__size__");
}

typedef SageValue (*SageMethodFn)(SageValue, int, SageValue*);
typedef struct { const char* class_name; const char* method_name; SageMethodFn fn; } SageMethodEntry;
typedef struct { const char* name; const char* parent; } SageClassEntry;
#define SAGE_MAX_METHODS 256
#define SAGE_MAX_CLASSES 64
static SageMethodEntry sage_method_table[SAGE_MAX_METHODS];
static int sage_method_count = 0;
static SageClassEntry sage_class_registry[SAGE_MAX_CLASSES];
static int sage_class_count = 0;

static void sage_register_class(const char* name, const char* parent) {
    if (sage_class_count >= SAGE_MAX_CLASSES) sage_fail("too many classes");
    sage_class_registry[sage_class_count].name = name;
    sage_class_registry[sage_class_count].parent = parent;
    sage_class_count++;
}

static void sage_register_method(const char* cls, const char* name, SageMethodFn fn) {
    if (sage_method_count >= SAGE_MAX_METHODS) sage_fail("too many methods");
    sage_method_table[sage_method_count].class_name = cls;
    sage_method_table[sage_method_count].method_name = name;
    sage_method_table[sage_method_count].fn = fn;
    sage_method_count++;
}

static SageValue sage_call_method(SageValue obj, const char* method, int argc, SageValue* argv) {
    if (obj.type != SAGE_TAG_DICT) {
        fprintf(stderr, "Runtime Error: method call on non-instance (type=%d).\n", obj.type);
        exit(1);
    }
    SageValue class_val = sage_dict_get(obj.as.dict, "__class__");
    if (class_val.type != SAGE_TAG_STRING) {
        fprintf(stderr, "Runtime Error: no __class__ on instance (method=%s class_val_type=%d).\n", method, class_val.type);
        exit(1);
    }
    const char* current = class_val.as.string;
    while (current != NULL) {
        for (int i = 0; i < sage_method_count; i++) {
            if (strcmp(sage_method_table[i].class_name, current) == 0 &&
                strcmp(sage_method_table[i].method_name, method) == 0) {
                return sage_method_table[i].fn(obj, argc, argv);
            }
        }
        const char* parent = NULL;
        for (int j = 0; j < sage_class_count; j++) {
            if (strcmp(sage_class_registry[j].name, current) == 0) {
                parent = sage_class_registry[j].parent;
                break;
            }
        }
        current = parent;
    }
    fprintf(stderr, "Runtime Error: Undefined method '%s'.\n", method);
    exit(1);
    return sage_nil();
}

static SageValue sage_construct(const char* class_name, const char* parent_name, int argc, SageValue* argv) {
    sage_gc_pin();
    SageValue inst = sage_make_dict();
    sage_dict_set(inst.as.dict, "__class__", sage_string(class_name));
    if (parent_name != NULL) sage_dict_set(inst.as.dict, "__parent__", sage_string(parent_name));
    sage_gc_unpin();
    const char* current = class_name;
    while (current != NULL) {
        for (int i = 0; i < sage_method_count; i++) {
            if (strcmp(sage_method_table[i].class_name, current) == 0 &&
                strcmp(sage_method_table[i].method_name, "init") == 0) {
                sage_method_table[i].fn(inst, argc, argv);
                return inst;
            }
        }
        const char* parent = NULL;
        for (int j = 0; j < sage_class_count; j++) {
            if (strcmp(sage_class_registry[j].name, current) == 0) {
                parent = sage_class_registry[j].parent;
                break;
            }
        }
        current = parent;
    }
    return inst;
}

static SageValue sage_arch_fn(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return sage_string("x86_64");
#elif defined(__aarch64__) || defined(_M_ARM64)
    return sage_string("aarch64");
#elif defined(__riscv) && __riscv_xlen == 64
    return sage_string("rv64");
#else
    return sage_string("unknown");
#endif
}

#include <time.h>
static SageValue sage_clock_fn(void) {
    return sage_number((double)clock() / CLOCKS_PER_SEC);
}
static SageValue sage_input_fn(SageValue prompt) {
    if (prompt.type == SAGE_TAG_STRING) fputs(prompt.as.string, stdout);
    char buf[4096];
    if (fgets(buf, sizeof(buf), stdin) == NULL) return sage_nil();
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[--len] = '\0';
    return sage_string(buf);
}
static SageValue sage_sys_args(void) {
    extern int sage_argc; extern char** sage_argv;
    SageValue list = sage_array();
    for(int i=0; i<sage_argc; i++) sage_push(list, sage_string(sage_argv[i]));
    return list;
}
static int sage_is_safe_command(const char* cmd) {
    if (!cmd) return 1;
    if (cmd[0] == '-') return 0;
    for (const char* p = cmd; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '/' && *p != '.' &&
            *p != '-' && *p != '_' && *p != '~' && *p != ' ') {
            return 0;
        }
    }
    return 1;
}
static SageValue sage_sys_exec(SageValue cmd) {
    if(cmd.type != SAGE_TAG_STRING) return sage_number(-1);
    if(!sage_is_safe_command(cmd.as.string)) {
        fprintf(stderr, "Security Error: Unsafe characters in command\n");
        return sage_number(-1);
    }
    return sage_number(system(cmd.as.string));
}
static SageValue sage_io_readfile(SageValue p) {
    if(p.type != SAGE_TAG_STRING) return sage_nil();
    FILE* f = fopen(p.as.string, "rb"); if(!f) return sage_nil();
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    if (size < 0 || size > SAGE_MAX_READ_SIZE) { fclose(f); return sage_nil(); }
    char* buf = malloc(size + 1); if(!buf) { fclose(f); return sage_nil(); }
    fread(buf, 1, size, f); buf[size] = 0; fclose(f);
    return sage_string_take(buf);
}
static SageValue sage_io_writefile(SageValue p, SageValue c) {
    if(p.type != SAGE_TAG_STRING || c.type != SAGE_TAG_STRING) return sage_bool(0);
    FILE* f = fopen(p.as.string, "wb"); if(!f) return sage_bool(0);
    fwrite(c.as.string, 1, strlen(c.as.string), f); fclose(f); return sage_bool(1);
}
static SageValue sage_io_writebytes(SageValue p, SageValue arr) {
    if(p.type != SAGE_TAG_STRING || arr.type != SAGE_TAG_ARRAY) return sage_bool(0);
    FILE* f = fopen(p.as.string, "wb"); if(!f) return sage_bool(0);
    SageArray* a = arr.as.array;
    unsigned char* buf = malloc(a->count);
    for(int i=0; i<a->count; i++) buf[i] = (unsigned char)a->elements[i].as.number;
    fwrite(buf, 1, a->count, f); fclose(f); free(buf); return sage_bool(1);
}
static SageValue sage_io_readbytes(SageValue p) {
    if(p.type != SAGE_TAG_STRING) return sage_nil();
    FILE* f = fopen(p.as.string, "rb"); if(!f) return sage_nil();
    SageValue arr = sage_array();
    if (fseek(f, 0, SEEK_END) == 0) {
        long size = ftell(f); fseek(f, 0, SEEK_SET);
        if (size < 0 || size > SAGE_MAX_READ_SIZE) { fclose(f); return sage_nil(); }
        if (size > 0) {
            unsigned char* buf = malloc(size);
            fread(buf, 1, size, f);
            for(int i=0; i<size; i++) sage_push(arr, sage_number((double)buf[i]));
            free(buf);
        }
        fclose(f);
        return arr;
    }
    // Non-seekable file (e.g., /dev/urandom) — read in chunks until EOF
    unsigned char chunk[4096];
    size_t nread;
    size_t total_read = 0;
    while ((nread = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (total_read + nread > SAGE_MAX_READ_SIZE) {
            nread = SAGE_MAX_READ_SIZE - total_read;
        }
        for (size_t i = 0; i < nread; i++) sage_push(arr, sage_number((double)chunk[i]));
        total_read += nread;
        if (total_read >= SAGE_MAX_READ_SIZE) break;
    }
    fclose(f);
    return arr;
}
static SageValue sage_io_exists(SageValue p) {
    if(p.type != SAGE_TAG_STRING) return sage_bool(0);
    FILE* f = fopen(p.as.string, "r"); if(f){ fclose(f); return sage_bool(1); } return sage_bool(0);
}
static SageValue sage_string_substr(SageValue s, SageValue start, SageValue len) {
    if(s.type != SAGE_TAG_STRING || start.type != SAGE_TAG_NUMBER || len.type != SAGE_TAG_NUMBER) return sage_nil();
    int st = (int)start.as.number; int l = (int)len.as.number;
    int slen = strlen(s.as.string);
    if(st < 0 || st > slen) return sage_string("");
    if(l < 0) l = 0; if(st + l > slen) l = slen - st;
    char* buf = malloc(l + 1); if(!buf) return sage_nil();
    memcpy(buf, s.as.string + st, l); buf[l] = 0;
    return sage_string_take(buf);
}

static SageValue sage_fn_run_script_31(SageValue arg0, SageValue arg1);
static SageValue sage_fn_run_interactive_30(SageValue arg0);
static SageValue sage_fn_print_banner_29();
static SageValue sage_method_Interpreter_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Interpreter_build_label_table(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Interpreter_eval_condition(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Interpreter_expand_args(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Interpreter_exec_node(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Interpreter_run_program(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Interpreter_run_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_peek(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_peek_kind(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_advance(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_expect(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_skip_newlines(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_at_end(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_collect_args(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_block(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_statement(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_label(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_rem(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_goto(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_call(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_if(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_condition(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_for(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_set(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_command(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse_block_contents(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Parser_parse(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_get_char(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_peek(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_advance(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_match_char(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_skip_whitespace_inline(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_emit(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_scan_string(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_scan_variable(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_scan_word(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_scan_redirect(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_scan_comment(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Lexer_tokenize(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandRegistry_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandRegistry_is_internal(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandRegistry_dispatch(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_echo(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_rem(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_set(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_pause(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_cls(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_exit(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_cd(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_md(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_rd(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_dir(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_type(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_copy(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_move(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_del(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_ren(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_shift(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_ver(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_InternalCommands_cmd_help(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_BlockNode_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_PipeNode_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_RedirectNode_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CallNode_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_GotoNode_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_LabelNode_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_ForStatement_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_IfStatement_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Assignment_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Command_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Program_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_BatchProcess_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_BatchProcess_make_context(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_BatchProcess_push_call(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_BatchProcess_pop_call(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandContext_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandContext_expand_token(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandContext_shift_args(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandContext_get_arg(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_CommandContext_write_out(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_normalize(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_resolve(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_exists(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_is_dir(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_is_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_read_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_write_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_append_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_delete_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_make_dir(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_remove_dir(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_list_dir(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_glob(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_copy_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_move_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_FileSystem_rename_file(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_push_scope(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_pop_scope(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_set_local(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_get(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_set(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_VarStore_expand(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment__init_defaults(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_set_var(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_get_var(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_del_var(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_expand(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_set_errorlevel(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_get_errorlevel(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_chdir(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Environment_render_prompt(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Token_init(SageValue _self, int _argc, SageValue* _argv);
static SageValue sage_method_Token___str__(SageValue _self, int _argc, SageValue* _argv);

static SageSlot sage_global_rest_36;
static SageSlot sage_global_script_35;
static SageSlot sage_global_proc_inst_34;
static SageSlot sage_global_arg_offset_33;
static SageSlot sage_global_args_32;
static SageSlot sage_global_parser_28;
static SageSlot sage_global_string_27;
static SageSlot sage_global_lexer_26;
static SageSlot sage_global_commands_25;
static SageSlot sage_global_registry_24;
static SageSlot sage_global_ast_23;
static SageSlot sage_global_interpreter_22;
static SageSlot sage_global_context_21;
static SageSlot sage_global_filesystem_20;
static SageSlot sage_global_varstore_19;
static SageSlot sage_global_io_18;
static SageSlot sage_global_sys_17;
static SageSlot sage_global_environment_16;
static SageSlot sage_global_process_15;
static SageSlot sage_global_TOK_AT_14;
static SageSlot sage_global_TOK_PAREN_R_13;
static SageSlot sage_global_TOK_PAREN_L_12;
static SageSlot sage_global_TOK_AMP_11;
static SageSlot sage_global_TOK_EOF_10;
static SageSlot sage_global_TOK_NEWLINE_9;
static SageSlot sage_global_TOK_PIPE_8;
static SageSlot sage_global_TOK_REDIRECT_7;
static SageSlot sage_global_TOK_OPERATOR_6;
static SageSlot sage_global_TOK_LABEL_5;
static SageSlot sage_global_TOK_VARIABLE_4;
static SageSlot sage_global_TOK_STRING_3;
static SageSlot sage_global_TOK_WORD_2;
static SageSlot sage_global_token_1;

void sage_gc_mark_program_globals(void) {
    if (sage_global_rest_36.defined) sage_gc_mark_value(sage_global_rest_36.value);
    if (sage_global_script_35.defined) sage_gc_mark_value(sage_global_script_35.value);
    if (sage_global_proc_inst_34.defined) sage_gc_mark_value(sage_global_proc_inst_34.value);
    if (sage_global_arg_offset_33.defined) sage_gc_mark_value(sage_global_arg_offset_33.value);
    if (sage_global_args_32.defined) sage_gc_mark_value(sage_global_args_32.value);
    if (sage_global_parser_28.defined) sage_gc_mark_value(sage_global_parser_28.value);
    if (sage_global_string_27.defined) sage_gc_mark_value(sage_global_string_27.value);
    if (sage_global_lexer_26.defined) sage_gc_mark_value(sage_global_lexer_26.value);
    if (sage_global_commands_25.defined) sage_gc_mark_value(sage_global_commands_25.value);
    if (sage_global_registry_24.defined) sage_gc_mark_value(sage_global_registry_24.value);
    if (sage_global_ast_23.defined) sage_gc_mark_value(sage_global_ast_23.value);
    if (sage_global_interpreter_22.defined) sage_gc_mark_value(sage_global_interpreter_22.value);
    if (sage_global_context_21.defined) sage_gc_mark_value(sage_global_context_21.value);
    if (sage_global_filesystem_20.defined) sage_gc_mark_value(sage_global_filesystem_20.value);
    if (sage_global_varstore_19.defined) sage_gc_mark_value(sage_global_varstore_19.value);
    if (sage_global_io_18.defined) sage_gc_mark_value(sage_global_io_18.value);
    if (sage_global_sys_17.defined) sage_gc_mark_value(sage_global_sys_17.value);
    if (sage_global_environment_16.defined) sage_gc_mark_value(sage_global_environment_16.value);
    if (sage_global_process_15.defined) sage_gc_mark_value(sage_global_process_15.value);
    if (sage_global_TOK_AT_14.defined) sage_gc_mark_value(sage_global_TOK_AT_14.value);
    if (sage_global_TOK_PAREN_R_13.defined) sage_gc_mark_value(sage_global_TOK_PAREN_R_13.value);
    if (sage_global_TOK_PAREN_L_12.defined) sage_gc_mark_value(sage_global_TOK_PAREN_L_12.value);
    if (sage_global_TOK_AMP_11.defined) sage_gc_mark_value(sage_global_TOK_AMP_11.value);
    if (sage_global_TOK_EOF_10.defined) sage_gc_mark_value(sage_global_TOK_EOF_10.value);
    if (sage_global_TOK_NEWLINE_9.defined) sage_gc_mark_value(sage_global_TOK_NEWLINE_9.value);
    if (sage_global_TOK_PIPE_8.defined) sage_gc_mark_value(sage_global_TOK_PIPE_8.value);
    if (sage_global_TOK_REDIRECT_7.defined) sage_gc_mark_value(sage_global_TOK_REDIRECT_7.value);
    if (sage_global_TOK_OPERATOR_6.defined) sage_gc_mark_value(sage_global_TOK_OPERATOR_6.value);
    if (sage_global_TOK_LABEL_5.defined) sage_gc_mark_value(sage_global_TOK_LABEL_5.value);
    if (sage_global_TOK_VARIABLE_4.defined) sage_gc_mark_value(sage_global_TOK_VARIABLE_4.value);
    if (sage_global_TOK_STRING_3.defined) sage_gc_mark_value(sage_global_TOK_STRING_3.value);
    if (sage_global_TOK_WORD_2.defined) sage_gc_mark_value(sage_global_TOK_WORD_2.value);
    if (sage_global_token_1.defined) sage_gc_mark_value(sage_global_token_1.value);
}


static SageValue sage_method_Interpreter_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_process_38 = sage_slot_undefined();
    SageSlot sage_local_self_37 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_process_38, &sage_local_self_37};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_37, _self);
    sage_define_slot(&sage_local_process_38, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_37, "self"); SageValue _val = sage_load_slot(&sage_local_process_38, "process"); sage_dict_set(_obj.as.dict, "process", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_37, "self"); SageValue _val = sage_call_method(sage_load_slot(&sage_local_process_38, "process"), "make_context", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_process_38, "process"), sage_string("batch_args"))}); sage_dict_set(_obj.as.dict, "ctx", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_37, "self"); SageValue _val = sage_construct("CommandRegistry", NULL, 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_37, "self"), sage_string("ctx"))}); sage_dict_set(_obj.as.dict, "registry", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_37, "self"); SageValue _val = sage_make_dict(); sage_dict_set(_obj.as.dict, "labels", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_37, "self"); SageValue _val = sage_make_array(0, NULL); sage_dict_set(_obj.as.dict, "stmts", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Interpreter_build_label_table(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_43 = sage_slot_undefined();
    SageSlot sage_local_stmt_42 = sage_slot_undefined();
    SageSlot sage_local_i_41 = sage_slot_undefined();
    SageSlot sage_local_program_40 = sage_slot_undefined();
    SageSlot sage_local_self_39 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_e_43, &sage_local_stmt_42, &sage_local_i_41, &sage_local_program_40, &sage_local_self_39};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_39, _self);
    sage_define_slot(&sage_local_program_40, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_39, "self"); SageValue _val = sage_index(sage_load_slot(&sage_local_program_40, "program"), sage_string("statements")); sage_dict_set(_obj.as.dict, "stmts", _val); _val;});
    sage_define_slot(&sage_local_i_41, sage_number(0));
    {
        SageValue sage_iter_stmt_44 = sage_index(sage_load_slot(&sage_local_self_39, "self"), sage_string("stmts"));
        if (sage_iter_stmt_44.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_stmt_45 = 0; sage_idx_stmt_45 < sage_iter_stmt_44.as.array->count; sage_idx_stmt_45++) {
                sage_define_slot(&sage_local_stmt_42, sage_iter_stmt_44.as.array->elements[sage_idx_stmt_45]);
                    if (sage_truthy(sage_and(SAGE_EQ(sage_type(sage_load_slot(&sage_local_stmt_42, "stmt")), sage_string("Instance")), SAGE_NEQ(sage_index(sage_load_slot(&sage_local_stmt_42, "stmt"), sage_string("name")), sage_nil())))) {
                        {
                            if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
                            int _caught = 0;
                            sage_try_depth++;
                            if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
                                (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_39, "self"), sage_string("labels")), sage_upper(sage_index(sage_load_slot(&sage_local_stmt_42, "stmt"), sage_string("name"))), sage_load_slot(&sage_local_i_41, "i"));
                            } else {
                                _caught = 1;
                                sage_define_slot(&sage_local_e_43, sage_exception_value);
                            }
                            sage_try_depth--;
                            if (_caught) {
                                (void)sage_nil();
                            }
                        }
                    }
                    (void)sage_assign_slot(&sage_local_i_41, "i", SAGE_ADD(sage_load_slot(&sage_local_i_41, "i"), sage_number(1)));
            }
        } else if (sage_iter_stmt_44.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_stmt_44.as.string);
            for (int sage_idx_stmt_45 = 0; sage_idx_stmt_45 < _len; sage_idx_stmt_45++) {
                char _ch[2] = {sage_iter_stmt_44.as.string[sage_idx_stmt_45], '\0'};
                sage_define_slot(&sage_local_stmt_42, sage_string(_ch));
                    if (sage_truthy(sage_and(SAGE_EQ(sage_type(sage_load_slot(&sage_local_stmt_42, "stmt")), sage_string("Instance")), SAGE_NEQ(sage_index(sage_load_slot(&sage_local_stmt_42, "stmt"), sage_string("name")), sage_nil())))) {
                        {
                            if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
                            int _caught = 0;
                            sage_try_depth++;
                            if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
                                (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_39, "self"), sage_string("labels")), sage_upper(sage_index(sage_load_slot(&sage_local_stmt_42, "stmt"), sage_string("name"))), sage_load_slot(&sage_local_i_41, "i"));
                            } else {
                                _caught = 1;
                                sage_define_slot(&sage_local_e_43, sage_exception_value);
                            }
                            sage_try_depth--;
                            if (_caught) {
                                (void)sage_nil();
                            }
                        }
                    }
                    (void)sage_assign_slot(&sage_local_i_41, "i", SAGE_ADD(sage_load_slot(&sage_local_i_41, "i"), sage_number(1)));
            }
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Interpreter_eval_condition(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_op_53 = sage_slot_undefined();
    SageSlot sage_local_right_52 = sage_slot_undefined();
    SageSlot sage_local_left_51 = sage_slot_undefined();
    SageSlot sage_local_n_50 = sage_slot_undefined();
    SageSlot sage_local_path_49 = sage_slot_undefined();
    SageSlot sage_local_ctype_48 = sage_slot_undefined();
    SageSlot sage_local_cond_47 = sage_slot_undefined();
    SageSlot sage_local_self_46 = sage_slot_undefined();
    SageSlot* sage_gc_roots[8] = {&sage_local_op_53, &sage_local_right_52, &sage_local_left_51, &sage_local_n_50, &sage_local_path_49, &sage_local_ctype_48, &sage_local_cond_47, &sage_local_self_46};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 8);
    sage_define_slot(&sage_local_self_46, _self);
    sage_define_slot(&sage_local_cond_47, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_ctype_48, sage_index(sage_load_slot(&sage_local_cond_47, "cond"), sage_string("type")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ctype_48, "ctype"), sage_string("EXIST")))) {
        sage_define_slot(&sage_local_path_49, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_46, "self"), sage_string("ctx")), sage_string("vars")), "expand", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_cond_47, "cond"), sage_string("value"))}));
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_46, "self"), sage_string("ctx")), sage_string("fs")), "exists", 1, (SageValue[]){sage_load_slot(&sage_local_path_49, "path")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ctype_48, "ctype"), sage_string("ERRORLEVEL")))) {
        sage_define_slot(&sage_local_n_50, sage_tonumber(sage_index(sage_load_slot(&sage_local_cond_47, "cond"), sage_string("value"))));
        return sage_gc_return(&sage_gc_frame, SAGE_GTE(sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_46, "self"), sage_string("ctx")), sage_string("env")), "get_errorlevel", 0, NULL), sage_load_slot(&sage_local_n_50, "n")));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ctype_48, "ctype"), sage_string("COMPARE")))) {
        sage_define_slot(&sage_local_left_51, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_46, "self"), sage_string("ctx")), sage_string("vars")), "expand", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_cond_47, "cond"), sage_string("left"))}));
        sage_define_slot(&sage_local_right_52, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_46, "self"), sage_string("ctx")), sage_string("vars")), "expand", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_cond_47, "cond"), sage_string("right"))}));
        sage_define_slot(&sage_local_op_53, sage_upper(sage_index(sage_load_slot(&sage_local_cond_47, "cond"), sage_string("op"))));
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("==")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_EQ(sage_load_slot(&sage_local_left_51, "left"), sage_load_slot(&sage_local_right_52, "right")));
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("EQU")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_EQ(sage_load_slot(&sage_local_left_51, "left"), sage_load_slot(&sage_local_right_52, "right")));
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("NEQ")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_NEQ(sage_load_slot(&sage_local_left_51, "left"), sage_load_slot(&sage_local_right_52, "right")));
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("LSS")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_LT(sage_tonumber(sage_load_slot(&sage_local_left_51, "left")), sage_tonumber(sage_load_slot(&sage_local_right_52, "right"))));
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("LEQ")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_LTE(sage_tonumber(sage_load_slot(&sage_local_left_51, "left")), sage_tonumber(sage_load_slot(&sage_local_right_52, "right"))));
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("GTR")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_GT(sage_tonumber(sage_load_slot(&sage_local_left_51, "left")), sage_tonumber(sage_load_slot(&sage_local_right_52, "right"))));
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_op_53, "op"), sage_string("GEQ")))) {
            return sage_gc_return(&sage_gc_frame, SAGE_GTE(sage_tonumber(sage_load_slot(&sage_local_left_51, "left")), sage_tonumber(sage_load_slot(&sage_local_right_52, "right"))));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_bool(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Interpreter_expand_args(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_arg_57 = sage_slot_undefined();
    SageSlot sage_local_out_56 = sage_slot_undefined();
    SageSlot sage_local_args_55 = sage_slot_undefined();
    SageSlot sage_local_self_54 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_arg_57, &sage_local_out_56, &sage_local_args_55, &sage_local_self_54};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_54, _self);
    sage_define_slot(&sage_local_args_55, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_out_56, sage_make_array(0, NULL));
    {
        SageValue sage_iter_arg_58 = sage_load_slot(&sage_local_args_55, "args");
        if (sage_iter_arg_58.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_arg_59 = 0; sage_idx_arg_59 < sage_iter_arg_58.as.array->count; sage_idx_arg_59++) {
                sage_define_slot(&sage_local_arg_57, sage_iter_arg_58.as.array->elements[sage_idx_arg_59]);
                    (void)sage_push(sage_load_slot(&sage_local_out_56, "out"), sage_call_method(sage_index(sage_load_slot(&sage_local_self_54, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_arg_57, "arg")}));
            }
        } else if (sage_iter_arg_58.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_arg_58.as.string);
            for (int sage_idx_arg_59 = 0; sage_idx_arg_59 < _len; sage_idx_arg_59++) {
                char _ch[2] = {sage_iter_arg_58.as.string[sage_idx_arg_59], '\0'};
                sage_define_slot(&sage_local_arg_57, sage_string(_ch));
                    (void)sage_push(sage_load_slot(&sage_local_out_56, "out"), sage_call_method(sage_index(sage_load_slot(&sage_local_self_54, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_arg_57, "arg")}));
            }
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_out_56, "out"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Interpreter_exec_node(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_code_70 = sage_slot_undefined();
    SageSlot sage_local_old_stdout_69 = sage_slot_undefined();
    SageSlot sage_local_filename_68 = sage_slot_undefined();
    SageSlot sage_local_s_67 = sage_slot_undefined();
    SageSlot sage_local_args_66 = sage_slot_undefined();
    SageSlot sage_local_val_65 = sage_slot_undefined();
    SageSlot sage_local_tok_64 = sage_slot_undefined();
    SageSlot sage_local_result_63 = sage_slot_undefined();
    SageSlot sage_local_ntype_62 = sage_slot_undefined();
    SageSlot sage_local_node_61 = sage_slot_undefined();
    SageSlot sage_local_self_60 = sage_slot_undefined();
    SageSlot* sage_gc_roots[11] = {&sage_local_code_70, &sage_local_old_stdout_69, &sage_local_filename_68, &sage_local_s_67, &sage_local_args_66, &sage_local_val_65, &sage_local_tok_64, &sage_local_result_63, &sage_local_ntype_62, &sage_local_node_61, &sage_local_self_60};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 11);
    sage_define_slot(&sage_local_self_60, _self);
    sage_define_slot(&sage_local_node_61, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_node_61, "node"), sage_nil()))) {
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    sage_define_slot(&sage_local_ntype_62, sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("type")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("LabelNode")))) {
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("Assignment")))) {
        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "set", 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("name")), sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "expand", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("value"))})});
        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("env")), "set_errorlevel", 1, (SageValue[]){sage_number(0)});
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("GotoNode")))) {
        sage_raise(sage_make_dict_from_entries(2, (const char*[]){"__signal", "target"}, (SageValue[]){sage_string("GOTO"), sage_upper(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("target")))}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("IfStatement")))) {
        sage_define_slot(&sage_local_result_63, sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "eval_condition", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("condition"))}));
        if (sage_truthy(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("negated")))) {
            (void)sage_assign_slot(&sage_local_result_63, "result", sage_not(sage_load_slot(&sage_local_result_63, "result")));
        }
        if (sage_truthy(sage_load_slot(&sage_local_result_63, "result"))) {
            return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("consequent"))}));
        }
        else {
            if (sage_truthy(SAGE_NEQ(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("alternate")), sage_nil()))) {
                return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("alternate"))}));
            }
        }
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("ForStatement")))) {
        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "push_scope", 0, NULL);
        {
            SageValue sage_iter_tok_71 = sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("in_list"));
            if (sage_iter_tok_71.type == SAGE_TAG_ARRAY) {
                for (int sage_idx_tok_72 = 0; sage_idx_tok_72 < sage_iter_tok_71.as.array->count; sage_idx_tok_72++) {
                    sage_define_slot(&sage_local_tok_64, sage_iter_tok_71.as.array->elements[sage_idx_tok_72]);
                        sage_define_slot(&sage_local_val_65, sage_call_method(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_tok_64, "tok")}));
                        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "set_local", 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("var_name")), sage_load_slot(&sage_local_val_65, "val")});
                        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("body"))});
                }
            } else if (sage_iter_tok_71.type == SAGE_TAG_STRING) {
                int _len = (int)strlen(sage_iter_tok_71.as.string);
                for (int sage_idx_tok_72 = 0; sage_idx_tok_72 < _len; sage_idx_tok_72++) {
                    char _ch[2] = {sage_iter_tok_71.as.string[sage_idx_tok_72], '\0'};
                    sage_define_slot(&sage_local_tok_64, sage_string(_ch));
                        sage_define_slot(&sage_local_val_65, sage_call_method(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_tok_64, "tok")}));
                        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "set_local", 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("var_name")), sage_load_slot(&sage_local_val_65, "val")});
                        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("body"))});
                }
            }
        }
        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "pop_scope", 0, NULL);
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("CallNode")))) {
        sage_define_slot(&sage_local_args_66, sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "expand_args", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("args"))}));
        if (sage_truthy(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("is_subroutine")))) {
            sage_raise(sage_make_dict_from_entries(2, (const char*[]){"__signal", "target"}, (SageValue[]){sage_string("GOTO"), sage_upper(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("target")))}));
        }
        else {
            (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "run_file", 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("target")), sage_load_slot(&sage_local_args_66, "args")});
        }
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("BlockNode")))) {
        {
            SageValue sage_iter_s_73 = sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("statements"));
            if (sage_iter_s_73.type == SAGE_TAG_ARRAY) {
                for (int sage_idx_s_74 = 0; sage_idx_s_74 < sage_iter_s_73.as.array->count; sage_idx_s_74++) {
                    sage_define_slot(&sage_local_s_67, sage_iter_s_73.as.array->elements[sage_idx_s_74]);
                        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_load_slot(&sage_local_s_67, "s")});
                }
            } else if (sage_iter_s_73.type == SAGE_TAG_STRING) {
                int _len = (int)strlen(sage_iter_s_73.as.string);
                for (int sage_idx_s_74 = 0; sage_idx_s_74 < _len; sage_idx_s_74++) {
                    char _ch[2] = {sage_iter_s_73.as.string[sage_idx_s_74], '\0'};
                    sage_define_slot(&sage_local_s_67, sage_string(_ch));
                        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_load_slot(&sage_local_s_67, "s")});
                }
            }
        }
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("RedirectNode")))) {
        sage_define_slot(&sage_local_filename_68, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("vars")), "expand", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("filename"))}));
        sage_define_slot(&sage_local_old_stdout_69, sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("stdout")));
        if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("op")), sage_string(">")))) {
            (void)sage_native_io_writefile(sage_load_slot(&sage_local_filename_68, "filename"), sage_string(""));
            (void)({SageValue _obj = sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")); SageValue _val = sage_load_slot(&sage_local_filename_68, "filename"); sage_dict_set(_obj.as.dict, "stdout", _val); _val;});
        }
        else {
            if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("op")), sage_string(">>")))) {
                (void)({SageValue _obj = sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")); SageValue _val = sage_load_slot(&sage_local_filename_68, "filename"); sage_dict_set(_obj.as.dict, "stdout", _val); _val;});
            }
        }
        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("inner"))});
        (void)({SageValue _obj = sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")); SageValue _val = sage_load_slot(&sage_local_old_stdout_69, "old_stdout"); sage_dict_set(_obj.as.dict, "stdout", _val); _val;});
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("PipeNode")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("left"))});
        (void)sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "exec_node", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("right"))});
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ntype_62, "ntype"), sage_string("Command")))) {
        sage_print_ln(SAGE_ADD(sage_string("Command "), sage_str(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("name")))));
        sage_define_slot(&sage_local_args_66, sage_call_method(sage_load_slot(&sage_local_self_60, "self"), "expand_args", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("args"))}));
        if (sage_truthy(sage_and(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("echo_on")), sage_not(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("suppress")))))) {
            sage_print_ln(SAGE_ADD(SAGE_ADD(SAGE_ADD(sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("env")), "render_prompt", 0, NULL), sage_str(sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("name")))), sage_string(" ")), sage_join_fn(sage_load_slot(&sage_local_args_66, "args"), sage_string(" "))));
        }
        sage_define_slot(&sage_local_code_70, sage_call_method(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("registry")), "dispatch", 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("name")), sage_index(sage_load_slot(&sage_local_node_61, "node"), sage_string("args"))}));
        (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_60, "self"), sage_string("ctx")), sage_string("env")), "set_errorlevel", 1, (SageValue[]){sage_load_slot(&sage_local_code_70, "code")});
        return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_code_70, "code"));
    }
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Interpreter_run_program(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_target_80 = sage_slot_undefined();
    SageSlot sage_local_e_79 = sage_slot_undefined();
    SageSlot sage_local_stmt_78 = sage_slot_undefined();
    SageSlot sage_local_ip_77 = sage_slot_undefined();
    SageSlot sage_local_program_76 = sage_slot_undefined();
    SageSlot sage_local_self_75 = sage_slot_undefined();
    SageSlot* sage_gc_roots[6] = {&sage_local_target_80, &sage_local_e_79, &sage_local_stmt_78, &sage_local_ip_77, &sage_local_program_76, &sage_local_self_75};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 6);
    sage_define_slot(&sage_local_self_75, _self);
    sage_define_slot(&sage_local_program_76, _argv[0]);
    (void)_argc;
    (void)sage_call_method(sage_load_slot(&sage_local_self_75, "self"), "build_label_table", 1, (SageValue[]){sage_load_slot(&sage_local_program_76, "program")});
    sage_define_slot(&sage_local_ip_77, sage_number(0));
    while (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_ip_77, "ip"), sage_len(sage_index(sage_load_slot(&sage_local_self_75, "self"), sage_string("stmts")))))) {
        sage_define_slot(&sage_local_stmt_78, sage_index(sage_index(sage_load_slot(&sage_local_self_75, "self"), sage_string("stmts")), sage_load_slot(&sage_local_ip_77, "ip")));
        {
            if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
            int _caught = 0;
            sage_try_depth++;
            if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
                (void)sage_call_method(sage_load_slot(&sage_local_self_75, "self"), "exec_node", 1, (SageValue[]){sage_load_slot(&sage_local_stmt_78, "stmt")});
                (void)sage_assign_slot(&sage_local_ip_77, "ip", SAGE_ADD(sage_load_slot(&sage_local_ip_77, "ip"), sage_number(1)));
            } else {
                _caught = 1;
                sage_define_slot(&sage_local_e_79, sage_exception_value);
            }
            sage_try_depth--;
            if (_caught) {
                if (sage_truthy(sage_and(SAGE_EQ(sage_type(sage_load_slot(&sage_local_e_79, "e")), sage_string("Dict")), sage_dict_has_fn(sage_load_slot(&sage_local_e_79, "e"), sage_string("__signal"))))) {
                    if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_e_79, "e"), sage_string("__signal")), sage_string("GOTO")))) {
                        sage_define_slot(&sage_local_target_80, sage_index(sage_load_slot(&sage_local_e_79, "e"), sage_string("target")));
                        if (sage_truthy(sage_dict_has_fn(sage_index(sage_load_slot(&sage_local_self_75, "self"), sage_string("labels")), sage_load_slot(&sage_local_target_80, "target")))) {
                            (void)sage_assign_slot(&sage_local_ip_77, "ip", SAGE_ADD(sage_index(sage_index(sage_load_slot(&sage_local_self_75, "self"), sage_string("labels")), sage_load_slot(&sage_local_target_80, "target")), sage_number(1)));
                        }
                        else {
                            sage_print_ln(SAGE_ADD(sage_string("GOTO: Label not found: "), sage_load_slot(&sage_local_target_80, "target")));
                            return sage_gc_return(&sage_gc_frame, sage_number(1));
                        }
                    }
                    else {
                        if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_e_79, "e"), sage_string("__signal")), sage_string("EXIT")))) {
                            return sage_gc_return(&sage_gc_frame, sage_index(sage_load_slot(&sage_local_e_79, "e"), sage_string("code")));
                        }
                    }
                }
                else {
                    sage_raise(sage_load_slot(&sage_local_e_79, "e"));
                }
            }
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Interpreter_run_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_sub_89 = sage_slot_undefined();
    SageSlot sage_local_ast_88 = sage_slot_undefined();
    SageSlot sage_local_parser_87 = sage_slot_undefined();
    SageSlot sage_local_tokens_86 = sage_slot_undefined();
    SageSlot sage_local_lexer_85 = sage_slot_undefined();
    SageSlot sage_local_source_84 = sage_slot_undefined();
    SageSlot sage_local_args_83 = sage_slot_undefined();
    SageSlot sage_local_path_82 = sage_slot_undefined();
    SageSlot sage_local_self_81 = sage_slot_undefined();
    SageSlot* sage_gc_roots[9] = {&sage_local_sub_89, &sage_local_ast_88, &sage_local_parser_87, &sage_local_tokens_86, &sage_local_lexer_85, &sage_local_source_84, &sage_local_args_83, &sage_local_path_82, &sage_local_self_81};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 9);
    sage_define_slot(&sage_local_self_81, _self);
    sage_define_slot(&sage_local_path_82, _argv[0]);
    sage_define_slot(&sage_local_args_83, _argv[1]);
    (void)_argc;
    sage_define_slot(&sage_local_source_84, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_81, "self"), sage_string("ctx")), sage_string("fs")), "read_file", 1, (SageValue[]){sage_load_slot(&sage_local_path_82, "path")}));
    sage_define_slot(&sage_local_lexer_85, sage_construct("Lexer", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_source_84, "source")}));
    sage_define_slot(&sage_local_tokens_86, sage_call_method(sage_load_slot(&sage_local_lexer_85, "lexer"), "tokenize", 0, NULL));
    sage_define_slot(&sage_local_parser_87, sage_construct("Parser", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_tokens_86, "tokens")}));
    sage_define_slot(&sage_local_ast_88, sage_call_method(sage_load_slot(&sage_local_parser_87, "parser"), "parse", 0, NULL));
    sage_define_slot(&sage_local_sub_89, sage_construct("Interpreter", NULL, 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_81, "self"), sage_string("process"))}));
    (void)({SageValue _obj = sage_index(sage_load_slot(&sage_local_sub_89, "sub"), sage_string("ctx")); SageValue _val = sage_load_slot(&sage_local_args_83, "args"); sage_dict_set(_obj.as.dict, "args", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_sub_89, "sub"), "run_program", 1, (SageValue[]){sage_load_slot(&sage_local_ast_88, "ast")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_tokens_91 = sage_slot_undefined();
    SageSlot sage_local_self_90 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_tokens_91, &sage_local_self_90};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_90, _self);
    sage_define_slot(&sage_local_tokens_91, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_90, "self"); SageValue _val = sage_load_slot(&sage_local_tokens_91, "tokens"); sage_dict_set(_obj.as.dict, "tokens", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_90, "self"); SageValue _val = sage_number(0); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_peek(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_92 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_92};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_92, _self);
    (void)_argc;
    if (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_92, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_92, "self"), sage_string("tokens")))))) {
        return sage_gc_return(&sage_gc_frame, sage_index(sage_index(sage_load_slot(&sage_local_self_92, "self"), sage_string("tokens")), sage_index(sage_load_slot(&sage_local_self_92, "self"), sage_string("pos"))));
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_peek_kind(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_t_94 = sage_slot_undefined();
    SageSlot sage_local_self_93 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_t_94, &sage_local_self_93};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_93, _self);
    (void)_argc;
    sage_define_slot(&sage_local_t_94, sage_call_method(sage_load_slot(&sage_local_self_93, "self"), "peek", 0, NULL));
    if (sage_truthy(SAGE_NEQ(sage_load_slot(&sage_local_t_94, "t"), sage_nil()))) {
        return sage_gc_return(&sage_gc_frame, sage_index(sage_load_slot(&sage_local_t_94, "t"), sage_string("kind")));
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_global_TOK_EOF_10, "TOK_EOF"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_advance(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_t_96 = sage_slot_undefined();
    SageSlot sage_local_self_95 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_t_96, &sage_local_self_95};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_95, _self);
    (void)_argc;
    sage_define_slot(&sage_local_t_96, sage_index(sage_index(sage_load_slot(&sage_local_self_95, "self"), sage_string("tokens")), sage_index(sage_load_slot(&sage_local_self_95, "self"), sage_string("pos"))));
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_95, "self"); SageValue _val = SAGE_ADD(sage_index(sage_load_slot(&sage_local_self_95, "self"), sage_string("pos")), sage_number(1)); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_t_96, "t"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_expect(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_t_99 = sage_slot_undefined();
    SageSlot sage_local_kind_98 = sage_slot_undefined();
    SageSlot sage_local_self_97 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_t_99, &sage_local_kind_98, &sage_local_self_97};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_97, _self);
    sage_define_slot(&sage_local_kind_98, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_t_99, sage_call_method(sage_load_slot(&sage_local_self_97, "self"), "advance", 0, NULL));
    if (sage_truthy(SAGE_NEQ(sage_index(sage_load_slot(&sage_local_t_99, "t"), sage_string("kind")), sage_load_slot(&sage_local_kind_98, "kind")))) {
        sage_raise(SAGE_ADD(SAGE_ADD(SAGE_ADD(SAGE_ADD(SAGE_ADD(sage_string("Parse error: expected "), sage_load_slot(&sage_local_kind_98, "kind")), sage_string(" got ")), sage_index(sage_load_slot(&sage_local_t_99, "t"), sage_string("kind"))), sage_string(" at line ")), sage_str(sage_index(sage_load_slot(&sage_local_t_99, "t"), sage_string("line")))));
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_t_99, "t"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_skip_newlines(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_100 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_100};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_100, _self);
    (void)_argc;
    while (sage_truthy(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_100, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_NEWLINE_9, "TOK_NEWLINE")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_100, "self"), "advance", 0, NULL);
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_at_end(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_101 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_101};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_101, _self);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_101, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_EOF_10, "TOK_EOF")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_collect_args(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_103 = sage_slot_undefined();
    SageSlot sage_local_self_102 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_103, &sage_local_self_102};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_102, _self);
    (void)_argc;
    sage_define_slot(&sage_local_args_103, sage_make_array(0, NULL));
    while (sage_truthy(sage_and(sage_and(sage_and(sage_and(sage_and(SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_NEWLINE_9, "TOK_NEWLINE")), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_EOF_10, "TOK_EOF"))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_AMP_11, "TOK_AMP"))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_PIPE_8, "TOK_PIPE"))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_REDIRECT_7, "TOK_REDIRECT"))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_PAREN_R_13, "TOK_PAREN_R"))))) {
        (void)sage_push(sage_load_slot(&sage_local_args_103, "args"), sage_call_method(sage_load_slot(&sage_local_self_102, "self"), "advance", 0, NULL));
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_args_103, "args"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_block(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_s_107 = sage_slot_undefined();
    SageSlot sage_local_stmts_106 = sage_slot_undefined();
    SageSlot sage_local_line_105 = sage_slot_undefined();
    SageSlot sage_local_self_104 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_s_107, &sage_local_stmts_106, &sage_local_line_105, &sage_local_self_104};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_104, _self);
    (void)_argc;
    sage_define_slot(&sage_local_line_105, sage_index(sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "peek", 0, NULL), sage_string("line")));
    (void)sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_PAREN_L_12, "TOK_PAREN_L")});
    (void)sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "skip_newlines", 0, NULL);
    sage_define_slot(&sage_local_stmts_106, sage_make_array(0, NULL));
    while (sage_truthy(sage_and(SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_PAREN_R_13, "TOK_PAREN_R")), sage_not(sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "at_end", 0, NULL))))) {
        sage_define_slot(&sage_local_s_107, sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "parse_statement", 0, NULL));
        if (sage_truthy(SAGE_NEQ(sage_load_slot(&sage_local_s_107, "s"), sage_nil()))) {
            (void)sage_push(sage_load_slot(&sage_local_stmts_106, "stmts"), sage_load_slot(&sage_local_s_107, "s"));
        }
        (void)sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "skip_newlines", 0, NULL);
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_104, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_PAREN_R_13, "TOK_PAREN_R")});
    return sage_gc_return(&sage_gc_frame, sage_construct("BlockNode", NULL, 2, (SageValue[]){sage_load_slot(&sage_local_stmts_106, "stmts"), sage_load_slot(&sage_local_line_105, "line")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_statement(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_kw_111 = sage_slot_undefined();
    SageSlot sage_local_t_110 = sage_slot_undefined();
    SageSlot sage_local_suppress_109 = sage_slot_undefined();
    SageSlot sage_local_self_108 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_kw_111, &sage_local_t_110, &sage_local_suppress_109, &sage_local_self_108};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_108, _self);
    (void)_argc;
    (void)sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "skip_newlines", 0, NULL);
    if (sage_truthy(sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "at_end", 0, NULL))) {
        return sage_gc_return(&sage_gc_frame, sage_nil());
    }
    sage_define_slot(&sage_local_suppress_109, sage_bool(0));
    if (sage_truthy(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_AT_14, "TOK_AT")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "advance", 0, NULL);
        (void)sage_assign_slot(&sage_local_suppress_109, "suppress", sage_bool(1));
    }
    sage_define_slot(&sage_local_t_110, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "peek", 0, NULL));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_t_110, "t"), sage_nil()))) {
        return sage_gc_return(&sage_gc_frame, sage_nil());
    }
    if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_t_110, "t"), sage_string("kind")), sage_load_slot(&sage_global_TOK_LABEL_5, "TOK_LABEL")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_label", 0, NULL));
    }
    if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_t_110, "t"), sage_string("kind")), sage_load_slot(&sage_global_TOK_PAREN_L_12, "TOK_PAREN_L")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_block", 0, NULL));
    }
    if (sage_truthy(SAGE_NEQ(sage_index(sage_load_slot(&sage_local_t_110, "t"), sage_string("kind")), sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_command", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    }
    sage_define_slot(&sage_local_kw_111, sage_index(sage_load_slot(&sage_local_t_110, "t"), sage_string("value")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("REM")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_rem", 0, NULL));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("GOTO")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_goto", 0, NULL));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("CALL")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_call", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("IF")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_if", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("FOR")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_for", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("SET")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_set", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    }
    if (sage_truthy(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(sage_or(SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("ECHO")), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("PAUSE"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("CLS"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("EXIT"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("CD"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("MD"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("RD"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("DIR"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("TYPE"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("COPY"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("MOVE"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("DEL"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("REN"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("SHIFT"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("VER"))), SAGE_EQ(sage_load_slot(&sage_local_kw_111, "kw"), sage_string("HELP"))))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_command", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    }
    return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_108, "self"), "parse_command", 1, (SageValue[]){sage_load_slot(&sage_local_suppress_109, "suppress")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_label(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_t_113 = sage_slot_undefined();
    SageSlot sage_local_self_112 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_t_113, &sage_local_self_112};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_112, _self);
    (void)_argc;
    sage_define_slot(&sage_local_t_113, sage_call_method(sage_load_slot(&sage_local_self_112, "self"), "advance", 0, NULL));
    return sage_gc_return(&sage_gc_frame, sage_construct("LabelNode", NULL, 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_t_113, "t"), sage_string("value")), sage_index(sage_load_slot(&sage_local_t_113, "t"), sage_string("line"))}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_rem(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_115 = sage_slot_undefined();
    SageSlot sage_local_self_114 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_line_115, &sage_local_self_114};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_114, _self);
    (void)_argc;
    sage_define_slot(&sage_local_line_115, sage_index(sage_call_method(sage_load_slot(&sage_local_self_114, "self"), "peek", 0, NULL), sage_string("line")));
    (void)sage_call_method(sage_load_slot(&sage_local_self_114, "self"), "advance", 0, NULL);
    while (sage_truthy(sage_and(SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_114, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_NEWLINE_9, "TOK_NEWLINE")), sage_not(sage_call_method(sage_load_slot(&sage_local_self_114, "self"), "at_end", 0, NULL))))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_114, "self"), "advance", 0, NULL);
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_goto(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_target_118 = sage_slot_undefined();
    SageSlot sage_local_line_117 = sage_slot_undefined();
    SageSlot sage_local_self_116 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_target_118, &sage_local_line_117, &sage_local_self_116};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_116, _self);
    (void)_argc;
    sage_define_slot(&sage_local_line_117, sage_index(sage_call_method(sage_load_slot(&sage_local_self_116, "self"), "advance", 0, NULL), sage_string("line")));
    sage_define_slot(&sage_local_target_118, sage_call_method(sage_load_slot(&sage_local_self_116, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")}));
    return sage_gc_return(&sage_gc_frame, sage_construct("GotoNode", NULL, 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_target_118, "target"), sage_string("value")), sage_load_slot(&sage_local_line_117, "line")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_call(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_target_124 = sage_slot_undefined();
    SageSlot sage_local_t_123 = sage_slot_undefined();
    SageSlot sage_local_is_sub_122 = sage_slot_undefined();
    SageSlot sage_local_line_121 = sage_slot_undefined();
    SageSlot sage_local_suppress_120 = sage_slot_undefined();
    SageSlot sage_local_self_119 = sage_slot_undefined();
    SageSlot* sage_gc_roots[6] = {&sage_local_target_124, &sage_local_t_123, &sage_local_is_sub_122, &sage_local_line_121, &sage_local_suppress_120, &sage_local_self_119};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 6);
    sage_define_slot(&sage_local_self_119, _self);
    sage_define_slot(&sage_local_suppress_120, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_line_121, sage_index(sage_call_method(sage_load_slot(&sage_local_self_119, "self"), "advance", 0, NULL), sage_string("line")));
    sage_define_slot(&sage_local_is_sub_122, sage_bool(0));
    sage_define_slot(&sage_local_t_123, sage_call_method(sage_load_slot(&sage_local_self_119, "self"), "peek", 0, NULL));
    if (sage_truthy(sage_and(SAGE_NEQ(sage_load_slot(&sage_local_t_123, "t"), sage_nil()), SAGE_EQ(sage_index(sage_load_slot(&sage_local_t_123, "t"), sage_string("kind")), sage_load_slot(&sage_global_TOK_LABEL_5, "TOK_LABEL"))))) {
        (void)sage_assign_slot(&sage_local_is_sub_122, "is_sub", sage_bool(1));
        (void)sage_call_method(sage_load_slot(&sage_local_self_119, "self"), "advance", 0, NULL);
        return sage_gc_return(&sage_gc_frame, sage_construct("CallNode", NULL, 4, (SageValue[]){sage_index(sage_load_slot(&sage_local_t_123, "t"), sage_string("value")), sage_call_method(sage_load_slot(&sage_local_self_119, "self"), "collect_args", 0, NULL), sage_load_slot(&sage_local_is_sub_122, "is_sub"), sage_load_slot(&sage_local_line_121, "line")}));
    }
    sage_define_slot(&sage_local_target_124, sage_call_method(sage_load_slot(&sage_local_self_119, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")}));
    return sage_gc_return(&sage_gc_frame, sage_construct("CallNode", NULL, 4, (SageValue[]){sage_index(sage_load_slot(&sage_local_target_124, "target"), sage_string("value")), sage_call_method(sage_load_slot(&sage_local_self_119, "self"), "collect_args", 0, NULL), sage_bool(0), sage_load_slot(&sage_local_line_121, "line")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_if(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_alternate_131 = sage_slot_undefined();
    SageSlot sage_local_consequent_130 = sage_slot_undefined();
    SageSlot sage_local_condition_129 = sage_slot_undefined();
    SageSlot sage_local_negated_128 = sage_slot_undefined();
    SageSlot sage_local_line_127 = sage_slot_undefined();
    SageSlot sage_local_suppress_126 = sage_slot_undefined();
    SageSlot sage_local_self_125 = sage_slot_undefined();
    SageSlot* sage_gc_roots[7] = {&sage_local_alternate_131, &sage_local_consequent_130, &sage_local_condition_129, &sage_local_negated_128, &sage_local_line_127, &sage_local_suppress_126, &sage_local_self_125};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 7);
    sage_define_slot(&sage_local_self_125, _self);
    sage_define_slot(&sage_local_suppress_126, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_line_127, sage_index(sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "advance", 0, NULL), sage_string("line")));
    sage_define_slot(&sage_local_negated_128, sage_bool(0));
    if (sage_truthy(sage_and(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")), SAGE_EQ(sage_index(sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "peek", 0, NULL), sage_string("value")), sage_string("NOT"))))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "advance", 0, NULL);
        (void)sage_assign_slot(&sage_local_negated_128, "negated", sage_bool(1));
    }
    sage_define_slot(&sage_local_condition_129, sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "parse_condition", 0, NULL));
    sage_define_slot(&sage_local_consequent_130, sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "parse_statement", 0, NULL));
    sage_define_slot(&sage_local_alternate_131, sage_nil());
    if (sage_truthy(sage_and(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")), SAGE_EQ(sage_index(sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "peek", 0, NULL), sage_string("value")), sage_string("ELSE"))))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "advance", 0, NULL);
        (void)sage_assign_slot(&sage_local_alternate_131, "alternate", sage_call_method(sage_load_slot(&sage_local_self_125, "self"), "parse_statement", 0, NULL));
    }
    return sage_gc_return(&sage_gc_frame, sage_construct("IfStatement", NULL, 5, (SageValue[]){sage_load_slot(&sage_local_negated_128, "negated"), sage_load_slot(&sage_local_condition_129, "condition"), sage_load_slot(&sage_local_consequent_130, "consequent"), sage_load_slot(&sage_local_alternate_131, "alternate"), sage_load_slot(&sage_local_line_127, "line")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_condition(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_right_140 = sage_slot_undefined();
    SageSlot sage_local_op_139 = sage_slot_undefined();
    SageSlot sage_local_left_138 = sage_slot_undefined();
    SageSlot sage_local_level_137 = sage_slot_undefined();
    SageSlot sage_local_vname_136 = sage_slot_undefined();
    SageSlot sage_local_path_135 = sage_slot_undefined();
    SageSlot sage_local_kw_134 = sage_slot_undefined();
    SageSlot sage_local_t_133 = sage_slot_undefined();
    SageSlot sage_local_self_132 = sage_slot_undefined();
    SageSlot* sage_gc_roots[9] = {&sage_local_right_140, &sage_local_op_139, &sage_local_left_138, &sage_local_level_137, &sage_local_vname_136, &sage_local_path_135, &sage_local_kw_134, &sage_local_t_133, &sage_local_self_132};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 9);
    sage_define_slot(&sage_local_self_132, _self);
    (void)_argc;
    sage_define_slot(&sage_local_t_133, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "peek", 0, NULL));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_t_133, "t"), sage_nil()))) {
        sage_raise(sage_string("Parse error: expected condition"));
    }
    sage_define_slot(&sage_local_kw_134, sage_index(sage_load_slot(&sage_local_t_133, "t"), sage_string("value")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_134, "kw"), sage_string("EXIST")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL);
        sage_define_slot(&sage_local_path_135, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL));
        return sage_gc_return(&sage_gc_frame, sage_make_dict_from_entries(2, (const char*[]){"type", "path"}, (SageValue[]){sage_string("EXIST"), sage_index(sage_load_slot(&sage_local_path_135, "path"), sage_string("value"))}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_134, "kw"), sage_string("DEFINED")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL);
        sage_define_slot(&sage_local_vname_136, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL));
        return sage_gc_return(&sage_gc_frame, sage_make_dict_from_entries(2, (const char*[]){"type", "name"}, (SageValue[]){sage_string("DEFINED"), sage_index(sage_load_slot(&sage_local_vname_136, "vname"), sage_string("value"))}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_kw_134, "kw"), sage_string("ERRORLEVEL")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL);
        sage_define_slot(&sage_local_level_137, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL));
        return sage_gc_return(&sage_gc_frame, sage_make_dict_from_entries(2, (const char*[]){"type", "level"}, (SageValue[]){sage_string("ERRORLEVEL"), sage_index(sage_load_slot(&sage_local_level_137, "level"), sage_string("value"))}));
    }
    sage_define_slot(&sage_local_left_138, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL));
    sage_define_slot(&sage_local_op_139, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL));
    sage_define_slot(&sage_local_right_140, sage_call_method(sage_load_slot(&sage_local_self_132, "self"), "advance", 0, NULL));
    return sage_gc_return(&sage_gc_frame, sage_make_dict_from_entries(4, (const char*[]){"type", "left", "op", "right"}, (SageValue[]){sage_string("CMP"), sage_index(sage_load_slot(&sage_local_left_138, "left"), sage_string("value")), sage_index(sage_load_slot(&sage_local_op_139, "op"), sage_string("value")), sage_index(sage_load_slot(&sage_local_right_140, "right"), sage_string("value"))}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_for(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_vname_149 = sage_slot_undefined();
    SageSlot sage_local_body_148 = sage_slot_undefined();
    SageSlot sage_local_in_list_147 = sage_slot_undefined();
    SageSlot sage_local_var_tok_146 = sage_slot_undefined();
    SageSlot sage_local_sw_145 = sage_slot_undefined();
    SageSlot sage_local_flags_144 = sage_slot_undefined();
    SageSlot sage_local_line_143 = sage_slot_undefined();
    SageSlot sage_local_suppress_142 = sage_slot_undefined();
    SageSlot sage_local_self_141 = sage_slot_undefined();
    SageSlot* sage_gc_roots[9] = {&sage_local_vname_149, &sage_local_body_148, &sage_local_in_list_147, &sage_local_var_tok_146, &sage_local_sw_145, &sage_local_flags_144, &sage_local_line_143, &sage_local_suppress_142, &sage_local_self_141};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 9);
    sage_define_slot(&sage_local_self_141, _self);
    sage_define_slot(&sage_local_suppress_142, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_line_143, sage_index(sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "advance", 0, NULL), sage_string("line")));
    sage_define_slot(&sage_local_flags_144, sage_make_dict());
    while (sage_truthy(sage_and(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")), sage_startswith(sage_index(sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "peek", 0, NULL), sage_string("value")), sage_string("/"))))) {
        sage_define_slot(&sage_local_sw_145, sage_index(sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "advance", 0, NULL), sage_string("value")));
        (void)sage_index_set(sage_load_slot(&sage_local_flags_144, "flags"), sage_load_slot(&sage_local_sw_145, "sw"), sage_bool(1));
    }
    sage_define_slot(&sage_local_var_tok_146, sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "advance", 0, NULL));
    (void)sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")});
    (void)sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_PAREN_L_12, "TOK_PAREN_L")});
    sage_define_slot(&sage_local_in_list_147, sage_make_array(0, NULL));
    while (sage_truthy(sage_and(SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_PAREN_R_13, "TOK_PAREN_R")), sage_not(sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "at_end", 0, NULL))))) {
        (void)sage_push(sage_load_slot(&sage_local_in_list_147, "in_list"), sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "advance", 0, NULL));
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_PAREN_R_13, "TOK_PAREN_R")});
    (void)sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "expect", 1, (SageValue[]){sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD")});
    sage_define_slot(&sage_local_body_148, sage_call_method(sage_load_slot(&sage_local_self_141, "self"), "parse_statement", 0, NULL));
    sage_define_slot(&sage_local_vname_149, sage_index(sage_load_slot(&sage_local_var_tok_146, "var_tok"), sage_string("value")));
    if (sage_truthy(sage_startswith(sage_load_slot(&sage_local_vname_149, "vname"), sage_string("%")))) {
        (void)sage_assign_slot(&sage_local_vname_149, "vname", sage_slice(sage_load_slot(&sage_local_vname_149, "vname"), sage_number(1), sage_len(sage_load_slot(&sage_local_vname_149, "vname"))));
    }
    return sage_gc_return(&sage_gc_frame, sage_construct("ForStatement", NULL, 5, (SageValue[]){sage_load_slot(&sage_local_vname_149, "vname"), sage_load_slot(&sage_local_in_list_147, "in_list"), sage_load_slot(&sage_local_body_148, "body"), sage_load_slot(&sage_local_flags_144, "flags"), sage_load_slot(&sage_local_line_143, "line")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_set(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_vval_159 = sage_slot_undefined();
    SageSlot sage_local_vname_158 = sage_slot_undefined();
    SageSlot sage_local_i_157 = sage_slot_undefined();
    SageSlot sage_local_eq_156 = sage_slot_undefined();
    SageSlot sage_local_p_155 = sage_slot_undefined();
    SageSlot sage_local_raw_154 = sage_slot_undefined();
    SageSlot sage_local_parts_153 = sage_slot_undefined();
    SageSlot sage_local_line_152 = sage_slot_undefined();
    SageSlot sage_local_suppress_151 = sage_slot_undefined();
    SageSlot sage_local_self_150 = sage_slot_undefined();
    SageSlot* sage_gc_roots[10] = {&sage_local_vval_159, &sage_local_vname_158, &sage_local_i_157, &sage_local_eq_156, &sage_local_p_155, &sage_local_raw_154, &sage_local_parts_153, &sage_local_line_152, &sage_local_suppress_151, &sage_local_self_150};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 10);
    sage_define_slot(&sage_local_self_150, _self);
    sage_define_slot(&sage_local_suppress_151, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_line_152, sage_index(sage_call_method(sage_load_slot(&sage_local_self_150, "self"), "advance", 0, NULL), sage_string("line")));
    sage_define_slot(&sage_local_parts_153, sage_call_method(sage_load_slot(&sage_local_self_150, "self"), "collect_args", 0, NULL));
    sage_define_slot(&sage_local_raw_154, sage_string(""));
    {
        SageValue sage_iter_p_160 = sage_load_slot(&sage_local_parts_153, "parts");
        if (sage_iter_p_160.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_p_161 = 0; sage_idx_p_161 < sage_iter_p_160.as.array->count; sage_idx_p_161++) {
                sage_define_slot(&sage_local_p_155, sage_iter_p_160.as.array->elements[sage_idx_p_161]);
                    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_raw_154, "raw")), sage_number(0)))) {
                        (void)sage_assign_slot(&sage_local_raw_154, "raw", SAGE_ADD(sage_load_slot(&sage_local_raw_154, "raw"), sage_string(" ")));
                    }
                    (void)sage_assign_slot(&sage_local_raw_154, "raw", SAGE_ADD(sage_load_slot(&sage_local_raw_154, "raw"), sage_index(sage_load_slot(&sage_local_p_155, "p"), sage_string("value"))));
            }
        } else if (sage_iter_p_160.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_p_160.as.string);
            for (int sage_idx_p_161 = 0; sage_idx_p_161 < _len; sage_idx_p_161++) {
                char _ch[2] = {sage_iter_p_160.as.string[sage_idx_p_161], '\0'};
                sage_define_slot(&sage_local_p_155, sage_string(_ch));
                    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_raw_154, "raw")), sage_number(0)))) {
                        (void)sage_assign_slot(&sage_local_raw_154, "raw", SAGE_ADD(sage_load_slot(&sage_local_raw_154, "raw"), sage_string(" ")));
                    }
                    (void)sage_assign_slot(&sage_local_raw_154, "raw", SAGE_ADD(sage_load_slot(&sage_local_raw_154, "raw"), sage_index(sage_load_slot(&sage_local_p_155, "p"), sage_string("value"))));
            }
        }
    }
    sage_define_slot(&sage_local_eq_156, SAGE_SUB(sage_number(0), sage_number(1)));
    sage_define_slot(&sage_local_i_157, sage_number(0));
    while (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_i_157, "i"), sage_len(sage_load_slot(&sage_local_raw_154, "raw"))))) {
        if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_raw_154, "raw"), sage_load_slot(&sage_local_i_157, "i")), sage_string("=")))) {
            (void)sage_assign_slot(&sage_local_eq_156, "eq", sage_load_slot(&sage_local_i_157, "i"));
            break;
        }
        (void)sage_assign_slot(&sage_local_i_157, "i", SAGE_ADD(sage_load_slot(&sage_local_i_157, "i"), sage_number(1)));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_eq_156, "eq"), SAGE_SUB(sage_number(0), sage_number(1))))) {
        return sage_gc_return(&sage_gc_frame, sage_construct("Command", NULL, 4, (SageValue[]){sage_string("SET"), sage_load_slot(&sage_local_parts_153, "parts"), sage_load_slot(&sage_local_suppress_151, "suppress"), sage_load_slot(&sage_local_line_152, "line")}));
    }
    sage_define_slot(&sage_local_vname_158, sage_slice(sage_load_slot(&sage_local_raw_154, "raw"), sage_number(0), sage_load_slot(&sage_local_eq_156, "eq")));
    sage_define_slot(&sage_local_vval_159, sage_slice(sage_load_slot(&sage_local_raw_154, "raw"), SAGE_ADD(sage_load_slot(&sage_local_eq_156, "eq"), sage_number(1)), sage_len(sage_load_slot(&sage_local_raw_154, "raw"))));
    return sage_gc_return(&sage_gc_frame, sage_construct("Assignment", NULL, 3, (SageValue[]){sage_upper(sage_load_slot(&sage_local_vname_158, "vname")), sage_load_slot(&sage_local_vval_159, "vval"), sage_load_slot(&sage_local_line_152, "line")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_command(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_right_171 = sage_slot_undefined();
    SageSlot sage_local_fname_170 = sage_slot_undefined();
    SageSlot sage_local_op_169 = sage_slot_undefined();
    SageSlot sage_local_cmd_168 = sage_slot_undefined();
    SageSlot sage_local_args_167 = sage_slot_undefined();
    SageSlot sage_local_name_166 = sage_slot_undefined();
    SageSlot sage_local_line_165 = sage_slot_undefined();
    SageSlot sage_local_t_164 = sage_slot_undefined();
    SageSlot sage_local_suppress_163 = sage_slot_undefined();
    SageSlot sage_local_self_162 = sage_slot_undefined();
    SageSlot* sage_gc_roots[10] = {&sage_local_right_171, &sage_local_fname_170, &sage_local_op_169, &sage_local_cmd_168, &sage_local_args_167, &sage_local_name_166, &sage_local_line_165, &sage_local_t_164, &sage_local_suppress_163, &sage_local_self_162};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 10);
    sage_define_slot(&sage_local_self_162, _self);
    sage_define_slot(&sage_local_suppress_163, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_t_164, sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "advance", 0, NULL));
    sage_define_slot(&sage_local_line_165, sage_index(sage_load_slot(&sage_local_t_164, "t"), sage_string("line")));
    sage_define_slot(&sage_local_name_166, sage_index(sage_load_slot(&sage_local_t_164, "t"), sage_string("value")));
    sage_define_slot(&sage_local_args_167, sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "collect_args", 0, NULL));
    sage_define_slot(&sage_local_cmd_168, sage_construct("Command", NULL, 4, (SageValue[]){sage_load_slot(&sage_local_name_166, "name"), sage_load_slot(&sage_local_args_167, "args"), sage_load_slot(&sage_local_suppress_163, "suppress"), sage_load_slot(&sage_local_line_165, "line")}));
    if (sage_truthy(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_REDIRECT_7, "TOK_REDIRECT")))) {
        sage_define_slot(&sage_local_op_169, sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "advance", 0, NULL));
        sage_define_slot(&sage_local_fname_170, sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "advance", 0, NULL));
        return sage_gc_return(&sage_gc_frame, sage_construct("RedirectNode", NULL, 4, (SageValue[]){sage_load_slot(&sage_local_cmd_168, "cmd"), sage_index(sage_load_slot(&sage_local_op_169, "op"), sage_string("value")), sage_index(sage_load_slot(&sage_local_fname_170, "fname"), sage_string("value")), sage_load_slot(&sage_local_line_165, "line")}));
    }
    if (sage_truthy(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "peek_kind", 0, NULL), sage_load_slot(&sage_global_TOK_PIPE_8, "TOK_PIPE")))) {
        (void)sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "advance", 0, NULL);
        sage_define_slot(&sage_local_right_171, sage_call_method(sage_load_slot(&sage_local_self_162, "self"), "parse_statement", 0, NULL));
        return sage_gc_return(&sage_gc_frame, sage_construct("PipeNode", NULL, 3, (SageValue[]){sage_load_slot(&sage_local_cmd_168, "cmd"), sage_load_slot(&sage_local_right_171, "right"), sage_load_slot(&sage_local_line_165, "line")}));
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_cmd_168, "cmd"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse_block_contents(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_172 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_172};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_172, _self);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_172, "self"), "parse_block", 0, NULL));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Parser_parse(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_s_175 = sage_slot_undefined();
    SageSlot sage_local_stmts_174 = sage_slot_undefined();
    SageSlot sage_local_self_173 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_s_175, &sage_local_stmts_174, &sage_local_self_173};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_173, _self);
    (void)_argc;
    sage_define_slot(&sage_local_stmts_174, sage_make_array(0, NULL));
    (void)sage_call_method(sage_load_slot(&sage_local_self_173, "self"), "skip_newlines", 0, NULL);
    while (sage_truthy(sage_not(sage_call_method(sage_load_slot(&sage_local_self_173, "self"), "at_end", 0, NULL)))) {
        sage_define_slot(&sage_local_s_175, sage_call_method(sage_load_slot(&sage_local_self_173, "self"), "parse_statement", 0, NULL));
        if (sage_truthy(SAGE_NEQ(sage_load_slot(&sage_local_s_175, "s"), sage_nil()))) {
            (void)sage_push(sage_load_slot(&sage_local_stmts_174, "stmts"), sage_load_slot(&sage_local_s_175, "s"));
        }
        (void)sage_call_method(sage_load_slot(&sage_local_self_173, "self"), "skip_newlines", 0, NULL);
    }
    return sage_gc_return(&sage_gc_frame, sage_construct("Program", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_stmts_174, "stmts")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_source_177 = sage_slot_undefined();
    SageSlot sage_local_self_176 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_source_177, &sage_local_self_176};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_176, _self);
    sage_define_slot(&sage_local_source_177, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_176, "self"); SageValue _val = sage_load_slot(&sage_local_source_177, "source"); sage_dict_set(_obj.as.dict, "source", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_176, "self"); SageValue _val = sage_number(0); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_176, "self"); SageValue _val = sage_number(1); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_176, "self"); SageValue _val = sage_make_array(0, NULL); sage_dict_set(_obj.as.dict, "tokens", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_get_char(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ch_180 = sage_slot_undefined();
    SageSlot sage_local_index_179 = sage_slot_undefined();
    SageSlot sage_local_self_178 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_ch_180, &sage_local_index_179, &sage_local_self_178};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_178, _self);
    sage_define_slot(&sage_local_index_179, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_ch_180, sage_index(sage_index(sage_load_slot(&sage_local_self_178, "self"), sage_string("source")), sage_load_slot(&sage_local_index_179, "index")));
    if (sage_truthy(SAGE_EQ(sage_type(sage_load_slot(&sage_local_ch_180, "ch")), sage_string("number")))) {
        return sage_gc_return(&sage_gc_frame, sage_chr(sage_load_slot(&sage_local_ch_180, "ch")));
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_ch_180, "ch"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_peek(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_181 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_181};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_181, _self);
    (void)_argc;
    if (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_181, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_181, "self"), sage_string("source")))))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_181, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_181, "self"), sage_string("pos"))}));
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_advance(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ch_183 = sage_slot_undefined();
    SageSlot sage_local_self_182 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_ch_183, &sage_local_self_182};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_182, _self);
    (void)_argc;
    sage_define_slot(&sage_local_ch_183, sage_call_method(sage_load_slot(&sage_local_self_182, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_182, "self"), sage_string("pos"))}));
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_182, "self"); SageValue _val = SAGE_ADD(sage_index(sage_load_slot(&sage_local_self_182, "self"), sage_string("pos")), sage_number(1)); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_183, "ch"), sage_string("\n")))) {
        (void)({SageValue _obj = sage_load_slot(&sage_local_self_182, "self"); SageValue _val = SAGE_ADD(sage_index(sage_load_slot(&sage_local_self_182, "self"), sage_string("line")), sage_number(1)); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_ch_183, "ch"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_match_char(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_expected_185 = sage_slot_undefined();
    SageSlot sage_local_self_184 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_expected_185, &sage_local_self_184};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_184, _self);
    sage_define_slot(&sage_local_expected_185, _argv[0]);
    (void)_argc;
    if (sage_truthy(sage_and(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_184, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_184, "self"), sage_string("source")))), SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_184, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_184, "self"), sage_string("pos"))}), sage_load_slot(&sage_local_expected_185, "expected"))))) {
        (void)({SageValue _obj = sage_load_slot(&sage_local_self_184, "self"); SageValue _val = SAGE_ADD(sage_index(sage_load_slot(&sage_local_self_184, "self"), sage_string("pos")), sage_number(1)); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
        return sage_gc_return(&sage_gc_frame, sage_bool(1));
    }
    return sage_gc_return(&sage_gc_frame, sage_bool(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_skip_whitespace_inline(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ch_187 = sage_slot_undefined();
    SageSlot sage_local_self_186 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_ch_187, &sage_local_self_186};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_186, _self);
    (void)_argc;
    while (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_186, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_186, "self"), sage_string("source")))))) {
        sage_define_slot(&sage_local_ch_187, sage_call_method(sage_load_slot(&sage_local_self_186, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_186, "self"), sage_string("pos"))}));
        if (sage_truthy(sage_or(SAGE_EQ(sage_load_slot(&sage_local_ch_187, "ch"), sage_string(" ")), SAGE_EQ(sage_load_slot(&sage_local_ch_187, "ch"), sage_string("\t"))))) {
            (void)({SageValue _obj = sage_load_slot(&sage_local_self_186, "self"); SageValue _val = SAGE_ADD(sage_index(sage_load_slot(&sage_local_self_186, "self"), sage_string("pos")), sage_number(1)); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
        }
        else {
            break;
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_emit(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_value_190 = sage_slot_undefined();
    SageSlot sage_local_kind_189 = sage_slot_undefined();
    SageSlot sage_local_self_188 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_value_190, &sage_local_kind_189, &sage_local_self_188};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_188, _self);
    sage_define_slot(&sage_local_kind_189, _argv[0]);
    sage_define_slot(&sage_local_value_190, _argv[1]);
    (void)_argc;
    (void)sage_push(sage_index(sage_load_slot(&sage_local_self_188, "self"), sage_string("tokens")), sage_construct("Token", NULL, 3, (SageValue[]){sage_load_slot(&sage_local_kind_189, "kind"), sage_load_slot(&sage_local_value_190, "value"), sage_index(sage_load_slot(&sage_local_self_188, "self"), sage_string("line"))}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_scan_string(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ch_193 = sage_slot_undefined();
    SageSlot sage_local_buf_192 = sage_slot_undefined();
    SageSlot sage_local_self_191 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_ch_193, &sage_local_buf_192, &sage_local_self_191};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_191, _self);
    (void)_argc;
    sage_define_slot(&sage_local_buf_192, sage_string(""));
    while (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_191, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_191, "self"), sage_string("source")))))) {
        sage_define_slot(&sage_local_ch_193, sage_call_method(sage_load_slot(&sage_local_self_191, "self"), "advance", 0, NULL));
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_193, "ch"), sage_string("\"")))) {
            break;
        }
        (void)sage_assign_slot(&sage_local_buf_192, "buf", SAGE_ADD(sage_load_slot(&sage_local_buf_192, "buf"), sage_load_slot(&sage_local_ch_193, "ch")));
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_191, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_STRING_3, "TOK_STRING"), sage_load_slot(&sage_local_buf_192, "buf")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_scan_variable(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ch_198 = sage_slot_undefined();
    SageSlot sage_local_closer_197 = sage_slot_undefined();
    SageSlot sage_local_buf_196 = sage_slot_undefined();
    SageSlot sage_local_delayed_195 = sage_slot_undefined();
    SageSlot sage_local_self_194 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_ch_198, &sage_local_closer_197, &sage_local_buf_196, &sage_local_delayed_195, &sage_local_self_194};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_194, _self);
    sage_define_slot(&sage_local_delayed_195, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_buf_196, sage_string(""));
    sage_define_slot(&sage_local_closer_197, sage_string("%"));
    if (sage_truthy(sage_load_slot(&sage_local_delayed_195, "delayed"))) {
        (void)sage_assign_slot(&sage_local_closer_197, "closer", sage_string("!"));
    }
    while (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_194, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_194, "self"), sage_string("source")))))) {
        sage_define_slot(&sage_local_ch_198, sage_call_method(sage_load_slot(&sage_local_self_194, "self"), "advance", 0, NULL));
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_198, "ch"), sage_load_slot(&sage_local_closer_197, "closer")))) {
            break;
        }
        (void)sage_assign_slot(&sage_local_buf_196, "buf", SAGE_ADD(sage_load_slot(&sage_local_buf_196, "buf"), sage_load_slot(&sage_local_ch_198, "ch")));
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_194, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_VARIABLE_4, "TOK_VARIABLE"), sage_load_slot(&sage_local_buf_196, "buf")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_scan_word(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ch_203 = sage_slot_undefined();
    SageSlot sage_local_specials_202 = sage_slot_undefined();
    SageSlot sage_local_buf_201 = sage_slot_undefined();
    SageSlot sage_local_first_char_200 = sage_slot_undefined();
    SageSlot sage_local_self_199 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_ch_203, &sage_local_specials_202, &sage_local_buf_201, &sage_local_first_char_200, &sage_local_self_199};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_199, _self);
    sage_define_slot(&sage_local_first_char_200, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_buf_201, sage_load_slot(&sage_local_first_char_200, "first_char"));
    sage_define_slot(&sage_local_specials_202, sage_string(">< |&()\"\n\r\t%!"));
    while (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_199, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_199, "self"), sage_string("source")))))) {
        sage_define_slot(&sage_local_ch_203, sage_call_method(sage_load_slot(&sage_local_self_199, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_199, "self"), sage_string("pos"))}));
        if (sage_truthy(sage_contains(sage_load_slot(&sage_local_specials_202, "specials"), sage_load_slot(&sage_local_ch_203, "ch")))) {
            break;
        }
        (void)sage_assign_slot(&sage_local_buf_201, "buf", SAGE_ADD(sage_load_slot(&sage_local_buf_201, "buf"), sage_call_method(sage_load_slot(&sage_local_self_199, "self"), "advance", 0, NULL)));
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_199, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD"), sage_upper(sage_load_slot(&sage_local_buf_201, "buf"))});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_scan_redirect(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_buf_206 = sage_slot_undefined();
    SageSlot sage_local_first_char_205 = sage_slot_undefined();
    SageSlot sage_local_self_204 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_buf_206, &sage_local_first_char_205, &sage_local_self_204};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_204, _self);
    sage_define_slot(&sage_local_first_char_205, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_buf_206, sage_load_slot(&sage_local_first_char_205, "first_char"));
    if (sage_truthy(sage_or(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_204, "self"), "peek", 0, NULL), sage_string(">")), SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_204, "self"), "peek", 0, NULL), sage_string("&"))))) {
        (void)sage_assign_slot(&sage_local_buf_206, "buf", SAGE_ADD(sage_load_slot(&sage_local_buf_206, "buf"), sage_call_method(sage_load_slot(&sage_local_self_204, "self"), "advance", 0, NULL)));
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_204, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_REDIRECT_7, "TOK_REDIRECT"), sage_load_slot(&sage_local_buf_206, "buf")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_scan_comment(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_207 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_207};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_207, _self);
    (void)_argc;
    while (sage_truthy(sage_and(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_207, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_207, "self"), sage_string("source")))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_207, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_207, "self"), sage_string("pos"))}), sage_string("\n"))))) {
        (void)({SageValue _obj = sage_load_slot(&sage_local_self_207, "self"); SageValue _val = SAGE_ADD(sage_index(sage_load_slot(&sage_local_self_207, "self"), sage_string("pos")), sage_number(1)); sage_dict_set(_obj.as.dict, "pos", _val); _val;});
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Lexer_tokenize(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_buf_210 = sage_slot_undefined();
    SageSlot sage_local_ch_209 = sage_slot_undefined();
    SageSlot sage_local_self_208 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_buf_210, &sage_local_ch_209, &sage_local_self_208};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_208, _self);
    (void)_argc;
    while (sage_truthy(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("source")))))) {
        sage_define_slot(&sage_local_ch_209, sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "advance", 0, NULL));
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("\r")))) {
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("\n")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_NEWLINE_9, "TOK_NEWLINE"), sage_string("\n")});
            continue;
        }
        if (sage_truthy(sage_or(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string(" ")), SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("\t"))))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "skip_whitespace_inline", 0, NULL);
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("@")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_AT_14, "TOK_AT"), sage_string("@")});
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string(":")))) {
            if (sage_truthy(SAGE_EQ(sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "peek", 0, NULL), sage_string(":")))) {
                (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "scan_comment", 0, NULL);
            }
            else {
                sage_define_slot(&sage_local_buf_210, sage_string(""));
                while (sage_truthy(sage_and(sage_and(SAGE_LT(sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("pos")), sage_len(sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("source")))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("pos"))}), sage_string("\n"))), SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "get_char", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("pos"))}), sage_string(" "))))) {
                    (void)sage_assign_slot(&sage_local_buf_210, "buf", SAGE_ADD(sage_load_slot(&sage_local_buf_210, "buf"), sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "advance", 0, NULL)));
                }
                (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_LABEL_5, "TOK_LABEL"), sage_upper(sage_load_slot(&sage_local_buf_210, "buf"))});
            }
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("%")))) {
            if (sage_truthy(SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "peek", 0, NULL), sage_nil()))) {
                (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "scan_variable", 1, (SageValue[]){sage_bool(0)});
            }
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("!")))) {
            if (sage_truthy(SAGE_NEQ(sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "peek", 0, NULL), sage_nil()))) {
                (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "scan_variable", 1, (SageValue[]){sage_bool(1)});
            }
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("\"")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "scan_string", 0, NULL);
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("|")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_PIPE_8, "TOK_PIPE"), sage_string("|")});
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("&")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_AMP_11, "TOK_AMP"), sage_string("&")});
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("(")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_PAREN_L_12, "TOK_PAREN_L"), sage_string("(")});
            continue;
        }
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string(")")))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_PAREN_R_13, "TOK_PAREN_R"), sage_string(")")});
            continue;
        }
        if (sage_truthy(sage_or(SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string(">")), SAGE_EQ(sage_load_slot(&sage_local_ch_209, "ch"), sage_string("<"))))) {
            (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "scan_redirect", 1, (SageValue[]){sage_load_slot(&sage_local_ch_209, "ch")});
            continue;
        }
        (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "scan_word", 1, (SageValue[]){sage_load_slot(&sage_local_ch_209, "ch")});
    }
    (void)sage_call_method(sage_load_slot(&sage_local_self_208, "self"), "emit", 2, (SageValue[]){sage_load_slot(&sage_global_TOK_EOF_10, "TOK_EOF"), sage_nil()});
    return sage_gc_return(&sage_gc_frame, sage_index(sage_load_slot(&sage_local_self_208, "self"), sage_string("tokens")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandRegistry_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ctx_212 = sage_slot_undefined();
    SageSlot sage_local_self_211 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_ctx_212, &sage_local_self_211};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_211, _self);
    sage_define_slot(&sage_local_ctx_212, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_211, "self"); SageValue _val = sage_load_slot(&sage_local_ctx_212, "ctx"); sage_dict_set(_obj.as.dict, "ctx", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_211, "self"); SageValue _val = sage_construct("InternalCommands", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_ctx_212, "ctx")}); sage_dict_set(_obj.as.dict, "ic", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandRegistry_is_internal(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_key_215 = sage_slot_undefined();
    SageSlot sage_local_name_214 = sage_slot_undefined();
    SageSlot sage_local_self_213 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_key_215, &sage_local_name_214, &sage_local_self_213};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_213, _self);
    sage_define_slot(&sage_local_name_214, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_key_215, sage_upper(sage_load_slot(&sage_local_name_214, "name")));
    if (sage_truthy(sage_or(sage_or(sage_or(sage_or(SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("ECHO")), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("REM"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("SET"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("PAUSE"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("CLS"))))) {
        return sage_gc_return(&sage_gc_frame, sage_bool(1));
    }
    if (sage_truthy(sage_or(sage_or(sage_or(sage_or(SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("EXIT")), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("CD"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("MD"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("RD"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("DIR"))))) {
        return sage_gc_return(&sage_gc_frame, sage_bool(1));
    }
    if (sage_truthy(sage_or(sage_or(sage_or(sage_or(SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("TYPE")), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("COPY"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("MOVE"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("DEL"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("ERASE"))))) {
        return sage_gc_return(&sage_gc_frame, sage_bool(1));
    }
    if (sage_truthy(sage_or(sage_or(sage_or(sage_or(SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("REN")), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("RENAME"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("SHIFT"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("VER"))), SAGE_EQ(sage_load_slot(&sage_local_key_215, "key"), sage_string("HELP"))))) {
        return sage_gc_return(&sage_gc_frame, sage_bool(1));
    }
    return sage_gc_return(&sage_gc_frame, sage_bool(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandRegistry_dispatch(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_cmd_220 = sage_slot_undefined();
    SageSlot sage_local_key_219 = sage_slot_undefined();
    SageSlot sage_local_args_218 = sage_slot_undefined();
    SageSlot sage_local_name_217 = sage_slot_undefined();
    SageSlot sage_local_self_216 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_cmd_220, &sage_local_key_219, &sage_local_args_218, &sage_local_name_217, &sage_local_self_216};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_216, _self);
    sage_define_slot(&sage_local_name_217, _argv[0]);
    sage_define_slot(&sage_local_args_218, _argv[1]);
    (void)_argc;
    sage_define_slot(&sage_local_key_219, sage_upper(sage_load_slot(&sage_local_name_217, "name")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("ECHO")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_echo", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("REM")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_rem", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("SET")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_set", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("PAUSE")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_pause", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("CLS")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_cls", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("EXIT")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_exit", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("CD")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_cd", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("MD")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_md", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("RD")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_rd", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("DIR")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_dir", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("TYPE")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_type", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("COPY")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_copy", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("MOVE")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_move", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("DEL")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_del", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("ERASE")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_del", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("REN")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_ren", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("RENAME")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_ren", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("SHIFT")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_shift", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("VER")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_ver", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_key_219, "key"), sage_string("HELP")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_216, "self"), sage_string("ic")), "cmd_help", 1, (SageValue[]){sage_load_slot(&sage_local_args_218, "args")}));
    }
    sage_define_slot(&sage_local_cmd_220, sage_load_slot(&sage_local_name_217, "name"));
    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_args_218, "args")), sage_number(0)))) {
        (void)sage_assign_slot(&sage_local_cmd_220, "cmd", SAGE_ADD(SAGE_ADD(sage_load_slot(&sage_local_cmd_220, "cmd"), sage_string(" ")), sage_join_fn(sage_load_slot(&sage_local_args_218, "args"), sage_string(" "))));
    }
    return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_global_sys_17, "sys"), "exec", 1, (SageValue[]){sage_load_slot(&sage_local_cmd_220, "cmd")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ctx_222 = sage_slot_undefined();
    SageSlot sage_local_self_221 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_ctx_222, &sage_local_self_221};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_221, _self);
    sage_define_slot(&sage_local_ctx_222, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_221, "self"); SageValue _val = sage_load_slot(&sage_local_ctx_222, "ctx"); sage_dict_set(_obj.as.dict, "ctx", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_echo(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_val_227 = sage_slot_undefined();
    SageSlot sage_local_arg_226 = sage_slot_undefined();
    SageSlot sage_local_line_225 = sage_slot_undefined();
    SageSlot sage_local_args_224 = sage_slot_undefined();
    SageSlot sage_local_self_223 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_val_227, &sage_local_arg_226, &sage_local_line_225, &sage_local_args_224, &sage_local_self_223};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_223, _self);
    sage_define_slot(&sage_local_args_224, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_224, "args")), sage_number(0)))) {
        sage_print_ln(sage_string("ECHO is on"));
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    sage_define_slot(&sage_local_line_225, sage_string(""));
    {
        SageValue sage_iter_arg_228 = sage_load_slot(&sage_local_args_224, "args");
        if (sage_iter_arg_228.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_arg_229 = 0; sage_idx_arg_229 < sage_iter_arg_228.as.array->count; sage_idx_arg_229++) {
                sage_define_slot(&sage_local_arg_226, sage_iter_arg_228.as.array->elements[sage_idx_arg_229]);
                    sage_define_slot(&sage_local_val_227, sage_call_method(sage_index(sage_load_slot(&sage_local_self_223, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_arg_226, "arg")}));
                    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_line_225, "line")), sage_number(0)))) {
                        (void)sage_assign_slot(&sage_local_line_225, "line", SAGE_ADD(sage_load_slot(&sage_local_line_225, "line"), sage_string(" ")));
                    }
                    (void)sage_assign_slot(&sage_local_line_225, "line", SAGE_ADD(sage_load_slot(&sage_local_line_225, "line"), sage_load_slot(&sage_local_val_227, "val")));
            }
        } else if (sage_iter_arg_228.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_arg_228.as.string);
            for (int sage_idx_arg_229 = 0; sage_idx_arg_229 < _len; sage_idx_arg_229++) {
                char _ch[2] = {sage_iter_arg_228.as.string[sage_idx_arg_229], '\0'};
                sage_define_slot(&sage_local_arg_226, sage_string(_ch));
                    sage_define_slot(&sage_local_val_227, sage_call_method(sage_index(sage_load_slot(&sage_local_self_223, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_arg_226, "arg")}));
                    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_line_225, "line")), sage_number(0)))) {
                        (void)sage_assign_slot(&sage_local_line_225, "line", SAGE_ADD(sage_load_slot(&sage_local_line_225, "line"), sage_string(" ")));
                    }
                    (void)sage_assign_slot(&sage_local_line_225, "line", SAGE_ADD(sage_load_slot(&sage_local_line_225, "line"), sage_load_slot(&sage_local_val_227, "val")));
            }
        }
    }
    if (sage_truthy(SAGE_EQ(sage_upper(sage_strip_fn(sage_load_slot(&sage_local_line_225, "line"))), sage_string("OFF")))) {
        (void)({SageValue _obj = sage_index(sage_load_slot(&sage_local_self_223, "self"), sage_string("ctx")); SageValue _val = sage_bool(0); sage_dict_set(_obj.as.dict, "echo_on", _val); _val;});
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    if (sage_truthy(SAGE_EQ(sage_upper(sage_strip_fn(sage_load_slot(&sage_local_line_225, "line"))), sage_string("ON")))) {
        (void)({SageValue _obj = sage_index(sage_load_slot(&sage_local_self_223, "self"), sage_string("ctx")); SageValue _val = sage_bool(1); sage_dict_set(_obj.as.dict, "echo_on", _val); _val;});
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    sage_print_ln(sage_load_slot(&sage_local_line_225, "line"));
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_rem(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_231 = sage_slot_undefined();
    SageSlot sage_local_self_230 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_231, &sage_local_self_230};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_230, _self);
    sage_define_slot(&sage_local_args_231, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_set(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_k_234 = sage_slot_undefined();
    SageSlot sage_local_args_233 = sage_slot_undefined();
    SageSlot sage_local_self_232 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_k_234, &sage_local_args_233, &sage_local_self_232};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_232, _self);
    sage_define_slot(&sage_local_args_233, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_233, "args")), sage_number(0)))) {
        {
            SageValue sage_iter_k_235 = sage_dict_keys_fn(sage_index(sage_index(sage_index(sage_load_slot(&sage_local_self_232, "self"), sage_string("ctx")), sage_string("env")), sage_string("vars")));
            if (sage_iter_k_235.type == SAGE_TAG_ARRAY) {
                for (int sage_idx_k_236 = 0; sage_idx_k_236 < sage_iter_k_235.as.array->count; sage_idx_k_236++) {
                    sage_define_slot(&sage_local_k_234, sage_iter_k_235.as.array->elements[sage_idx_k_236]);
                        sage_print_ln(SAGE_ADD(SAGE_ADD(sage_load_slot(&sage_local_k_234, "k"), sage_string("=")), sage_index(sage_index(sage_index(sage_index(sage_load_slot(&sage_local_self_232, "self"), sage_string("ctx")), sage_string("env")), sage_string("vars")), sage_load_slot(&sage_local_k_234, "k"))));
                }
            } else if (sage_iter_k_235.type == SAGE_TAG_STRING) {
                int _len = (int)strlen(sage_iter_k_235.as.string);
                for (int sage_idx_k_236 = 0; sage_idx_k_236 < _len; sage_idx_k_236++) {
                    char _ch[2] = {sage_iter_k_235.as.string[sage_idx_k_236], '\0'};
                    sage_define_slot(&sage_local_k_234, sage_string(_ch));
                        sage_print_ln(SAGE_ADD(SAGE_ADD(sage_load_slot(&sage_local_k_234, "k"), sage_string("=")), sage_index(sage_index(sage_index(sage_index(sage_load_slot(&sage_local_self_232, "self"), sage_string("ctx")), sage_string("env")), sage_string("vars")), sage_load_slot(&sage_local_k_234, "k"))));
                }
            }
        }
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_pause(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_238 = sage_slot_undefined();
    SageSlot sage_local_self_237 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_238, &sage_local_self_237};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_237, _self);
    sage_define_slot(&sage_local_args_238, _argv[0]);
    (void)_argc;
    sage_print_ln(sage_string("Press any key to continue . . ."));
    (void)sage_input_fn(sage_nil());
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_cls(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_240 = sage_slot_undefined();
    SageSlot sage_local_self_239 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_240, &sage_local_self_239};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_239, _self);
    sage_define_slot(&sage_local_args_240, _argv[0]);
    (void)_argc;
    sage_print_ln(sage_string(""));
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_exit(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_code_243 = sage_slot_undefined();
    SageSlot sage_local_args_242 = sage_slot_undefined();
    SageSlot sage_local_self_241 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_code_243, &sage_local_args_242, &sage_local_self_241};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_241, _self);
    sage_define_slot(&sage_local_args_242, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_code_243, sage_number(0));
    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_args_242, "args")), sage_number(0)))) {
        (void)sage_assign_slot(&sage_local_code_243, "code", sage_tonumber(sage_call_method(sage_index(sage_load_slot(&sage_local_self_241, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_242, "args"), sage_number(0))})));
    }
    (void)sage_call_method(sage_load_slot(&sage_global_sys_17, "sys"), "exit", 1, (SageValue[]){sage_load_slot(&sage_local_code_243, "code")});
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_cd(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_247 = sage_slot_undefined();
    SageSlot sage_local_path_246 = sage_slot_undefined();
    SageSlot sage_local_args_245 = sage_slot_undefined();
    SageSlot sage_local_self_244 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_e_247, &sage_local_path_246, &sage_local_args_245, &sage_local_self_244};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_244, _self);
    sage_define_slot(&sage_local_args_245, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_245, "args")), sage_number(0)))) {
        sage_print_ln(sage_index(sage_index(sage_index(sage_load_slot(&sage_local_self_244, "self"), sage_string("ctx")), sage_string("env")), sage_string("cwd")));
        return sage_gc_return(&sage_gc_frame, sage_number(0));
    }
    sage_define_slot(&sage_local_path_246, sage_call_method(sage_index(sage_load_slot(&sage_local_self_244, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_245, "args"), sage_number(0))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_244, "self"), sage_string("ctx")), sage_string("env")), "chdir", 1, (SageValue[]){sage_load_slot(&sage_local_path_246, "path")});
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_247, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(sage_load_slot(&sage_local_e_247, "e"));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_md(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_251 = sage_slot_undefined();
    SageSlot sage_local_path_250 = sage_slot_undefined();
    SageSlot sage_local_args_249 = sage_slot_undefined();
    SageSlot sage_local_self_248 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_e_251, &sage_local_path_250, &sage_local_args_249, &sage_local_self_248};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_248, _self);
    sage_define_slot(&sage_local_args_249, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_249, "args")), sage_number(0)))) {
        sage_print_ln(sage_string("MD: Missing directory name"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    sage_define_slot(&sage_local_path_250, sage_call_method(sage_index(sage_load_slot(&sage_local_self_248, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_249, "args"), sage_number(0))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_248, "self"), sage_string("ctx")), sage_string("fs")), "make_dir", 1, (SageValue[]){sage_load_slot(&sage_local_path_250, "path")});
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_251, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(sage_load_slot(&sage_local_e_251, "e"));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_rd(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_255 = sage_slot_undefined();
    SageSlot sage_local_path_254 = sage_slot_undefined();
    SageSlot sage_local_args_253 = sage_slot_undefined();
    SageSlot sage_local_self_252 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_e_255, &sage_local_path_254, &sage_local_args_253, &sage_local_self_252};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_252, _self);
    sage_define_slot(&sage_local_args_253, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_253, "args")), sage_number(0)))) {
        sage_print_ln(sage_string("RD: Missing directory name"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    sage_define_slot(&sage_local_path_254, sage_call_method(sage_index(sage_load_slot(&sage_local_self_252, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_253, "args"), sage_number(0))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_252, "self"), sage_string("ctx")), sage_string("fs")), "remove_dir", 1, (SageValue[]){sage_load_slot(&sage_local_path_254, "path")});
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_255, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(sage_load_slot(&sage_local_e_255, "e"));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_dir(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_entry_260 = sage_slot_undefined();
    SageSlot sage_local_entries_259 = sage_slot_undefined();
    SageSlot sage_local_path_258 = sage_slot_undefined();
    SageSlot sage_local_args_257 = sage_slot_undefined();
    SageSlot sage_local_self_256 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_entry_260, &sage_local_entries_259, &sage_local_path_258, &sage_local_args_257, &sage_local_self_256};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_256, _self);
    sage_define_slot(&sage_local_args_257, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_path_258, sage_index(sage_index(sage_index(sage_load_slot(&sage_local_self_256, "self"), sage_string("ctx")), sage_string("env")), sage_string("cwd")));
    if (sage_truthy(SAGE_GT(sage_len(sage_load_slot(&sage_local_args_257, "args")), sage_number(0)))) {
        (void)sage_assign_slot(&sage_local_path_258, "path", sage_call_method(sage_index(sage_load_slot(&sage_local_self_256, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_257, "args"), sage_number(0))}));
    }
    sage_define_slot(&sage_local_entries_259, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_256, "self"), sage_string("ctx")), sage_string("fs")), "list_dir", 1, (SageValue[]){sage_load_slot(&sage_local_path_258, "path")}));
    sage_print_ln(SAGE_ADD(sage_string(" Directory of "), sage_load_slot(&sage_local_path_258, "path")));
    sage_print_ln(sage_string(""));
    {
        SageValue sage_iter_entry_261 = sage_load_slot(&sage_local_entries_259, "entries");
        if (sage_iter_entry_261.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_entry_262 = 0; sage_idx_entry_262 < sage_iter_entry_261.as.array->count; sage_idx_entry_262++) {
                sage_define_slot(&sage_local_entry_260, sage_iter_entry_261.as.array->elements[sage_idx_entry_262]);
                    sage_print_ln(sage_load_slot(&sage_local_entry_260, "entry"));
            }
        } else if (sage_iter_entry_261.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_entry_261.as.string);
            for (int sage_idx_entry_262 = 0; sage_idx_entry_262 < _len; sage_idx_entry_262++) {
                char _ch[2] = {sage_iter_entry_261.as.string[sage_idx_entry_262], '\0'};
                sage_define_slot(&sage_local_entry_260, sage_string(_ch));
                    sage_print_ln(sage_load_slot(&sage_local_entry_260, "entry"));
            }
        }
    }
    sage_print_ln(SAGE_ADD(sage_str(sage_len(sage_load_slot(&sage_local_entries_259, "entries"))), sage_string(" file(s)")));
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_type(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_267 = sage_slot_undefined();
    SageSlot sage_local_content_266 = sage_slot_undefined();
    SageSlot sage_local_path_265 = sage_slot_undefined();
    SageSlot sage_local_args_264 = sage_slot_undefined();
    SageSlot sage_local_self_263 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_e_267, &sage_local_content_266, &sage_local_path_265, &sage_local_args_264, &sage_local_self_263};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_263, _self);
    sage_define_slot(&sage_local_args_264, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_264, "args")), sage_number(0)))) {
        sage_print_ln(sage_string("TYPE: Missing filename"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    sage_define_slot(&sage_local_path_265, sage_call_method(sage_index(sage_load_slot(&sage_local_self_263, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_264, "args"), sage_number(0))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            sage_define_slot(&sage_local_content_266, sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_263, "self"), sage_string("ctx")), sage_string("fs")), "read_file", 1, (SageValue[]){sage_load_slot(&sage_local_path_265, "path")}));
            sage_print_ln(sage_load_slot(&sage_local_content_266, "content"));
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_267, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(SAGE_ADD(sage_string("TYPE: "), sage_load_slot(&sage_local_e_267, "e")));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_copy(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_272 = sage_slot_undefined();
    SageSlot sage_local_dst_271 = sage_slot_undefined();
    SageSlot sage_local_src_270 = sage_slot_undefined();
    SageSlot sage_local_args_269 = sage_slot_undefined();
    SageSlot sage_local_self_268 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_e_272, &sage_local_dst_271, &sage_local_src_270, &sage_local_args_269, &sage_local_self_268};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_268, _self);
    sage_define_slot(&sage_local_args_269, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_LT(sage_len(sage_load_slot(&sage_local_args_269, "args")), sage_number(2)))) {
        sage_print_ln(sage_string("COPY: Syntax error"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    sage_define_slot(&sage_local_src_270, sage_call_method(sage_index(sage_load_slot(&sage_local_self_268, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_269, "args"), sage_number(0))}));
    sage_define_slot(&sage_local_dst_271, sage_call_method(sage_index(sage_load_slot(&sage_local_self_268, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_269, "args"), sage_number(1))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_268, "self"), sage_string("ctx")), sage_string("fs")), "copy_file", 2, (SageValue[]){sage_load_slot(&sage_local_src_270, "src"), sage_load_slot(&sage_local_dst_271, "dst")});
            sage_print_ln(sage_string("        1 file(s) copied."));
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_272, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(SAGE_ADD(sage_string("COPY: "), sage_load_slot(&sage_local_e_272, "e")));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_move(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_277 = sage_slot_undefined();
    SageSlot sage_local_dst_276 = sage_slot_undefined();
    SageSlot sage_local_src_275 = sage_slot_undefined();
    SageSlot sage_local_args_274 = sage_slot_undefined();
    SageSlot sage_local_self_273 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_e_277, &sage_local_dst_276, &sage_local_src_275, &sage_local_args_274, &sage_local_self_273};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_273, _self);
    sage_define_slot(&sage_local_args_274, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_LT(sage_len(sage_load_slot(&sage_local_args_274, "args")), sage_number(2)))) {
        sage_print_ln(sage_string("MOVE: Syntax error"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    sage_define_slot(&sage_local_src_275, sage_call_method(sage_index(sage_load_slot(&sage_local_self_273, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_274, "args"), sage_number(0))}));
    sage_define_slot(&sage_local_dst_276, sage_call_method(sage_index(sage_load_slot(&sage_local_self_273, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_274, "args"), sage_number(1))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_273, "self"), sage_string("ctx")), sage_string("fs")), "move_file", 2, (SageValue[]){sage_load_slot(&sage_local_src_275, "src"), sage_load_slot(&sage_local_dst_276, "dst")});
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_277, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(SAGE_ADD(sage_string("MOVE: "), sage_load_slot(&sage_local_e_277, "e")));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_del(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_282 = sage_slot_undefined();
    SageSlot sage_local_path_281 = sage_slot_undefined();
    SageSlot sage_local_arg_280 = sage_slot_undefined();
    SageSlot sage_local_args_279 = sage_slot_undefined();
    SageSlot sage_local_self_278 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_e_282, &sage_local_path_281, &sage_local_arg_280, &sage_local_args_279, &sage_local_self_278};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_278, _self);
    sage_define_slot(&sage_local_args_279, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_args_279, "args")), sage_number(0)))) {
        sage_print_ln(sage_string("DEL: Missing filename"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    {
        SageValue sage_iter_arg_283 = sage_load_slot(&sage_local_args_279, "args");
        if (sage_iter_arg_283.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_arg_284 = 0; sage_idx_arg_284 < sage_iter_arg_283.as.array->count; sage_idx_arg_284++) {
                sage_define_slot(&sage_local_arg_280, sage_iter_arg_283.as.array->elements[sage_idx_arg_284]);
                    sage_define_slot(&sage_local_path_281, sage_call_method(sage_index(sage_load_slot(&sage_local_self_278, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_arg_280, "arg")}));
                    {
                        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
                        int _caught = 0;
                        sage_try_depth++;
                        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
                            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_278, "self"), sage_string("ctx")), sage_string("fs")), "delete_file", 1, (SageValue[]){sage_load_slot(&sage_local_path_281, "path")});
                        } else {
                            _caught = 1;
                            sage_define_slot(&sage_local_e_282, sage_exception_value);
                        }
                        sage_try_depth--;
                        if (_caught) {
                            sage_print_ln(SAGE_ADD(sage_string("DEL: "), sage_load_slot(&sage_local_e_282, "e")));
                            return sage_gc_return(&sage_gc_frame, sage_number(1));
                        }
                    }
            }
        } else if (sage_iter_arg_283.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_arg_283.as.string);
            for (int sage_idx_arg_284 = 0; sage_idx_arg_284 < _len; sage_idx_arg_284++) {
                char _ch[2] = {sage_iter_arg_283.as.string[sage_idx_arg_284], '\0'};
                sage_define_slot(&sage_local_arg_280, sage_string(_ch));
                    sage_define_slot(&sage_local_path_281, sage_call_method(sage_index(sage_load_slot(&sage_local_self_278, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_load_slot(&sage_local_arg_280, "arg")}));
                    {
                        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
                        int _caught = 0;
                        sage_try_depth++;
                        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
                            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_278, "self"), sage_string("ctx")), sage_string("fs")), "delete_file", 1, (SageValue[]){sage_load_slot(&sage_local_path_281, "path")});
                        } else {
                            _caught = 1;
                            sage_define_slot(&sage_local_e_282, sage_exception_value);
                        }
                        sage_try_depth--;
                        if (_caught) {
                            sage_print_ln(SAGE_ADD(sage_string("DEL: "), sage_load_slot(&sage_local_e_282, "e")));
                            return sage_gc_return(&sage_gc_frame, sage_number(1));
                        }
                    }
            }
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_ren(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_e_289 = sage_slot_undefined();
    SageSlot sage_local_dst_288 = sage_slot_undefined();
    SageSlot sage_local_src_287 = sage_slot_undefined();
    SageSlot sage_local_args_286 = sage_slot_undefined();
    SageSlot sage_local_self_285 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_e_289, &sage_local_dst_288, &sage_local_src_287, &sage_local_args_286, &sage_local_self_285};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_285, _self);
    sage_define_slot(&sage_local_args_286, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_LT(sage_len(sage_load_slot(&sage_local_args_286, "args")), sage_number(2)))) {
        sage_print_ln(sage_string("REN: Syntax error"));
        return sage_gc_return(&sage_gc_frame, sage_number(1));
    }
    sage_define_slot(&sage_local_src_287, sage_call_method(sage_index(sage_load_slot(&sage_local_self_285, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_286, "args"), sage_number(0))}));
    sage_define_slot(&sage_local_dst_288, sage_call_method(sage_index(sage_load_slot(&sage_local_self_285, "self"), sage_string("ctx")), "expand_token", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_args_286, "args"), sage_number(1))}));
    {
        if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
        int _caught = 0;
        sage_try_depth++;
        if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
            (void)sage_call_method(sage_index(sage_index(sage_load_slot(&sage_local_self_285, "self"), sage_string("ctx")), sage_string("fs")), "rename_file", 2, (SageValue[]){sage_load_slot(&sage_local_src_287, "src"), sage_load_slot(&sage_local_dst_288, "dst")});
            return sage_gc_return(&sage_gc_frame, sage_number(0));
        } else {
            _caught = 1;
            sage_define_slot(&sage_local_e_289, sage_exception_value);
        }
        sage_try_depth--;
        if (_caught) {
            sage_print_ln(SAGE_ADD(sage_string("REN: "), sage_load_slot(&sage_local_e_289, "e")));
            return sage_gc_return(&sage_gc_frame, sage_number(1));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_shift(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_291 = sage_slot_undefined();
    SageSlot sage_local_self_290 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_291, &sage_local_self_290};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_290, _self);
    sage_define_slot(&sage_local_args_291, _argv[0]);
    (void)_argc;
    (void)sage_call_method(sage_index(sage_load_slot(&sage_local_self_290, "self"), sage_string("ctx")), "shift_args", 0, NULL);
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_ver(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_293 = sage_slot_undefined();
    SageSlot sage_local_self_292 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_293, &sage_local_self_292};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_292, _self);
    sage_define_slot(&sage_local_args_293, _argv[0]);
    (void)_argc;
    sage_print_ln(sage_string("MS-DOS Batch 4.0 (SageBatch v1.0.0)"));
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_InternalCommands_cmd_help(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_295 = sage_slot_undefined();
    SageSlot sage_local_self_294 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_295, &sage_local_self_294};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_294, _self);
    sage_define_slot(&sage_local_args_295, _argv[0]);
    (void)_argc;
    sage_print_ln(sage_string("SageBatch internal commands:"));
    sage_print_ln(sage_string("  ECHO SET REM PAUSE CLS EXIT CD MD RD DIR TYPE COPY MOVE DEL REN SHIFT VER"));
    sage_print_ln(sage_string("  IF FOR GOTO CALL"));
    return sage_gc_return(&sage_gc_frame, sage_number(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_BlockNode_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_298 = sage_slot_undefined();
    SageSlot sage_local_statements_297 = sage_slot_undefined();
    SageSlot sage_local_self_296 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_line_298, &sage_local_statements_297, &sage_local_self_296};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_296, _self);
    sage_define_slot(&sage_local_statements_297, _argv[0]);
    sage_define_slot(&sage_local_line_298, _argv[1]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_296, "self"); SageValue _val = sage_string("BlockNode"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_296, "self"); SageValue _val = sage_load_slot(&sage_local_statements_297, "statements"); sage_dict_set(_obj.as.dict, "statements", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_296, "self"); SageValue _val = sage_load_slot(&sage_local_line_298, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_PipeNode_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_302 = sage_slot_undefined();
    SageSlot sage_local_right_301 = sage_slot_undefined();
    SageSlot sage_local_left_300 = sage_slot_undefined();
    SageSlot sage_local_self_299 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_line_302, &sage_local_right_301, &sage_local_left_300, &sage_local_self_299};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_299, _self);
    sage_define_slot(&sage_local_left_300, _argv[0]);
    sage_define_slot(&sage_local_right_301, _argv[1]);
    sage_define_slot(&sage_local_line_302, _argv[2]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_299, "self"); SageValue _val = sage_string("PipeNode"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_299, "self"); SageValue _val = sage_load_slot(&sage_local_left_300, "left"); sage_dict_set(_obj.as.dict, "left", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_299, "self"); SageValue _val = sage_load_slot(&sage_local_right_301, "right"); sage_dict_set(_obj.as.dict, "right", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_299, "self"); SageValue _val = sage_load_slot(&sage_local_line_302, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_RedirectNode_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_307 = sage_slot_undefined();
    SageSlot sage_local_filename_306 = sage_slot_undefined();
    SageSlot sage_local_op_305 = sage_slot_undefined();
    SageSlot sage_local_inner_304 = sage_slot_undefined();
    SageSlot sage_local_self_303 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_line_307, &sage_local_filename_306, &sage_local_op_305, &sage_local_inner_304, &sage_local_self_303};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_303, _self);
    sage_define_slot(&sage_local_inner_304, _argv[0]);
    sage_define_slot(&sage_local_op_305, _argv[1]);
    sage_define_slot(&sage_local_filename_306, _argv[2]);
    sage_define_slot(&sage_local_line_307, _argv[3]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_303, "self"); SageValue _val = sage_string("RedirectNode"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_303, "self"); SageValue _val = sage_load_slot(&sage_local_inner_304, "inner"); sage_dict_set(_obj.as.dict, "inner", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_303, "self"); SageValue _val = sage_load_slot(&sage_local_op_305, "op"); sage_dict_set(_obj.as.dict, "op", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_303, "self"); SageValue _val = sage_load_slot(&sage_local_filename_306, "filename"); sage_dict_set(_obj.as.dict, "filename", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_303, "self"); SageValue _val = sage_load_slot(&sage_local_line_307, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CallNode_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_312 = sage_slot_undefined();
    SageSlot sage_local_is_subroutine_311 = sage_slot_undefined();
    SageSlot sage_local_args_310 = sage_slot_undefined();
    SageSlot sage_local_target_309 = sage_slot_undefined();
    SageSlot sage_local_self_308 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_line_312, &sage_local_is_subroutine_311, &sage_local_args_310, &sage_local_target_309, &sage_local_self_308};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_308, _self);
    sage_define_slot(&sage_local_target_309, _argv[0]);
    sage_define_slot(&sage_local_args_310, _argv[1]);
    sage_define_slot(&sage_local_is_subroutine_311, _argv[2]);
    sage_define_slot(&sage_local_line_312, _argv[3]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_308, "self"); SageValue _val = sage_string("CallNode"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_308, "self"); SageValue _val = sage_load_slot(&sage_local_target_309, "target"); sage_dict_set(_obj.as.dict, "target", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_308, "self"); SageValue _val = sage_load_slot(&sage_local_args_310, "args"); sage_dict_set(_obj.as.dict, "args", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_308, "self"); SageValue _val = sage_load_slot(&sage_local_is_subroutine_311, "is_subroutine"); sage_dict_set(_obj.as.dict, "is_subroutine", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_308, "self"); SageValue _val = sage_load_slot(&sage_local_line_312, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_GotoNode_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_315 = sage_slot_undefined();
    SageSlot sage_local_target_314 = sage_slot_undefined();
    SageSlot sage_local_self_313 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_line_315, &sage_local_target_314, &sage_local_self_313};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_313, _self);
    sage_define_slot(&sage_local_target_314, _argv[0]);
    sage_define_slot(&sage_local_line_315, _argv[1]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_313, "self"); SageValue _val = sage_string("GotoNode"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_313, "self"); SageValue _val = sage_load_slot(&sage_local_target_314, "target"); sage_dict_set(_obj.as.dict, "target", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_313, "self"); SageValue _val = sage_load_slot(&sage_local_line_315, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_LabelNode_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_318 = sage_slot_undefined();
    SageSlot sage_local_name_317 = sage_slot_undefined();
    SageSlot sage_local_self_316 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_line_318, &sage_local_name_317, &sage_local_self_316};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_316, _self);
    sage_define_slot(&sage_local_name_317, _argv[0]);
    sage_define_slot(&sage_local_line_318, _argv[1]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_316, "self"); SageValue _val = sage_string("LabelNode"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_316, "self"); SageValue _val = sage_load_slot(&sage_local_name_317, "name"); sage_dict_set(_obj.as.dict, "name", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_316, "self"); SageValue _val = sage_load_slot(&sage_local_line_318, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_ForStatement_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_324 = sage_slot_undefined();
    SageSlot sage_local_flags_323 = sage_slot_undefined();
    SageSlot sage_local_body_322 = sage_slot_undefined();
    SageSlot sage_local_in_list_321 = sage_slot_undefined();
    SageSlot sage_local_var_name_320 = sage_slot_undefined();
    SageSlot sage_local_self_319 = sage_slot_undefined();
    SageSlot* sage_gc_roots[6] = {&sage_local_line_324, &sage_local_flags_323, &sage_local_body_322, &sage_local_in_list_321, &sage_local_var_name_320, &sage_local_self_319};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 6);
    sage_define_slot(&sage_local_self_319, _self);
    sage_define_slot(&sage_local_var_name_320, _argv[0]);
    sage_define_slot(&sage_local_in_list_321, _argv[1]);
    sage_define_slot(&sage_local_body_322, _argv[2]);
    sage_define_slot(&sage_local_flags_323, _argv[3]);
    sage_define_slot(&sage_local_line_324, _argv[4]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_319, "self"); SageValue _val = sage_string("ForStatement"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_319, "self"); SageValue _val = sage_load_slot(&sage_local_var_name_320, "var_name"); sage_dict_set(_obj.as.dict, "var_name", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_319, "self"); SageValue _val = sage_load_slot(&sage_local_in_list_321, "in_list"); sage_dict_set(_obj.as.dict, "in_list", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_319, "self"); SageValue _val = sage_load_slot(&sage_local_body_322, "body"); sage_dict_set(_obj.as.dict, "body", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_319, "self"); SageValue _val = sage_load_slot(&sage_local_flags_323, "flags"); sage_dict_set(_obj.as.dict, "flags", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_319, "self"); SageValue _val = sage_load_slot(&sage_local_line_324, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_IfStatement_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_330 = sage_slot_undefined();
    SageSlot sage_local_alternate_329 = sage_slot_undefined();
    SageSlot sage_local_consequent_328 = sage_slot_undefined();
    SageSlot sage_local_condition_327 = sage_slot_undefined();
    SageSlot sage_local_negated_326 = sage_slot_undefined();
    SageSlot sage_local_self_325 = sage_slot_undefined();
    SageSlot* sage_gc_roots[6] = {&sage_local_line_330, &sage_local_alternate_329, &sage_local_consequent_328, &sage_local_condition_327, &sage_local_negated_326, &sage_local_self_325};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 6);
    sage_define_slot(&sage_local_self_325, _self);
    sage_define_slot(&sage_local_negated_326, _argv[0]);
    sage_define_slot(&sage_local_condition_327, _argv[1]);
    sage_define_slot(&sage_local_consequent_328, _argv[2]);
    sage_define_slot(&sage_local_alternate_329, _argv[3]);
    sage_define_slot(&sage_local_line_330, _argv[4]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_325, "self"); SageValue _val = sage_string("IfStatement"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_325, "self"); SageValue _val = sage_load_slot(&sage_local_negated_326, "negated"); sage_dict_set(_obj.as.dict, "negated", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_325, "self"); SageValue _val = sage_load_slot(&sage_local_condition_327, "condition"); sage_dict_set(_obj.as.dict, "condition", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_325, "self"); SageValue _val = sage_load_slot(&sage_local_consequent_328, "consequent"); sage_dict_set(_obj.as.dict, "consequent", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_325, "self"); SageValue _val = sage_load_slot(&sage_local_alternate_329, "alternate"); sage_dict_set(_obj.as.dict, "alternate", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_325, "self"); SageValue _val = sage_load_slot(&sage_local_line_330, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Assignment_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_334 = sage_slot_undefined();
    SageSlot sage_local_value_333 = sage_slot_undefined();
    SageSlot sage_local_name_332 = sage_slot_undefined();
    SageSlot sage_local_self_331 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_line_334, &sage_local_value_333, &sage_local_name_332, &sage_local_self_331};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_331, _self);
    sage_define_slot(&sage_local_name_332, _argv[0]);
    sage_define_slot(&sage_local_value_333, _argv[1]);
    sage_define_slot(&sage_local_line_334, _argv[2]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_331, "self"); SageValue _val = sage_string("Assignment"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_331, "self"); SageValue _val = sage_load_slot(&sage_local_name_332, "name"); sage_dict_set(_obj.as.dict, "name", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_331, "self"); SageValue _val = sage_load_slot(&sage_local_value_333, "value"); sage_dict_set(_obj.as.dict, "value", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_331, "self"); SageValue _val = sage_load_slot(&sage_local_line_334, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Command_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_339 = sage_slot_undefined();
    SageSlot sage_local_suppress_338 = sage_slot_undefined();
    SageSlot sage_local_args_337 = sage_slot_undefined();
    SageSlot sage_local_name_336 = sage_slot_undefined();
    SageSlot sage_local_self_335 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_line_339, &sage_local_suppress_338, &sage_local_args_337, &sage_local_name_336, &sage_local_self_335};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_335, _self);
    sage_define_slot(&sage_local_name_336, _argv[0]);
    sage_define_slot(&sage_local_args_337, _argv[1]);
    sage_define_slot(&sage_local_suppress_338, _argv[2]);
    sage_define_slot(&sage_local_line_339, _argv[3]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_335, "self"); SageValue _val = sage_string("Command"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_335, "self"); SageValue _val = sage_load_slot(&sage_local_name_336, "name"); sage_dict_set(_obj.as.dict, "name", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_335, "self"); SageValue _val = sage_load_slot(&sage_local_args_337, "args"); sage_dict_set(_obj.as.dict, "args", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_335, "self"); SageValue _val = sage_load_slot(&sage_local_suppress_338, "suppress"); sage_dict_set(_obj.as.dict, "suppress", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_335, "self"); SageValue _val = sage_load_slot(&sage_local_line_339, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Program_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_statements_341 = sage_slot_undefined();
    SageSlot sage_local_self_340 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_statements_341, &sage_local_self_340};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_340, _self);
    sage_define_slot(&sage_local_statements_341, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_340, "self"); SageValue _val = sage_string("Program"); sage_dict_set(_obj.as.dict, "type", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_340, "self"); SageValue _val = sage_load_slot(&sage_local_statements_341, "statements"); sage_dict_set(_obj.as.dict, "statements", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_BatchProcess_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_arg_346 = sage_slot_undefined();
    SageSlot sage_local_i_345 = sage_slot_undefined();
    SageSlot sage_local_batch_args_344 = sage_slot_undefined();
    SageSlot sage_local_script_path_343 = sage_slot_undefined();
    SageSlot sage_local_self_342 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_arg_346, &sage_local_i_345, &sage_local_batch_args_344, &sage_local_script_path_343, &sage_local_self_342};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_342, _self);
    sage_define_slot(&sage_local_script_path_343, _argv[0]);
    sage_define_slot(&sage_local_batch_args_344, _argv[1]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_342, "self"); SageValue _val = sage_load_slot(&sage_local_script_path_343, "script_path"); sage_dict_set(_obj.as.dict, "script_path", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_342, "self"); SageValue _val = sage_construct("Environment", NULL, 0, NULL); sage_dict_set(_obj.as.dict, "env", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_342, "self"); SageValue _val = sage_construct("VarStore", NULL, 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_342, "self"), sage_string("env"))}); sage_dict_set(_obj.as.dict, "varstore", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_342, "self"); SageValue _val = sage_construct("FileSystem", NULL, 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_342, "self"), sage_string("env"))}); sage_dict_set(_obj.as.dict, "fs", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_342, "self"); SageValue _val = sage_make_array(0, NULL); sage_dict_set(_obj.as.dict, "call_stack", _val); _val;});
    (void)sage_call_method(sage_index(sage_load_slot(&sage_local_self_342, "self"), sage_string("env")), "set_var", 2, (SageValue[]){sage_string("0"), sage_load_slot(&sage_local_script_path_343, "script_path")});
    sage_define_slot(&sage_local_i_345, sage_number(1));
    {
        SageValue sage_iter_arg_347 = sage_load_slot(&sage_local_batch_args_344, "batch_args");
        if (sage_iter_arg_347.type == SAGE_TAG_ARRAY) {
            for (int sage_idx_arg_348 = 0; sage_idx_arg_348 < sage_iter_arg_347.as.array->count; sage_idx_arg_348++) {
                sage_define_slot(&sage_local_arg_346, sage_iter_arg_347.as.array->elements[sage_idx_arg_348]);
                    (void)sage_call_method(sage_index(sage_load_slot(&sage_local_self_342, "self"), sage_string("env")), "set_var", 2, (SageValue[]){sage_str(sage_load_slot(&sage_local_i_345, "i")), sage_load_slot(&sage_local_arg_346, "arg")});
                    (void)sage_assign_slot(&sage_local_i_345, "i", SAGE_ADD(sage_load_slot(&sage_local_i_345, "i"), sage_number(1)));
            }
        } else if (sage_iter_arg_347.type == SAGE_TAG_STRING) {
            int _len = (int)strlen(sage_iter_arg_347.as.string);
            for (int sage_idx_arg_348 = 0; sage_idx_arg_348 < _len; sage_idx_arg_348++) {
                char _ch[2] = {sage_iter_arg_347.as.string[sage_idx_arg_348], '\0'};
                sage_define_slot(&sage_local_arg_346, sage_string(_ch));
                    (void)sage_call_method(sage_index(sage_load_slot(&sage_local_self_342, "self"), sage_string("env")), "set_var", 2, (SageValue[]){sage_str(sage_load_slot(&sage_local_i_345, "i")), sage_load_slot(&sage_local_arg_346, "arg")});
                    (void)sage_assign_slot(&sage_local_i_345, "i", SAGE_ADD(sage_load_slot(&sage_local_i_345, "i"), sage_number(1)));
            }
        }
    }
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_342, "self"); SageValue _val = sage_load_slot(&sage_local_batch_args_344, "batch_args"); sage_dict_set(_obj.as.dict, "batch_args", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_BatchProcess_make_context(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_args_350 = sage_slot_undefined();
    SageSlot sage_local_self_349 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_args_350, &sage_local_self_349};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_349, _self);
    sage_define_slot(&sage_local_args_350, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_construct("CommandContext", NULL, 4, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_349, "self"), sage_string("env")), sage_index(sage_load_slot(&sage_local_self_349, "self"), sage_string("varstore")), sage_index(sage_load_slot(&sage_local_self_349, "self"), sage_string("fs")), sage_load_slot(&sage_local_args_350, "args")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_BatchProcess_push_call(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_ip_354 = sage_slot_undefined();
    SageSlot sage_local_args_353 = sage_slot_undefined();
    SageSlot sage_local_script_352 = sage_slot_undefined();
    SageSlot sage_local_self_351 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_ip_354, &sage_local_args_353, &sage_local_script_352, &sage_local_self_351};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_351, _self);
    sage_define_slot(&sage_local_script_352, _argv[0]);
    sage_define_slot(&sage_local_args_353, _argv[1]);
    sage_define_slot(&sage_local_ip_354, _argv[2]);
    (void)_argc;
    (void)sage_push(sage_index(sage_load_slot(&sage_local_self_351, "self"), sage_string("call_stack")), sage_make_dict_from_entries(3, (const char*[]){"script", "args", "ip"}, (SageValue[]){sage_load_slot(&sage_local_script_352, "script"), sage_load_slot(&sage_local_args_353, "args"), sage_load_slot(&sage_local_ip_354, "ip")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_BatchProcess_pop_call(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_355 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_355};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_355, _self);
    (void)_argc;
    if (sage_truthy(SAGE_GT(sage_len(sage_index(sage_load_slot(&sage_local_self_355, "self"), sage_string("call_stack"))), sage_number(0)))) {
        return sage_gc_return(&sage_gc_frame, sage_pop(sage_index(sage_load_slot(&sage_local_self_355, "self"), sage_string("call_stack"))));
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandContext_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_batch_args_360 = sage_slot_undefined();
    SageSlot sage_local_fs_359 = sage_slot_undefined();
    SageSlot sage_local_varstore_358 = sage_slot_undefined();
    SageSlot sage_local_env_357 = sage_slot_undefined();
    SageSlot sage_local_self_356 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_batch_args_360, &sage_local_fs_359, &sage_local_varstore_358, &sage_local_env_357, &sage_local_self_356};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_356, _self);
    sage_define_slot(&sage_local_env_357, _argv[0]);
    sage_define_slot(&sage_local_varstore_358, _argv[1]);
    sage_define_slot(&sage_local_fs_359, _argv[2]);
    sage_define_slot(&sage_local_batch_args_360, _argv[3]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_load_slot(&sage_local_env_357, "env"); sage_dict_set(_obj.as.dict, "env", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_load_slot(&sage_local_varstore_358, "varstore"); sage_dict_set(_obj.as.dict, "vars", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_load_slot(&sage_local_fs_359, "fs"); sage_dict_set(_obj.as.dict, "fs", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_load_slot(&sage_local_batch_args_360, "batch_args"); sage_dict_set(_obj.as.dict, "args", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_bool(1); sage_dict_set(_obj.as.dict, "echo_on", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_nil(); sage_dict_set(_obj.as.dict, "stdout", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_356, "self"); SageValue _val = sage_nil(); sage_dict_set(_obj.as.dict, "stderr", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandContext_expand_token(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_tok_362 = sage_slot_undefined();
    SageSlot sage_local_self_361 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_tok_362, &sage_local_self_361};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_361, _self);
    sage_define_slot(&sage_local_tok_362, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_EQ(sage_index(sage_load_slot(&sage_local_tok_362, "tok"), sage_string("kind")), sage_load_slot(&sage_global_TOK_VARIABLE_4, "TOK_VARIABLE")))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_361, "self"), sage_string("vars")), "get", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_tok_362, "tok"), sage_string("value"))}));
    }
    if (sage_truthy(sage_or(SAGE_EQ(sage_index(sage_load_slot(&sage_local_tok_362, "tok"), sage_string("kind")), sage_load_slot(&sage_global_TOK_STRING_3, "TOK_STRING")), SAGE_EQ(sage_index(sage_load_slot(&sage_local_tok_362, "tok"), sage_string("kind")), sage_load_slot(&sage_global_TOK_WORD_2, "TOK_WORD"))))) {
        return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_361, "self"), sage_string("vars")), "expand", 1, (SageValue[]){sage_index(sage_load_slot(&sage_local_tok_362, "tok"), sage_string("value"))}));
    }
    return sage_gc_return(&sage_gc_frame, sage_str(sage_index(sage_load_slot(&sage_local_tok_362, "tok"), sage_string("value"))));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandContext_shift_args(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_363 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_363};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_363, _self);
    (void)_argc;
    if (sage_truthy(SAGE_GT(sage_len(sage_index(sage_load_slot(&sage_local_self_363, "self"), sage_string("args"))), sage_number(0)))) {
        (void)({SageValue _obj = sage_load_slot(&sage_local_self_363, "self"); SageValue _val = sage_slice(sage_index(sage_load_slot(&sage_local_self_363, "self"), sage_string("args")), sage_number(1), sage_len(sage_index(sage_load_slot(&sage_local_self_363, "self"), sage_string("args")))); sage_dict_set(_obj.as.dict, "args", _val); _val;});
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandContext_get_arg(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_n_365 = sage_slot_undefined();
    SageSlot sage_local_self_364 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_n_365, &sage_local_self_364};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_364, _self);
    sage_define_slot(&sage_local_n_365, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_n_365, "n"), sage_len(sage_index(sage_load_slot(&sage_local_self_364, "self"), sage_string("args")))))) {
        return sage_gc_return(&sage_gc_frame, sage_index(sage_index(sage_load_slot(&sage_local_self_364, "self"), sage_string("args")), sage_load_slot(&sage_local_n_365, "n")));
    }
    return sage_gc_return(&sage_gc_frame, sage_string(""));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_CommandContext_write_out(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_text_367 = sage_slot_undefined();
    SageSlot sage_local_self_366 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_text_367, &sage_local_self_366};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_366, _self);
    sage_define_slot(&sage_local_text_367, _argv[0]);
    (void)_argc;
    if (sage_truthy(SAGE_NEQ(sage_index(sage_load_slot(&sage_local_self_366, "self"), sage_string("stdout")), sage_nil()))) {
        (void)sage_call_method(sage_index(sage_load_slot(&sage_local_self_366, "self"), sage_string("fs")), "append_file", 2, (SageValue[]){sage_index(sage_load_slot(&sage_local_self_366, "self"), sage_string("stdout")), SAGE_ADD(sage_load_slot(&sage_local_text_367, "text"), sage_string("\n"))});
    }
    else {
        sage_print_ln(sage_load_slot(&sage_local_text_367, "text"));
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_env_369 = sage_slot_undefined();
    SageSlot sage_local_self_368 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_env_369, &sage_local_self_368};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_368, _self);
    sage_define_slot(&sage_local_env_369, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_368, "self"); SageValue _val = sage_load_slot(&sage_local_env_369, "env"); sage_dict_set(_obj.as.dict, "env", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_normalize(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_371 = sage_slot_undefined();
    SageSlot sage_local_self_370 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_371, &sage_local_self_370};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_370, _self);
    sage_define_slot(&sage_local_path_371, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_replace_fn(sage_load_slot(&sage_local_path_371, "path"), sage_string("\\"), sage_string("/")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_resolve(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_p_374 = sage_slot_undefined();
    SageSlot sage_local_path_373 = sage_slot_undefined();
    SageSlot sage_local_self_372 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_p_374, &sage_local_path_373, &sage_local_self_372};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_372, _self);
    sage_define_slot(&sage_local_path_373, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_p_374, sage_call_method(sage_load_slot(&sage_local_self_372, "self"), "normalize", 1, (SageValue[]){sage_load_slot(&sage_local_path_373, "path")}));
    if (sage_truthy(sage_startswith(sage_load_slot(&sage_local_p_374, "p"), sage_string("/")))) {
        return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_p_374, "p"));
    }
    return sage_gc_return(&sage_gc_frame, SAGE_ADD(SAGE_ADD(sage_index(sage_index(sage_load_slot(&sage_local_self_372, "self"), sage_string("env")), sage_string("cwd")), sage_string("/")), sage_load_slot(&sage_local_p_374, "p")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_exists(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_content_378 = sage_slot_undefined();
    SageSlot sage_local_res_377 = sage_slot_undefined();
    SageSlot sage_local_path_376 = sage_slot_undefined();
    SageSlot sage_local_self_375 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_content_378, &sage_local_res_377, &sage_local_path_376, &sage_local_self_375};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_375, _self);
    sage_define_slot(&sage_local_path_376, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_res_377, sage_call_method(sage_load_slot(&sage_local_self_375, "self"), "resolve", 1, (SageValue[]){sage_load_slot(&sage_local_path_376, "path")}));
    sage_define_slot(&sage_local_content_378, sage_native_io_readfile(sage_load_slot(&sage_local_res_377, "res")));
    return sage_gc_return(&sage_gc_frame, SAGE_NEQ(sage_load_slot(&sage_local_content_378, "content"), sage_nil()));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_is_dir(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_380 = sage_slot_undefined();
    SageSlot sage_local_self_379 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_380, &sage_local_self_379};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_379, _self);
    sage_define_slot(&sage_local_path_380, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_bool(0));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_is_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_382 = sage_slot_undefined();
    SageSlot sage_local_self_381 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_382, &sage_local_self_381};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_381, _self);
    sage_define_slot(&sage_local_path_382, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_call_method(sage_load_slot(&sage_local_self_381, "self"), "exists", 1, (SageValue[]){sage_load_slot(&sage_local_path_382, "path")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_read_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_384 = sage_slot_undefined();
    SageSlot sage_local_self_383 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_384, &sage_local_self_383};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_383, _self);
    sage_define_slot(&sage_local_path_384, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_native_io_readfile(sage_call_method(sage_load_slot(&sage_local_self_383, "self"), "resolve", 1, (SageValue[]){sage_load_slot(&sage_local_path_384, "path")})));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_write_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_content_387 = sage_slot_undefined();
    SageSlot sage_local_path_386 = sage_slot_undefined();
    SageSlot sage_local_self_385 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_content_387, &sage_local_path_386, &sage_local_self_385};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_385, _self);
    sage_define_slot(&sage_local_path_386, _argv[0]);
    sage_define_slot(&sage_local_content_387, _argv[1]);
    (void)_argc;
    (void)sage_native_io_writefile(sage_call_method(sage_load_slot(&sage_local_self_385, "self"), "resolve", 1, (SageValue[]){sage_load_slot(&sage_local_path_386, "path")}), sage_load_slot(&sage_local_content_387, "content"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_append_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_existing_392 = sage_slot_undefined();
    SageSlot sage_local_res_391 = sage_slot_undefined();
    SageSlot sage_local_content_390 = sage_slot_undefined();
    SageSlot sage_local_path_389 = sage_slot_undefined();
    SageSlot sage_local_self_388 = sage_slot_undefined();
    SageSlot* sage_gc_roots[5] = {&sage_local_existing_392, &sage_local_res_391, &sage_local_content_390, &sage_local_path_389, &sage_local_self_388};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 5);
    sage_define_slot(&sage_local_self_388, _self);
    sage_define_slot(&sage_local_path_389, _argv[0]);
    sage_define_slot(&sage_local_content_390, _argv[1]);
    (void)_argc;
    sage_define_slot(&sage_local_res_391, sage_call_method(sage_load_slot(&sage_local_self_388, "self"), "resolve", 1, (SageValue[]){sage_load_slot(&sage_local_path_389, "path")}));
    sage_define_slot(&sage_local_existing_392, sage_native_io_readfile(sage_load_slot(&sage_local_res_391, "res")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_existing_392, "existing"), sage_nil()))) {
        (void)sage_assign_slot(&sage_local_existing_392, "existing", sage_string(""));
    }
    (void)sage_native_io_writefile(sage_load_slot(&sage_local_res_391, "res"), SAGE_ADD(sage_load_slot(&sage_local_existing_392, "existing"), sage_load_slot(&sage_local_content_390, "content")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_delete_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_394 = sage_slot_undefined();
    SageSlot sage_local_self_393 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_394, &sage_local_self_393};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_393, _self);
    sage_define_slot(&sage_local_path_394, _argv[0]);
    (void)_argc;
    (void)sage_native_io_writefile(sage_call_method(sage_load_slot(&sage_local_self_393, "self"), "resolve", 1, (SageValue[]){sage_load_slot(&sage_local_path_394, "path")}), sage_string(""));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_make_dir(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_396 = sage_slot_undefined();
    SageSlot sage_local_self_395 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_396, &sage_local_self_395};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_395, _self);
    sage_define_slot(&sage_local_path_396, _argv[0]);
    (void)_argc;
    sage_raise(sage_string("MKDIR: Not yet implemented in standalone mode"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_remove_dir(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_398 = sage_slot_undefined();
    SageSlot sage_local_self_397 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_398, &sage_local_self_397};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_397, _self);
    sage_define_slot(&sage_local_path_398, _argv[0]);
    (void)_argc;
    sage_raise(sage_string("RMDIR: Not yet implemented in standalone mode"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_list_dir(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_400 = sage_slot_undefined();
    SageSlot sage_local_self_399 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_400, &sage_local_self_399};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_399, _self);
    sage_define_slot(&sage_local_path_400, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_make_array(0, NULL));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_glob(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_pattern_402 = sage_slot_undefined();
    SageSlot sage_local_self_401 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_pattern_402, &sage_local_self_401};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_401, _self);
    sage_define_slot(&sage_local_pattern_402, _argv[0]);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_make_array(1, (SageValue[]){sage_load_slot(&sage_local_pattern_402, "pattern")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_copy_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_content_406 = sage_slot_undefined();
    SageSlot sage_local_dst_405 = sage_slot_undefined();
    SageSlot sage_local_src_404 = sage_slot_undefined();
    SageSlot sage_local_self_403 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_content_406, &sage_local_dst_405, &sage_local_src_404, &sage_local_self_403};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_403, _self);
    sage_define_slot(&sage_local_src_404, _argv[0]);
    sage_define_slot(&sage_local_dst_405, _argv[1]);
    (void)_argc;
    sage_define_slot(&sage_local_content_406, sage_call_method(sage_load_slot(&sage_local_self_403, "self"), "read_file", 1, (SageValue[]){sage_load_slot(&sage_local_src_404, "src")}));
    (void)sage_call_method(sage_load_slot(&sage_local_self_403, "self"), "write_file", 2, (SageValue[]){sage_load_slot(&sage_local_dst_405, "dst"), sage_load_slot(&sage_local_content_406, "content")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_move_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_dst_409 = sage_slot_undefined();
    SageSlot sage_local_src_408 = sage_slot_undefined();
    SageSlot sage_local_self_407 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_dst_409, &sage_local_src_408, &sage_local_self_407};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_407, _self);
    sage_define_slot(&sage_local_src_408, _argv[0]);
    sage_define_slot(&sage_local_dst_409, _argv[1]);
    (void)_argc;
    (void)sage_call_method(sage_load_slot(&sage_local_self_407, "self"), "copy_file", 2, (SageValue[]){sage_load_slot(&sage_local_src_408, "src"), sage_load_slot(&sage_local_dst_409, "dst")});
    (void)sage_call_method(sage_load_slot(&sage_local_self_407, "self"), "delete_file", 1, (SageValue[]){sage_load_slot(&sage_local_src_408, "src")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_FileSystem_rename_file(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_dst_412 = sage_slot_undefined();
    SageSlot sage_local_src_411 = sage_slot_undefined();
    SageSlot sage_local_self_410 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_dst_412, &sage_local_src_411, &sage_local_self_410};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_410, _self);
    sage_define_slot(&sage_local_src_411, _argv[0]);
    sage_define_slot(&sage_local_dst_412, _argv[1]);
    (void)_argc;
    (void)sage_call_method(sage_load_slot(&sage_local_self_410, "self"), "move_file", 2, (SageValue[]){sage_load_slot(&sage_local_src_411, "src"), sage_load_slot(&sage_local_dst_412, "dst")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_env_414 = sage_slot_undefined();
    SageSlot sage_local_self_413 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_env_414, &sage_local_self_413};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_413, _self);
    sage_define_slot(&sage_local_env_414, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_413, "self"); SageValue _val = sage_load_slot(&sage_local_env_414, "env"); sage_dict_set(_obj.as.dict, "env", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_413, "self"); SageValue _val = sage_make_array(1, (SageValue[]){sage_make_dict()}); sage_dict_set(_obj.as.dict, "scopes", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_push_scope(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_415 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_415};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_415, _self);
    (void)_argc;
    (void)sage_push(sage_index(sage_load_slot(&sage_local_self_415, "self"), sage_string("scopes")), sage_make_dict());
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_pop_scope(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_416 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_416};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_416, _self);
    (void)_argc;
    if (sage_truthy(SAGE_GT(sage_len(sage_index(sage_load_slot(&sage_local_self_416, "self"), sage_string("scopes"))), sage_number(1)))) {
        (void)sage_pop(sage_index(sage_load_slot(&sage_local_self_416, "self"), sage_string("scopes")));
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_set_local(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_value_419 = sage_slot_undefined();
    SageSlot sage_local_name_418 = sage_slot_undefined();
    SageSlot sage_local_self_417 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_value_419, &sage_local_name_418, &sage_local_self_417};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_417, _self);
    sage_define_slot(&sage_local_name_418, _argv[0]);
    sage_define_slot(&sage_local_value_419, _argv[1]);
    (void)_argc;
    (void)sage_index_set(sage_index(sage_index(sage_load_slot(&sage_local_self_417, "self"), sage_string("scopes")), SAGE_SUB(sage_len(sage_index(sage_load_slot(&sage_local_self_417, "self"), sage_string("scopes"))), sage_number(1))), sage_upper(sage_load_slot(&sage_local_name_418, "name")), sage_load_slot(&sage_local_value_419, "value"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_get(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_i_422 = sage_slot_undefined();
    SageSlot sage_local_name_421 = sage_slot_undefined();
    SageSlot sage_local_self_420 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_i_422, &sage_local_name_421, &sage_local_self_420};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_420, _self);
    sage_define_slot(&sage_local_name_421, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_i_422, SAGE_SUB(sage_len(sage_index(sage_load_slot(&sage_local_self_420, "self"), sage_string("scopes"))), sage_number(1)));
    while (sage_truthy(SAGE_GTE(sage_load_slot(&sage_local_i_422, "i"), sage_number(0)))) {
        if (sage_truthy(sage_dict_has_fn(sage_index(sage_index(sage_load_slot(&sage_local_self_420, "self"), sage_string("scopes")), sage_load_slot(&sage_local_i_422, "i")), sage_upper(sage_load_slot(&sage_local_name_421, "name"))))) {
            return sage_gc_return(&sage_gc_frame, sage_index(sage_index(sage_index(sage_load_slot(&sage_local_self_420, "self"), sage_string("scopes")), sage_load_slot(&sage_local_i_422, "i")), sage_upper(sage_load_slot(&sage_local_name_421, "name"))));
        }
        (void)sage_assign_slot(&sage_local_i_422, "i", SAGE_SUB(sage_load_slot(&sage_local_i_422, "i"), sage_number(1)));
    }
    return sage_gc_return(&sage_gc_frame, sage_call_method(sage_index(sage_load_slot(&sage_local_self_420, "self"), sage_string("env")), "get_var", 1, (SageValue[]){sage_load_slot(&sage_local_name_421, "name")}));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_set(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_value_425 = sage_slot_undefined();
    SageSlot sage_local_name_424 = sage_slot_undefined();
    SageSlot sage_local_self_423 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_value_425, &sage_local_name_424, &sage_local_self_423};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_423, _self);
    sage_define_slot(&sage_local_name_424, _argv[0]);
    sage_define_slot(&sage_local_value_425, _argv[1]);
    (void)_argc;
    (void)sage_call_method(sage_index(sage_load_slot(&sage_local_self_423, "self"), sage_string("env")), "set_var", 2, (SageValue[]){sage_load_slot(&sage_local_name_424, "name"), sage_load_slot(&sage_local_value_425, "value")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_VarStore_expand(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_vname_432 = sage_slot_undefined();
    SageSlot sage_local_j_431 = sage_slot_undefined();
    SageSlot sage_local_ch_430 = sage_slot_undefined();
    SageSlot sage_local_i_429 = sage_slot_undefined();
    SageSlot sage_local_result_428 = sage_slot_undefined();
    SageSlot sage_local_text_427 = sage_slot_undefined();
    SageSlot sage_local_self_426 = sage_slot_undefined();
    SageSlot* sage_gc_roots[7] = {&sage_local_vname_432, &sage_local_j_431, &sage_local_ch_430, &sage_local_i_429, &sage_local_result_428, &sage_local_text_427, &sage_local_self_426};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 7);
    sage_define_slot(&sage_local_self_426, _self);
    sage_define_slot(&sage_local_text_427, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_result_428, sage_string(""));
    sage_define_slot(&sage_local_i_429, sage_number(0));
    while (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_i_429, "i"), sage_len(sage_load_slot(&sage_local_text_427, "text"))))) {
        sage_define_slot(&sage_local_ch_430, sage_index(sage_load_slot(&sage_local_text_427, "text"), sage_load_slot(&sage_local_i_429, "i")));
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_430, "ch"), sage_string("%")))) {
            sage_define_slot(&sage_local_j_431, SAGE_ADD(sage_load_slot(&sage_local_i_429, "i"), sage_number(1)));
            while (sage_truthy(sage_and(SAGE_LT(sage_load_slot(&sage_local_j_431, "j"), sage_len(sage_load_slot(&sage_local_text_427, "text"))), SAGE_NEQ(sage_index(sage_load_slot(&sage_local_text_427, "text"), sage_load_slot(&sage_local_j_431, "j")), sage_string("%"))))) {
                (void)sage_assign_slot(&sage_local_j_431, "j", SAGE_ADD(sage_load_slot(&sage_local_j_431, "j"), sage_number(1)));
            }
            if (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_j_431, "j"), sage_len(sage_load_slot(&sage_local_text_427, "text"))))) {
                sage_define_slot(&sage_local_vname_432, sage_slice(sage_load_slot(&sage_local_text_427, "text"), SAGE_ADD(sage_load_slot(&sage_local_i_429, "i"), sage_number(1)), sage_load_slot(&sage_local_j_431, "j")));
                (void)sage_assign_slot(&sage_local_result_428, "result", SAGE_ADD(sage_load_slot(&sage_local_result_428, "result"), sage_call_method(sage_load_slot(&sage_local_self_426, "self"), "get", 1, (SageValue[]){sage_load_slot(&sage_local_vname_432, "vname")})));
                (void)sage_assign_slot(&sage_local_i_429, "i", SAGE_ADD(sage_load_slot(&sage_local_j_431, "j"), sage_number(1)));
            }
            else {
                (void)sage_assign_slot(&sage_local_result_428, "result", SAGE_ADD(sage_load_slot(&sage_local_result_428, "result"), sage_load_slot(&sage_local_ch_430, "ch")));
                (void)sage_assign_slot(&sage_local_i_429, "i", SAGE_ADD(sage_load_slot(&sage_local_i_429, "i"), sage_number(1)));
            }
        }
        else {
            (void)sage_assign_slot(&sage_local_result_428, "result", SAGE_ADD(sage_load_slot(&sage_local_result_428, "result"), sage_load_slot(&sage_local_ch_430, "ch")));
            (void)sage_assign_slot(&sage_local_i_429, "i", SAGE_ADD(sage_load_slot(&sage_local_i_429, "i"), sage_number(1)));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_result_428, "result"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_433 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_433};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_433, _self);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_433, "self"); SageValue _val = sage_make_dict(); sage_dict_set(_obj.as.dict, "vars", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_433, "self"); SageValue _val = sage_number(0); sage_dict_set(_obj.as.dict, "errorlevel", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_433, "self"); SageValue _val = sage_string("/"); sage_dict_set(_obj.as.dict, "cwd", _val); _val;});
    (void)sage_call_method(sage_load_slot(&sage_local_self_433, "self"), "_init_defaults", 0, NULL);
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment__init_defaults(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_434 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_434};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_434, _self);
    (void)_argc;
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_434, "self"), sage_string("vars")), sage_string("PATH"), sage_native_sys_getenv(sage_string("PATH")));
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_434, "self"), sage_string("vars")), sage_string("TEMP"), sage_native_sys_getenv(sage_string("TEMP")));
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_434, "self"), sage_string("vars")), sage_string("COMSPEC"), sage_string("BATCH.SAGE"));
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_434, "self"), sage_string("vars")), sage_string("PROMPT"), sage_string("$P$G"));
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_434, "self"), sage_string("vars")), sage_string("PATHEXT"), sage_string(".BAT;.SAG;.EXE;.COM"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_set_var(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_value_437 = sage_slot_undefined();
    SageSlot sage_local_name_436 = sage_slot_undefined();
    SageSlot sage_local_self_435 = sage_slot_undefined();
    SageSlot* sage_gc_roots[3] = {&sage_local_value_437, &sage_local_name_436, &sage_local_self_435};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 3);
    sage_define_slot(&sage_local_self_435, _self);
    sage_define_slot(&sage_local_name_436, _argv[0]);
    sage_define_slot(&sage_local_value_437, _argv[1]);
    (void)_argc;
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_435, "self"), sage_string("vars")), sage_upper(sage_load_slot(&sage_local_name_436, "name")), sage_load_slot(&sage_local_value_437, "value"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_get_var(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_name_439 = sage_slot_undefined();
    SageSlot sage_local_self_438 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_name_439, &sage_local_self_438};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_438, _self);
    sage_define_slot(&sage_local_name_439, _argv[0]);
    (void)_argc;
    if (sage_truthy(sage_dict_has_fn(sage_index(sage_load_slot(&sage_local_self_438, "self"), sage_string("vars")), sage_upper(sage_load_slot(&sage_local_name_439, "name"))))) {
        return sage_gc_return(&sage_gc_frame, sage_index(sage_index(sage_load_slot(&sage_local_self_438, "self"), sage_string("vars")), sage_upper(sage_load_slot(&sage_local_name_439, "name"))));
    }
    return sage_gc_return(&sage_gc_frame, sage_string(""));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_del_var(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_name_441 = sage_slot_undefined();
    SageSlot sage_local_self_440 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_name_441, &sage_local_self_440};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_440, _self);
    sage_define_slot(&sage_local_name_441, _argv[0]);
    (void)_argc;
    (void)sage_dict_delete_fn(sage_index(sage_load_slot(&sage_local_self_440, "self"), sage_string("vars")), sage_upper(sage_load_slot(&sage_local_name_441, "name")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_expand(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_vname_448 = sage_slot_undefined();
    SageSlot sage_local_j_447 = sage_slot_undefined();
    SageSlot sage_local_ch_446 = sage_slot_undefined();
    SageSlot sage_local_i_445 = sage_slot_undefined();
    SageSlot sage_local_result_444 = sage_slot_undefined();
    SageSlot sage_local_text_443 = sage_slot_undefined();
    SageSlot sage_local_self_442 = sage_slot_undefined();
    SageSlot* sage_gc_roots[7] = {&sage_local_vname_448, &sage_local_j_447, &sage_local_ch_446, &sage_local_i_445, &sage_local_result_444, &sage_local_text_443, &sage_local_self_442};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 7);
    sage_define_slot(&sage_local_self_442, _self);
    sage_define_slot(&sage_local_text_443, _argv[0]);
    (void)_argc;
    sage_define_slot(&sage_local_result_444, sage_string(""));
    sage_define_slot(&sage_local_i_445, sage_number(0));
    while (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_i_445, "i"), sage_len(sage_load_slot(&sage_local_text_443, "text"))))) {
        sage_define_slot(&sage_local_ch_446, sage_index(sage_load_slot(&sage_local_text_443, "text"), sage_load_slot(&sage_local_i_445, "i")));
        if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_ch_446, "ch"), sage_string("%")))) {
            sage_define_slot(&sage_local_j_447, SAGE_ADD(sage_load_slot(&sage_local_i_445, "i"), sage_number(1)));
            while (sage_truthy(sage_and(SAGE_LT(sage_load_slot(&sage_local_j_447, "j"), sage_len(sage_load_slot(&sage_local_text_443, "text"))), SAGE_NEQ(sage_index(sage_load_slot(&sage_local_text_443, "text"), sage_load_slot(&sage_local_j_447, "j")), sage_string("%"))))) {
                (void)sage_assign_slot(&sage_local_j_447, "j", SAGE_ADD(sage_load_slot(&sage_local_j_447, "j"), sage_number(1)));
            }
            if (sage_truthy(SAGE_LT(sage_load_slot(&sage_local_j_447, "j"), sage_len(sage_load_slot(&sage_local_text_443, "text"))))) {
                sage_define_slot(&sage_local_vname_448, sage_slice(sage_load_slot(&sage_local_text_443, "text"), SAGE_ADD(sage_load_slot(&sage_local_i_445, "i"), sage_number(1)), sage_load_slot(&sage_local_j_447, "j")));
                (void)sage_assign_slot(&sage_local_result_444, "result", SAGE_ADD(sage_load_slot(&sage_local_result_444, "result"), sage_call_method(sage_load_slot(&sage_local_self_442, "self"), "get_var", 1, (SageValue[]){sage_load_slot(&sage_local_vname_448, "vname")})));
                (void)sage_assign_slot(&sage_local_i_445, "i", SAGE_ADD(sage_load_slot(&sage_local_j_447, "j"), sage_number(1)));
            }
            else {
                (void)sage_assign_slot(&sage_local_result_444, "result", SAGE_ADD(sage_load_slot(&sage_local_result_444, "result"), sage_load_slot(&sage_local_ch_446, "ch")));
                (void)sage_assign_slot(&sage_local_i_445, "i", SAGE_ADD(sage_load_slot(&sage_local_i_445, "i"), sage_number(1)));
            }
        }
        else {
            (void)sage_assign_slot(&sage_local_result_444, "result", SAGE_ADD(sage_load_slot(&sage_local_result_444, "result"), sage_load_slot(&sage_local_ch_446, "ch")));
            (void)sage_assign_slot(&sage_local_i_445, "i", SAGE_ADD(sage_load_slot(&sage_local_i_445, "i"), sage_number(1)));
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_result_444, "result"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_set_errorlevel(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_level_450 = sage_slot_undefined();
    SageSlot sage_local_self_449 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_level_450, &sage_local_self_449};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_449, _self);
    sage_define_slot(&sage_local_level_450, _argv[0]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_449, "self"); SageValue _val = sage_load_slot(&sage_local_level_450, "level"); sage_dict_set(_obj.as.dict, "errorlevel", _val); _val;});
    (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_449, "self"), sage_string("vars")), sage_string("ERRORLEVEL"), sage_str(sage_load_slot(&sage_local_level_450, "level")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_get_errorlevel(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_451 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_451};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_451, _self);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, sage_index(sage_load_slot(&sage_local_self_451, "self"), sage_string("errorlevel")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_chdir(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_path_453 = sage_slot_undefined();
    SageSlot sage_local_self_452 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_path_453, &sage_local_self_452};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_452, _self);
    sage_define_slot(&sage_local_path_453, _argv[0]);
    (void)_argc;
    if (sage_truthy(sage_bool(1))) {
        (void)({SageValue _obj = sage_load_slot(&sage_local_self_452, "self"); SageValue _val = sage_load_slot(&sage_local_path_453, "path"); sage_dict_set(_obj.as.dict, "cwd", _val); _val;});
        (void)sage_index_set(sage_index(sage_load_slot(&sage_local_self_452, "self"), sage_string("vars")), sage_string("CD"), sage_load_slot(&sage_local_path_453, "path"));
    }
    else {
        sage_raise(SAGE_ADD(sage_string("CD: Directory not found: "), sage_load_slot(&sage_local_path_453, "path")));
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Environment_render_prompt(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_p_455 = sage_slot_undefined();
    SageSlot sage_local_self_454 = sage_slot_undefined();
    SageSlot* sage_gc_roots[2] = {&sage_local_p_455, &sage_local_self_454};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 2);
    sage_define_slot(&sage_local_self_454, _self);
    (void)_argc;
    sage_define_slot(&sage_local_p_455, sage_call_method(sage_load_slot(&sage_local_self_454, "self"), "get_var", 1, (SageValue[]){sage_string("PROMPT")}));
    sage_define_slot(&sage_local_p_455, sage_replace_fn(sage_load_slot(&sage_local_p_455, "p"), sage_string("$P"), sage_index(sage_load_slot(&sage_local_self_454, "self"), sage_string("cwd"))));
    sage_define_slot(&sage_local_p_455, sage_replace_fn(sage_load_slot(&sage_local_p_455, "p"), sage_string("$G"), sage_string(">")));
    sage_define_slot(&sage_local_p_455, sage_replace_fn(sage_load_slot(&sage_local_p_455, "p"), sage_string("$L"), sage_string("<")));
    sage_define_slot(&sage_local_p_455, sage_replace_fn(sage_load_slot(&sage_local_p_455, "p"), sage_string("$N"), sage_string("C")));
    sage_define_slot(&sage_local_p_455, sage_replace_fn(sage_load_slot(&sage_local_p_455, "p"), sage_string("$Q"), sage_string("=")));
    sage_define_slot(&sage_local_p_455, sage_replace_fn(sage_load_slot(&sage_local_p_455, "p"), sage_string("$$"), sage_string("$")));
    return sage_gc_return(&sage_gc_frame, sage_load_slot(&sage_local_p_455, "p"));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Token_init(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_line_459 = sage_slot_undefined();
    SageSlot sage_local_value_458 = sage_slot_undefined();
    SageSlot sage_local_kind_457 = sage_slot_undefined();
    SageSlot sage_local_self_456 = sage_slot_undefined();
    SageSlot* sage_gc_roots[4] = {&sage_local_line_459, &sage_local_value_458, &sage_local_kind_457, &sage_local_self_456};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 4);
    sage_define_slot(&sage_local_self_456, _self);
    sage_define_slot(&sage_local_kind_457, _argv[0]);
    sage_define_slot(&sage_local_value_458, _argv[1]);
    sage_define_slot(&sage_local_line_459, _argv[2]);
    (void)_argc;
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_456, "self"); SageValue _val = sage_load_slot(&sage_local_kind_457, "kind"); sage_dict_set(_obj.as.dict, "kind", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_456, "self"); SageValue _val = sage_load_slot(&sage_local_value_458, "value"); sage_dict_set(_obj.as.dict, "value", _val); _val;});
    (void)({SageValue _obj = sage_load_slot(&sage_local_self_456, "self"); SageValue _val = sage_load_slot(&sage_local_line_459, "line"); sage_dict_set(_obj.as.dict, "line", _val); _val;});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_method_Token___str__(SageValue _self, int _argc, SageValue* _argv) {
    SageSlot sage_local_self_460 = sage_slot_undefined();
    SageSlot* sage_gc_roots[1] = {&sage_local_self_460};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 1);
    sage_define_slot(&sage_local_self_460, _self);
    (void)_argc;
    return sage_gc_return(&sage_gc_frame, SAGE_ADD(SAGE_ADD(SAGE_ADD(SAGE_ADD(SAGE_ADD(SAGE_ADD(sage_string("Token("), sage_index(sage_load_slot(&sage_local_self_460, "self"), sage_string("kind"))), sage_string(", ")), sage_str(sage_index(sage_load_slot(&sage_local_self_460, "self"), sage_string("value")))), sage_string(", line=")), sage_str(sage_index(sage_load_slot(&sage_local_self_460, "self"), sage_string("line")))), sage_string(")")));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_fn_print_banner_29() {
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, NULL, 0);
    sage_print_ln(sage_string("SageBatch v1.0.0 — MS-DOS Batch 4.0 Clone in Pure SageLang"));
    sage_print_ln(sage_string("Type HELP for a list of commands.  Type EXIT to quit."));
    sage_print_ln(sage_string(""));
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_fn_run_interactive_30(SageValue arg0) {
    SageSlot sage_local_e_469 = sage_slot_undefined();
    SageSlot sage_local_ast_468 = sage_slot_undefined();
    SageSlot sage_local_parser_467 = sage_slot_undefined();
    SageSlot sage_local_tokens_466 = sage_slot_undefined();
    SageSlot sage_local_lexer_465 = sage_slot_undefined();
    SageSlot sage_local_line_464 = sage_slot_undefined();
    SageSlot sage_local_prompt_463 = sage_slot_undefined();
    SageSlot sage_local_interp_462 = sage_slot_undefined();
    SageSlot sage_param_process_461 = sage_slot_undefined();
    SageSlot* sage_gc_roots[9] = {&sage_local_e_469, &sage_local_ast_468, &sage_local_parser_467, &sage_local_tokens_466, &sage_local_lexer_465, &sage_local_line_464, &sage_local_prompt_463, &sage_local_interp_462, &sage_param_process_461};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 9);
    sage_define_slot(&sage_param_process_461, arg0);
    (void)sage_fn_print_banner_29();
    sage_define_slot(&sage_local_interp_462, sage_construct("Interpreter", NULL, 1, (SageValue[]){sage_load_slot(&sage_param_process_461, "process")}));
    while (sage_truthy(sage_bool(1))) {
        sage_define_slot(&sage_local_prompt_463, sage_call_method(sage_index(sage_load_slot(&sage_param_process_461, "process"), sage_string("env")), "render_prompt", 0, NULL));
        sage_define_slot(&sage_local_line_464, sage_input_fn(sage_load_slot(&sage_local_prompt_463, "prompt")));
        sage_define_slot(&sage_local_line_464, sage_strip_fn(sage_load_slot(&sage_local_line_464, "line")));
        if (sage_truthy(SAGE_EQ(sage_len(sage_load_slot(&sage_local_line_464, "line")), sage_number(0)))) {
            continue;
        }
        {
            if (sage_try_depth >= SAGE_MAX_TRY_DEPTH) sage_fail("Runtime Error: try nesting too deep (max 1024)");
            int _caught = 0;
            sage_try_depth++;
            if (setjmp(sage_try_stack[sage_try_depth - 1]) == 0) {
                sage_define_slot(&sage_local_lexer_465, sage_construct("Lexer", NULL, 1, (SageValue[]){SAGE_ADD(sage_load_slot(&sage_local_line_464, "line"), sage_string("\n"))}));
                sage_define_slot(&sage_local_tokens_466, sage_call_method(sage_load_slot(&sage_local_lexer_465, "lexer"), "tokenize", 0, NULL));
                sage_define_slot(&sage_local_parser_467, sage_construct("Parser", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_tokens_466, "tokens")}));
                sage_define_slot(&sage_local_ast_468, sage_call_method(sage_load_slot(&sage_local_parser_467, "parser"), "parse", 0, NULL));
                (void)sage_call_method(sage_load_slot(&sage_local_interp_462, "interp"), "run_program", 1, (SageValue[]){sage_load_slot(&sage_local_ast_468, "ast")});
            } else {
                _caught = 1;
                sage_define_slot(&sage_local_e_469, sage_exception_value);
            }
            sage_try_depth--;
            if (_caught) {
                sage_print_ln(SAGE_ADD(sage_string("Error: "), sage_str(sage_load_slot(&sage_local_e_469, "e"))));
            }
        }
    }
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

static SageValue sage_fn_run_script_31(SageValue arg0, SageValue arg1) {
    SageSlot sage_local_code_479 = sage_slot_undefined();
    SageSlot sage_local_ast_478 = sage_slot_undefined();
    SageSlot sage_local_parser_477 = sage_slot_undefined();
    SageSlot sage_local_tokens_476 = sage_slot_undefined();
    SageSlot sage_local_lexer_475 = sage_slot_undefined();
    SageSlot sage_local_interp_474 = sage_slot_undefined();
    SageSlot sage_local_process_473 = sage_slot_undefined();
    SageSlot sage_local_source_472 = sage_slot_undefined();
    SageSlot sage_param_batch_args_471 = sage_slot_undefined();
    SageSlot sage_param_script_path_470 = sage_slot_undefined();
    SageSlot* sage_gc_roots[10] = {&sage_local_code_479, &sage_local_ast_478, &sage_local_parser_477, &sage_local_tokens_476, &sage_local_lexer_475, &sage_local_interp_474, &sage_local_process_473, &sage_local_source_472, &sage_param_batch_args_471, &sage_param_script_path_470};
    SageGcFrame sage_gc_frame;
    sage_gc_push_frame(&sage_gc_frame, sage_gc_roots, 10);
    sage_define_slot(&sage_param_script_path_470, arg0);
    sage_define_slot(&sage_param_batch_args_471, arg1);
    sage_define_slot(&sage_local_source_472, sage_native_io_readfile(sage_load_slot(&sage_param_script_path_470, "script_path")));
    if (sage_truthy(SAGE_EQ(sage_load_slot(&sage_local_source_472, "source"), sage_nil()))) {
        sage_print_ln(SAGE_ADD(sage_string("SageBatch: File not found: "), sage_load_slot(&sage_param_script_path_470, "script_path")));
        (void)sage_call_method(sage_load_slot(&sage_global_sys_17, "sys"), "exit", 1, (SageValue[]){sage_number(1)});
    }
    sage_define_slot(&sage_local_process_473, sage_construct("BatchProcess", NULL, 2, (SageValue[]){sage_load_slot(&sage_param_script_path_470, "script_path"), sage_load_slot(&sage_param_batch_args_471, "batch_args")}));
    sage_define_slot(&sage_local_interp_474, sage_construct("Interpreter", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_process_473, "process")}));
    sage_define_slot(&sage_local_lexer_475, sage_construct("Lexer", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_source_472, "source")}));
    sage_define_slot(&sage_local_tokens_476, sage_call_method(sage_load_slot(&sage_local_lexer_475, "lexer"), "tokenize", 0, NULL));
    sage_print_ln(SAGE_ADD(sage_string("TOKENS: "), sage_str(sage_len(sage_load_slot(&sage_local_tokens_476, "tokens")))));
    sage_define_slot(&sage_local_parser_477, sage_construct("Parser", NULL, 1, (SageValue[]){sage_load_slot(&sage_local_tokens_476, "tokens")}));
    sage_define_slot(&sage_local_ast_478, sage_call_method(sage_load_slot(&sage_local_parser_477, "parser"), "parse", 0, NULL));
    sage_define_slot(&sage_local_code_479, sage_call_method(sage_load_slot(&sage_local_interp_474, "interp"), "run_program", 1, (SageValue[]){sage_load_slot(&sage_local_ast_478, "ast")}));
    (void)sage_call_method(sage_load_slot(&sage_global_sys_17, "sys"), "exit", 1, (SageValue[]){sage_load_slot(&sage_local_code_479, "code")});
    return sage_gc_return(&sage_gc_frame, sage_nil());
}

int sage_argc; char** sage_argv;
int main(int argc, char** argv) {
    sage_argc = argc; sage_argv = argv;
    sage_global_rest_36 = sage_slot_undefined();
    sage_global_script_35 = sage_slot_undefined();
    sage_global_proc_inst_34 = sage_slot_undefined();
    sage_global_arg_offset_33 = sage_slot_undefined();
    sage_global_args_32 = sage_slot_undefined();
    sage_global_parser_28 = sage_slot_undefined();
    sage_global_string_27 = sage_slot_undefined();
    sage_global_lexer_26 = sage_slot_undefined();
    sage_global_commands_25 = sage_slot_undefined();
    sage_global_registry_24 = sage_slot_undefined();
    sage_global_ast_23 = sage_slot_undefined();
    sage_global_interpreter_22 = sage_slot_undefined();
    sage_global_context_21 = sage_slot_undefined();
    sage_global_filesystem_20 = sage_slot_undefined();
    sage_global_varstore_19 = sage_slot_undefined();
    sage_global_io_18 = sage_slot_undefined();
    sage_global_sys_17 = sage_slot_undefined();
    sage_global_environment_16 = sage_slot_undefined();
    sage_global_process_15 = sage_slot_undefined();
    sage_global_TOK_AT_14 = sage_slot_undefined();
    sage_global_TOK_PAREN_R_13 = sage_slot_undefined();
    sage_global_TOK_PAREN_L_12 = sage_slot_undefined();
    sage_global_TOK_AMP_11 = sage_slot_undefined();
    sage_global_TOK_EOF_10 = sage_slot_undefined();
    sage_global_TOK_NEWLINE_9 = sage_slot_undefined();
    sage_global_TOK_PIPE_8 = sage_slot_undefined();
    sage_global_TOK_REDIRECT_7 = sage_slot_undefined();
    sage_global_TOK_OPERATOR_6 = sage_slot_undefined();
    sage_global_TOK_LABEL_5 = sage_slot_undefined();
    sage_global_TOK_VARIABLE_4 = sage_slot_undefined();
    sage_global_TOK_STRING_3 = sage_slot_undefined();
    sage_global_TOK_WORD_2 = sage_slot_undefined();
    sage_global_token_1 = sage_slot_undefined();
    SageSlot* sage_gc_global_roots[33] = {&sage_global_rest_36, &sage_global_script_35, &sage_global_proc_inst_34, &sage_global_arg_offset_33, &sage_global_args_32, &sage_global_parser_28, &sage_global_string_27, &sage_global_lexer_26, &sage_global_commands_25, &sage_global_registry_24, &sage_global_ast_23, &sage_global_interpreter_22, &sage_global_context_21, &sage_global_filesystem_20, &sage_global_varstore_19, &sage_global_io_18, &sage_global_sys_17, &sage_global_environment_16, &sage_global_process_15, &sage_global_TOK_AT_14, &sage_global_TOK_PAREN_R_13, &sage_global_TOK_PAREN_L_12, &sage_global_TOK_AMP_11, &sage_global_TOK_EOF_10, &sage_global_TOK_NEWLINE_9, &sage_global_TOK_PIPE_8, &sage_global_TOK_REDIRECT_7, &sage_global_TOK_OPERATOR_6, &sage_global_TOK_LABEL_5, &sage_global_TOK_VARIABLE_4, &sage_global_TOK_STRING_3, &sage_global_TOK_WORD_2, &sage_global_token_1};
    SageGcFrame sage_gc_main_frame;
    sage_gc_push_frame(&sage_gc_main_frame, sage_gc_global_roots, 33);
    sage_register_class("Interpreter", NULL);
    sage_register_method("Interpreter", "init", sage_method_Interpreter_init);
    sage_register_method("Interpreter", "build_label_table", sage_method_Interpreter_build_label_table);
    sage_register_method("Interpreter", "eval_condition", sage_method_Interpreter_eval_condition);
    sage_register_method("Interpreter", "expand_args", sage_method_Interpreter_expand_args);
    sage_register_method("Interpreter", "exec_node", sage_method_Interpreter_exec_node);
    sage_register_method("Interpreter", "run_program", sage_method_Interpreter_run_program);
    sage_register_method("Interpreter", "run_file", sage_method_Interpreter_run_file);
    sage_register_class("Parser", NULL);
    sage_register_method("Parser", "init", sage_method_Parser_init);
    sage_register_method("Parser", "peek", sage_method_Parser_peek);
    sage_register_method("Parser", "peek_kind", sage_method_Parser_peek_kind);
    sage_register_method("Parser", "advance", sage_method_Parser_advance);
    sage_register_method("Parser", "expect", sage_method_Parser_expect);
    sage_register_method("Parser", "skip_newlines", sage_method_Parser_skip_newlines);
    sage_register_method("Parser", "at_end", sage_method_Parser_at_end);
    sage_register_method("Parser", "collect_args", sage_method_Parser_collect_args);
    sage_register_method("Parser", "parse_block", sage_method_Parser_parse_block);
    sage_register_method("Parser", "parse_statement", sage_method_Parser_parse_statement);
    sage_register_method("Parser", "parse_label", sage_method_Parser_parse_label);
    sage_register_method("Parser", "parse_rem", sage_method_Parser_parse_rem);
    sage_register_method("Parser", "parse_goto", sage_method_Parser_parse_goto);
    sage_register_method("Parser", "parse_call", sage_method_Parser_parse_call);
    sage_register_method("Parser", "parse_if", sage_method_Parser_parse_if);
    sage_register_method("Parser", "parse_condition", sage_method_Parser_parse_condition);
    sage_register_method("Parser", "parse_for", sage_method_Parser_parse_for);
    sage_register_method("Parser", "parse_set", sage_method_Parser_parse_set);
    sage_register_method("Parser", "parse_command", sage_method_Parser_parse_command);
    sage_register_method("Parser", "parse_block_contents", sage_method_Parser_parse_block_contents);
    sage_register_method("Parser", "parse", sage_method_Parser_parse);
    sage_register_class("Lexer", NULL);
    sage_register_method("Lexer", "init", sage_method_Lexer_init);
    sage_register_method("Lexer", "get_char", sage_method_Lexer_get_char);
    sage_register_method("Lexer", "peek", sage_method_Lexer_peek);
    sage_register_method("Lexer", "advance", sage_method_Lexer_advance);
    sage_register_method("Lexer", "match_char", sage_method_Lexer_match_char);
    sage_register_method("Lexer", "skip_whitespace_inline", sage_method_Lexer_skip_whitespace_inline);
    sage_register_method("Lexer", "emit", sage_method_Lexer_emit);
    sage_register_method("Lexer", "scan_string", sage_method_Lexer_scan_string);
    sage_register_method("Lexer", "scan_variable", sage_method_Lexer_scan_variable);
    sage_register_method("Lexer", "scan_word", sage_method_Lexer_scan_word);
    sage_register_method("Lexer", "scan_redirect", sage_method_Lexer_scan_redirect);
    sage_register_method("Lexer", "scan_comment", sage_method_Lexer_scan_comment);
    sage_register_method("Lexer", "tokenize", sage_method_Lexer_tokenize);
    sage_register_class("CommandRegistry", NULL);
    sage_register_method("CommandRegistry", "init", sage_method_CommandRegistry_init);
    sage_register_method("CommandRegistry", "is_internal", sage_method_CommandRegistry_is_internal);
    sage_register_method("CommandRegistry", "dispatch", sage_method_CommandRegistry_dispatch);
    sage_register_class("InternalCommands", NULL);
    sage_register_method("InternalCommands", "init", sage_method_InternalCommands_init);
    sage_register_method("InternalCommands", "cmd_echo", sage_method_InternalCommands_cmd_echo);
    sage_register_method("InternalCommands", "cmd_rem", sage_method_InternalCommands_cmd_rem);
    sage_register_method("InternalCommands", "cmd_set", sage_method_InternalCommands_cmd_set);
    sage_register_method("InternalCommands", "cmd_pause", sage_method_InternalCommands_cmd_pause);
    sage_register_method("InternalCommands", "cmd_cls", sage_method_InternalCommands_cmd_cls);
    sage_register_method("InternalCommands", "cmd_exit", sage_method_InternalCommands_cmd_exit);
    sage_register_method("InternalCommands", "cmd_cd", sage_method_InternalCommands_cmd_cd);
    sage_register_method("InternalCommands", "cmd_md", sage_method_InternalCommands_cmd_md);
    sage_register_method("InternalCommands", "cmd_rd", sage_method_InternalCommands_cmd_rd);
    sage_register_method("InternalCommands", "cmd_dir", sage_method_InternalCommands_cmd_dir);
    sage_register_method("InternalCommands", "cmd_type", sage_method_InternalCommands_cmd_type);
    sage_register_method("InternalCommands", "cmd_copy", sage_method_InternalCommands_cmd_copy);
    sage_register_method("InternalCommands", "cmd_move", sage_method_InternalCommands_cmd_move);
    sage_register_method("InternalCommands", "cmd_del", sage_method_InternalCommands_cmd_del);
    sage_register_method("InternalCommands", "cmd_ren", sage_method_InternalCommands_cmd_ren);
    sage_register_method("InternalCommands", "cmd_shift", sage_method_InternalCommands_cmd_shift);
    sage_register_method("InternalCommands", "cmd_ver", sage_method_InternalCommands_cmd_ver);
    sage_register_method("InternalCommands", "cmd_help", sage_method_InternalCommands_cmd_help);
    sage_register_class("BlockNode", NULL);
    sage_register_method("BlockNode", "init", sage_method_BlockNode_init);
    sage_register_class("PipeNode", NULL);
    sage_register_method("PipeNode", "init", sage_method_PipeNode_init);
    sage_register_class("RedirectNode", NULL);
    sage_register_method("RedirectNode", "init", sage_method_RedirectNode_init);
    sage_register_class("CallNode", NULL);
    sage_register_method("CallNode", "init", sage_method_CallNode_init);
    sage_register_class("GotoNode", NULL);
    sage_register_method("GotoNode", "init", sage_method_GotoNode_init);
    sage_register_class("LabelNode", NULL);
    sage_register_method("LabelNode", "init", sage_method_LabelNode_init);
    sage_register_class("ForStatement", NULL);
    sage_register_method("ForStatement", "init", sage_method_ForStatement_init);
    sage_register_class("IfStatement", NULL);
    sage_register_method("IfStatement", "init", sage_method_IfStatement_init);
    sage_register_class("Assignment", NULL);
    sage_register_method("Assignment", "init", sage_method_Assignment_init);
    sage_register_class("Command", NULL);
    sage_register_method("Command", "init", sage_method_Command_init);
    sage_register_class("Program", NULL);
    sage_register_method("Program", "init", sage_method_Program_init);
    sage_register_class("BatchProcess", NULL);
    sage_register_method("BatchProcess", "init", sage_method_BatchProcess_init);
    sage_register_method("BatchProcess", "make_context", sage_method_BatchProcess_make_context);
    sage_register_method("BatchProcess", "push_call", sage_method_BatchProcess_push_call);
    sage_register_method("BatchProcess", "pop_call", sage_method_BatchProcess_pop_call);
    sage_register_class("CommandContext", NULL);
    sage_register_method("CommandContext", "init", sage_method_CommandContext_init);
    sage_register_method("CommandContext", "expand_token", sage_method_CommandContext_expand_token);
    sage_register_method("CommandContext", "shift_args", sage_method_CommandContext_shift_args);
    sage_register_method("CommandContext", "get_arg", sage_method_CommandContext_get_arg);
    sage_register_method("CommandContext", "write_out", sage_method_CommandContext_write_out);
    sage_register_class("FileSystem", NULL);
    sage_register_method("FileSystem", "init", sage_method_FileSystem_init);
    sage_register_method("FileSystem", "normalize", sage_method_FileSystem_normalize);
    sage_register_method("FileSystem", "resolve", sage_method_FileSystem_resolve);
    sage_register_method("FileSystem", "exists", sage_method_FileSystem_exists);
    sage_register_method("FileSystem", "is_dir", sage_method_FileSystem_is_dir);
    sage_register_method("FileSystem", "is_file", sage_method_FileSystem_is_file);
    sage_register_method("FileSystem", "read_file", sage_method_FileSystem_read_file);
    sage_register_method("FileSystem", "write_file", sage_method_FileSystem_write_file);
    sage_register_method("FileSystem", "append_file", sage_method_FileSystem_append_file);
    sage_register_method("FileSystem", "delete_file", sage_method_FileSystem_delete_file);
    sage_register_method("FileSystem", "make_dir", sage_method_FileSystem_make_dir);
    sage_register_method("FileSystem", "remove_dir", sage_method_FileSystem_remove_dir);
    sage_register_method("FileSystem", "list_dir", sage_method_FileSystem_list_dir);
    sage_register_method("FileSystem", "glob", sage_method_FileSystem_glob);
    sage_register_method("FileSystem", "copy_file", sage_method_FileSystem_copy_file);
    sage_register_method("FileSystem", "move_file", sage_method_FileSystem_move_file);
    sage_register_method("FileSystem", "rename_file", sage_method_FileSystem_rename_file);
    sage_register_class("VarStore", NULL);
    sage_register_method("VarStore", "init", sage_method_VarStore_init);
    sage_register_method("VarStore", "push_scope", sage_method_VarStore_push_scope);
    sage_register_method("VarStore", "pop_scope", sage_method_VarStore_pop_scope);
    sage_register_method("VarStore", "set_local", sage_method_VarStore_set_local);
    sage_register_method("VarStore", "get", sage_method_VarStore_get);
    sage_register_method("VarStore", "set", sage_method_VarStore_set);
    sage_register_method("VarStore", "expand", sage_method_VarStore_expand);
    sage_register_class("Environment", NULL);
    sage_register_method("Environment", "init", sage_method_Environment_init);
    sage_register_method("Environment", "_init_defaults", sage_method_Environment__init_defaults);
    sage_register_method("Environment", "set_var", sage_method_Environment_set_var);
    sage_register_method("Environment", "get_var", sage_method_Environment_get_var);
    sage_register_method("Environment", "del_var", sage_method_Environment_del_var);
    sage_register_method("Environment", "expand", sage_method_Environment_expand);
    sage_register_method("Environment", "set_errorlevel", sage_method_Environment_set_errorlevel);
    sage_register_method("Environment", "get_errorlevel", sage_method_Environment_get_errorlevel);
    sage_register_method("Environment", "chdir", sage_method_Environment_chdir);
    sage_register_method("Environment", "render_prompt", sage_method_Environment_render_prompt);
    sage_register_class("Token", NULL);
    sage_register_method("Token", "init", sage_method_Token_init);
    sage_register_method("Token", "__str__", sage_method_Token___str__);
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_process_15, sage_init_native_module("process"));
    sage_define_slot(&sage_global_environment_16, sage_init_native_module("environment"));
    sage_define_slot(&sage_global_sys_17, sage_init_native_module("sys"));
    sage_define_slot(&sage_global_io_18, sage_init_native_module("io"));
    sage_define_slot(&sage_global_varstore_19, sage_init_native_module("varstore"));
    sage_define_slot(&sage_global_filesystem_20, sage_init_native_module("filesystem"));
    sage_define_slot(&sage_global_io_18, sage_init_native_module("io"));
    sage_define_slot(&sage_global_sys_17, sage_init_native_module("sys"));
    sage_define_slot(&sage_global_context_21, sage_init_native_module("context"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_io_18, sage_init_native_module("io"));
    sage_define_slot(&sage_global_interpreter_22, sage_init_native_module("interpreter"));
    sage_define_slot(&sage_global_ast_23, sage_init_native_module("ast"));
    sage_define_slot(&sage_global_registry_24, sage_init_native_module("registry"));
    sage_define_slot(&sage_global_commands_25, sage_init_native_module("commands"));
    sage_define_slot(&sage_global_sys_17, sage_init_native_module("sys"));
    sage_define_slot(&sage_global_lexer_26, sage_init_native_module("lexer"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_string_27, sage_init_native_module("string"));
    sage_define_slot(&sage_global_parser_28, sage_init_native_module("parser"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_ast_23, sage_init_native_module("ast"));
    sage_define_slot(&sage_global_ast_23, sage_init_native_module("ast"));
    sage_define_slot(&sage_global_string_27, sage_init_native_module("string"));
    sage_define_slot(&sage_global_io_18, sage_init_native_module("io"));
    sage_define_slot(&sage_global_sys_17, sage_init_native_module("sys"));
    sage_define_slot(&sage_global_lexer_26, sage_init_native_module("lexer"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_string_27, sage_init_native_module("string"));
    sage_define_slot(&sage_global_parser_28, sage_init_native_module("parser"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_token_1, sage_init_native_module("token"));
    sage_define_slot(&sage_global_TOK_WORD_2, sage_string("WORD"));
    sage_define_slot(&sage_global_TOK_STRING_3, sage_string("STRING"));
    sage_define_slot(&sage_global_TOK_VARIABLE_4, sage_string("VARIABLE"));
    sage_define_slot(&sage_global_TOK_LABEL_5, sage_string("LABEL"));
    sage_define_slot(&sage_global_TOK_OPERATOR_6, sage_string("OPERATOR"));
    sage_define_slot(&sage_global_TOK_REDIRECT_7, sage_string("REDIRECT"));
    sage_define_slot(&sage_global_TOK_PIPE_8, sage_string("PIPE"));
    sage_define_slot(&sage_global_TOK_NEWLINE_9, sage_string("NEWLINE"));
    sage_define_slot(&sage_global_TOK_EOF_10, sage_string("EOF"));
    sage_define_slot(&sage_global_TOK_AMP_11, sage_string("AMP"));
    sage_define_slot(&sage_global_TOK_PAREN_L_12, sage_string("PAREN_L"));
    sage_define_slot(&sage_global_TOK_PAREN_R_13, sage_string("PAREN_R"));
    sage_define_slot(&sage_global_TOK_AT_14, sage_string("AT"));
    sage_define_slot(&sage_global_ast_23, sage_init_native_module("ast"));
    sage_define_slot(&sage_global_ast_23, sage_init_native_module("ast"));
    sage_define_slot(&sage_global_string_27, sage_init_native_module("string"));
    sage_define_slot(&sage_global_sys_17, sage_init_native_module("sys"));
    sage_define_slot(&sage_global_io_18, sage_init_native_module("io"));
    sage_define_slot(&sage_global_args_32, sage_native_sys_args());
    sage_define_slot(&sage_global_arg_offset_33, sage_number(1));
    if (sage_truthy(sage_and(SAGE_GT(sage_len(sage_load_slot(&sage_global_args_32, "args")), sage_number(1)), sage_or(sage_endswith(sage_index(sage_load_slot(&sage_global_args_32, "args"), sage_number(1)), sage_string(".sage")), sage_endswith(sage_index(sage_load_slot(&sage_global_args_32, "args"), sage_number(1)), sage_string(".sgvm")))))) {
        (void)sage_assign_slot(&sage_global_arg_offset_33, "arg_offset", sage_number(2));
    }
    if (sage_truthy(SAGE_LTE(sage_len(sage_load_slot(&sage_global_args_32, "args")), sage_load_slot(&sage_global_arg_offset_33, "arg_offset")))) {
        sage_define_slot(&sage_global_proc_inst_34, sage_construct("BatchProcess", NULL, 2, (SageValue[]){sage_string("INTERACTIVE"), sage_make_array(0, NULL)}));
        (void)sage_fn_run_interactive_30(sage_load_slot(&sage_global_proc_inst_34, "proc_inst"));
    }
    else {
        sage_define_slot(&sage_global_script_35, sage_index(sage_load_slot(&sage_global_args_32, "args"), sage_load_slot(&sage_global_arg_offset_33, "arg_offset")));
        sage_define_slot(&sage_global_rest_36, sage_slice(sage_load_slot(&sage_global_args_32, "args"), SAGE_ADD(sage_load_slot(&sage_global_arg_offset_33, "arg_offset"), sage_number(1)), sage_len(sage_load_slot(&sage_global_args_32, "args"))));
        (void)sage_fn_run_script_31(sage_load_slot(&sage_global_script_35, "script"), sage_load_slot(&sage_global_rest_36, "rest"));
    }
    sage_gc_pop_frame(&sage_gc_main_frame);
    sage_gc_shutdown();
    return 0;
}
