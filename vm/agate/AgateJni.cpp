#include "Dalvik.h"
#include "agate/AgatePolicy.h"
#include "agate/AgateJniInternal.h"
#include "JniInternal.h"

/**
 *  Helper functions
 */
static char* _int_to_byte_array(int value) {
    char* bytes = (char*) malloc(sizeof(int));
    for (u4 i = 0; i < sizeof(int); i++) {
        bytes[i] = (char)((value >> ((sizeof(int) - i - 1) * 8)) & 0xff);
    }
    return bytes;
}

static int _int_from_byte_array(char* bytes) {
    int value = 0;
    for (u4 i = 0; i < sizeof(int); i++) {
        value = value << 8;
        value |= bytes[i] & 0xff;
    }
    return value;
}

static char* _copy_bytes(char* dest, char* src, u4 n) {
    for (u4 i = 0; i < n; i++) {
        ALOGW("byte[%d] = %c", i, *src);
        *dest++ = *src++;
    }
    return dest;
}

static char* _add_int(char* dest, int val) {
    char* l = _int_to_byte_array(val);
    dest = _copy_bytes(dest, l, sizeof(int));
    free(l);
    return dest;
}

static char* _get_int(char* dest, int* val) {
    *val = _int_from_byte_array(dest); 
    return dest + sizeof(int);
}

static char* _add_string(char* dest, std::string str) {
    dest = _add_int(dest, str.size());
    dest = _copy_bytes(dest, (char*) str.c_str(), str.size());
    return dest;
}

static char* _get_string(char* dest, Object** s) {
    int size;
    dest = _get_int(dest, &size);
    //ALOGW("Reader size: %d", size);
    Object* str = (Object*) dvmCreateStringFromCstrAndLength(dest, size);
    if (str == NULL) {
            // Probably OOM; drop out now.
            assert(dvmCheckException(dvmThreadSelf()));
            //dvmReleaseTrackedAlloc((Object*) stringArray, self);
    }

    *s = str;
    return dest + size;
}

static int _get_fd_from_filedescriptor(JNIEnv* env, jobject java_fd) {
    //TODO: Is this expensive? Set a global variable?
    jclass clazz = (jclass)env->NewGlobalRef(env->FindClass("java/io/FileDescriptor"));
    if (clazz == NULL) {
        ALOGW("[_get_fd_from_filedescriptor] Could not find class java.io.FileDEscriptor");
        return -1;
    }

    jfieldID descriptor = env->GetFieldID(clazz, "descriptor", "I");
    if (descriptor == NULL) {
        ALOGW("[_get_fd_from_filedescriptor] Could not get descriptor fieldID");
        return -1;
    }

    return env->GetIntField(java_fd, descriptor);
}

/* Functions working with JNI object references */

/*
 * Checks if data can flow
 */
bool agateJniCanFlow(JNIEnv* env, int from, int to) {
   return agate_can_flow((u4)from, (u4)to);
}

/*
 * Gets the Policy on a socket
 */
int agateJniGetSocketPolicy(JNIEnv* env, jobject java_fd) {
   int _fd = _get_fd_from_filedescriptor(env, java_fd);
   return agate_get_policy_on_socket(_fd);
}

/*
 * Gets the Policy on a StringObject
 */
int agateJniGetStringPolicy(JNIEnv* env, jobject obj) {
    return 1;
}

/*
 * Gets the Policy on an ArrayObject
 */
int agateJniGetArrayPolicy(JNIEnv* env, jobject obj) {
    ArrayObject* arrObj = (ArrayObject*) dvmJniGetObject(env, obj);
    return arrObj->taint.tag;
}

/*
 * Encodes a policy as a stream of bytes (Serializes)
 */
char* agateJniEncodePolicy(JNIEnv* env, int* size, int tag) {

    Policy* p = (Policy*) tag;
    int v_size = p->readers->size();

    /* Compute total length of the serialized policy */
    int total_length = 2*sizeof(int); // one int to encode total_length and one int to encode vector size
    std::set<std::string> reader_set = *(p->readers);
    for (std::set<std::string>::iterator i = reader_set.begin(); i != reader_set.end(); i++) {
        total_length += sizeof(int) + (*i).size();
    }

    /* Allocate memory */
    char* bytes = (char*)malloc(total_length);

    /* Add the  policy as a continuous stream */
    char* q = _add_int(bytes, total_length);
    q = _add_int(q, v_size);
    for (std::set<std::string>::iterator i = reader_set.begin(); i != reader_set.end(); i++) {
        q = _add_string(q, *i);
    }

    *size = total_length;
    return bytes;
}

/*
 * De-codes a policy from a stream of bytes (De-serialization)
 */
int agateJniDecodePolicy(JNIEnv* env, char* p) {
    int v_size;
    
    //char* q = _get_int(p, &total_size);
    //ALOGW("Total size = %d", total_size);
    char* q = _get_int(p, &v_size);
    //ALOGW("Vector size = %d", v_size);

    /* Create ArrayObject of readers */
    // Allocate an array to hold the String objects.
    ClassObject* elementClass = dvmFindArrayClassForElement(gDvm.classJavaLangString);
    ArrayObject* readers = dvmAllocArrayByClass(elementClass, v_size, ALLOC_DEFAULT);
    if (readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return 0;
    }

    for (int i = 0; i < v_size; i++) {
        Object* s;
        q = _get_string(q, &s);
        //ALOGW("Reader: %s", (char*) dvmCreateCstrFromString((StringObject*)s));
        if (s == NULL) {
             dvmReleaseTrackedAlloc((Object*) readers, dvmThreadSelf());
             return 0;
        }
        dvmSetObjectArrayElement(readers, i, s);
        /* stored in tracked array, okay to release */
        dvmReleaseTrackedAlloc(s, dvmThreadSelf());
    }

    return agate_create_policy(readers, NULL);
}

/*
 * Adds policy to a socket
 */
void agateJniAddSocketPolicy(JNIEnv* env, jobject java_fd, int tag) {
   int _fd = _get_fd_from_filedescriptor(env, java_fd);
   agate_add_policy_on_socket(_fd, tag);
}

/*
 * Adds policy to a StringObject
 */
void agateJniAddStringPolicy(JNIEnv* env) {
}

/*
 * Adds policy to an ArrayObject
 */
void agateJniAddArrayPolicy(JNIEnv* env, jobject obj, int tag) {
    ArrayObject* arrObj = (ArrayObject*) dvmJniGetObject(env, obj);
    arrObj->taint.tag = (u4)tag;
}
