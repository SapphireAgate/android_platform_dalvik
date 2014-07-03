#include "Dalvik.h"
#include "agate/AgatePolicy.h"
#include "agate/AgateUser.h"
#include "agate/AgateJniInternal.h"
#include "JniInternal.h"

/**
 *  Helper functions
 */
static char* _int_to_byte_array(char* dest, int value) {
    for (u4 i = 0; i < sizeof(int); i++) {
        *dest++ = (char)((value >> ((sizeof(int) - i - 1) * 8)) & 0xff);
    }
    return dest;
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
        *dest++ = *src++;
    }
    return dest;
}

static char* _add_int(char* dest, int val) {
    return _int_to_byte_array(dest, val);
}

static char* _get_int(char* dest, int* val) {
    *val = _int_from_byte_array(dest); 
    return dest + sizeof(int);
}

//static char* _add_string(char* dest, std::string str) {
//    dest = _add_int(dest, str.size());
//    dest = _copy_bytes(dest, (char*) str.c_str(), str.size());
//    return dest;
//}

//static char* _get_string(char* dest, Object** s) {
//    int size;
//    dest = _get_int(dest, &size);
//    //ALOGW("Reader size: %d", size);
//    Object* str = (Object*) dvmCreateStringFromCstrAndLength(dest, size);
//    if (str == NULL) {
//            // Probably OOM; drop out now.
//            assert(dvmCheckException(dvmThreadSelf()));
//            //dvmReleaseTrackedAlloc((Object*) stringArray, self);
//    }
//
//    *s = str;
//    return dest + size;
//}

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
   if (from == 0 && to == 0)
       return true;

   if (from == 0)
       return true;

   //TODO: solve this case
   if (to == 0)
       return false; 

   return agate_can_flow((PolicyObject*)from, (PolicyObject*)to);
}

/*
 * Gets the Policy on a socket
 */
int agateJniGetSocketPolicy(JNIEnv* env, jobject java_fd) {
   int _fd = _get_fd_from_filedescriptor(env, java_fd);
   return (int)agate_get_policy_on_socket(_fd);
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

    PolicyObject* p = (PolicyObject*) tag;
    u4 v_size = p->n_r;

    /* Compute total length of the serialized policy */
    u4 total_length = v_size * sizeof(u4) + 2 * sizeof(u4); // encode also the vector size and total_length

    /* Allocate memory */
    char* bytes = (char*)malloc(total_length);

    /* Add the  policy as a continuous stream */
    char* q = _add_int(bytes, total_length); // TODO: add u4, but it's ok because sizeof(u4) = sizeof(int)
    q = _add_int(q, v_size);
    for (u4 i = 0; i < v_size; i++) {
        q = _add_int(q, p->readers[i]);
    }

    // TODO: add writers
    *size = total_length;
    return bytes;
}

/*
 * De-codes a policy from a stream of bytes (De-serialization)
 */
int agateJniDecodePolicy(JNIEnv* env, char* s) {
    // TODO: for now only the readers
    u4 n_r;
    s = _get_int(s, (int*)&n_r); // get nr. of readers

    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*)dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);

    /* Allocate space for the reader's vector */
    // no need to track the allocation, p is already tracked and scanned.
    p->n_r = n_r;
    p->readers = (u4*)dvmMalloc(sizeof(u4) * n_r, ALLOC_DONT_TRACK);

    if (p->readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return 0;
    }

    /* Copy contents from readers argument */
    for (u4 i = 0; i < n_r; i++) {
        s = _get_int(s, (int*)(p->readers + i));
    }

    return (int)p;
}

/*
 * Adds policy to a socket
 */
void agateJniAddSocketPolicy(JNIEnv* env, jobject java_fd, int tag) {
   int _fd = _get_fd_from_filedescriptor(env, java_fd);
   agate_add_policy_on_socket(_fd, (PolicyObject*) tag);
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

/* Get the identity of the logged in user */
int agateJniGetCertificate(JNIEnv* env) {
    return agate_get_userId();
}

void agateJniPrintPolicy(int tag) {
    agate_print_policy((PolicyObject*)tag);
}
