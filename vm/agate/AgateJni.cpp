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
        ALOGW("AgateLog: [_get_fd_from_filedescriptor] Could not find class java.io.FileDEscriptor");
        return -1;
    }

    jfieldID descriptor = env->GetFieldID(clazz, "descriptor", "I");
    if (descriptor == NULL) {
        ALOGW("AgateLog: [_get_fd_from_filedescriptor] Could not get descriptor fieldID");
        return -1;
    }

    return env->GetIntField(java_fd, descriptor);
}

/* Functions working with JNI object references */

/*
 * Checks if data can flow
 */
bool agateJniCanFlow(JNIEnv* env, int from, int to) {
   if (from == 0)
       return true;

   if (to == 0)
       return false; 

   return agate_can_flow((PolicyObject*)from, (PolicyObject*)to);
}

/*
 * Get a policy representing the current process
 */
static int userId = -1;
static PolicyObject* curTag = NULL;
int agateJniGetCurrentProcessPolicy(JNIEnv* env) {
    int id = agate_get_userId();

    if(id == userId) {
        return (int)curTag;
    }

    userId = id;

    if(id == -1) {
        curTag = NULL;
    } else {
        ArrayObject* readers = dvmAllocPrimitiveArray('I', 1, 0);
        ((int*)(void*)readers->contents)[0] = id;
        curTag = agate_create_policy(readers, NULL);
        dvmReleaseTrackedAlloc(readers, NULL);
    }

    return (int)curTag;
}

/*
 * Gets the Policy on a socket
 */
int agateJniGetSocketPolicy(JNIEnv* env, jobject java_fd) {
    int _fd = _get_fd_from_filedescriptor(env, java_fd);
    return agate_get_policy_on_socket(_fd);
}

/* 
 * Removes the policy from a socket
 */
void agateJniRemoveSocketPolicy(JNIEnv* env, jint fd) {
    agate_remove_policy_from_socket(fd);
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
    ALOGW("AgateLog: [agateJniGetArrayPolicy] Getting policy on array object: %p", (void*) arrObj);
    return arrObj->taint.tag;
}

/*
 * Encodes a policy as a stream of bytes (Serializes)
 * - first 4 bytes in the stream represent the total length (in bytes) of the policy
 * - the "size" parameter will contain the total length of the returned stream
 */
char* agateJniEncodePolicy(JNIEnv* env, int* size, int tag) {
    PolicyObject* p = (PolicyObject*) tag;
    if(p == NULL) {
        char* out = (char*)malloc(sizeof(int));
	_add_int(out, 0);    // policy has size 0
 	*size = sizeof(int); // total length of stream has 4 bytes
        return out;
    }

    int v_size = p->readers->length;
    /* Compute total length of the serialized policy */
    u4 p_size = v_size * sizeof(u4) + sizeof(u4); // encode also the vector size

    /* Allocate memory */
    char* bytes = (char*)malloc(p_size + sizeof(int));

    /* Add the  policy as a continuous stream */
    char* q = _add_int(bytes, p_size); // TODO: add u4, but it's ok because sizeof(u4) = sizeof(int)
    q = _add_int(q, v_size);
    for (int i = 0; i < v_size; i++) {
        q = _add_int(q, ((int*)(void*)p->readers->contents)[i]);
    }

    // TODO: add writers
    *size = p_size + sizeof(int);
    return bytes;
}

/*
 * De-codes a policy from a stream of bytes (De-serialization)
 */
int agateJniDecodePolicy(JNIEnv* env, char* s) {
    // TODO: for now only the readers
    u4 n_r;
    s = _get_int(s, (int*)&n_r); // get nr. of readers
    ALOGW("AgateLog: [agateJniDecodePolicy] No readers: %d", (int) n_r);

    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);

    /* Allocate space for the reader's vector */
    // no need to track the allocation, p is already tracked and scanned.
    p->readers = dvmAllocPrimitiveArray('I', n_r, ALLOC_DEFAULT);
    dvmReleaseTrackedAlloc((Object*)p->readers, NULL);

    if (p->readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return 0;
    }

    /* Copy contents from readers argument */
    for (u4 i = 0; i < n_r; i++) {
        s = _get_int(s, (int*)(void*)p->readers->contents + i);
        ALOGW("AgateLog: [agateJniDecodePolicy] Reader: %d", (int)(int*)(void*)p->readers->contents[i]);
    }

    return (int)p;
}

/*
 * Un-tracks a heap allocated policy
 */
void agateJniReleasePolicy(JNIEnv* env, int tag) {
    agate_release_policy(tag);
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
 * Adds existing policy to an ArrayObject. The caller must know if
 * it needs to un-track the policy from tracked GC memory or not and make
 * sure that he does. This function does not un-track the policy.
 */
void agateJniAddArrayPolicy(JNIEnv* env, jobject obj, int tag) {
    ArrayObject* arrObj = (ArrayObject*) dvmJniGetObject(env, obj);
    arrObj->taint.tag = (u4)tag;
}

void agateJniPrintPolicy(int tag) {
	agate_print_policy((PolicyObject*)tag);
}

/* Get the identity of the logged in user */
int agateJniGetCertificate(JNIEnv* env) {
    return agate_get_userId();
}
