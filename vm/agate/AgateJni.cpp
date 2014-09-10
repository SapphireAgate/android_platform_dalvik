#include "Dalvik.h"
#include "agate/AgatePolicy.h"
#include "agate/AgateUser.h"
#include "agate/AgateJniInternal.h"
#include "JniInternal.h"

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

   return agate_can_flow(from, to);
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
        ArrayObject* user_readers = dvmAllocPrimitiveArray('I', 1, 0);
        ((int*)(void*)user_readers->contents)[0] = id;
        curTag = agate_create_policy(user_readers, NULL);
        dvmReleaseTrackedAlloc(user_readers, NULL);
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
 * - the next 4 bytes contain the length of user_readers
 * - follows the user_readers stream
 * - next the length of the group_readers
 * - the rest are the group_readers
 * - the "size" parameter will contain the total length of the returned stream
 */
char* agateJniEncodePolicy(JNIEnv* env, int* size, int tag) {
    return agate_encode_policy(size, tag);
}

/*
 * De-codes a policy from a stream of bytes (De-serialization)
 */
int agateJniDecodePolicy(JNIEnv* env, char* s) {
    return agate_decode_policy(s);
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
    agate_print_policy(tag);
}

/* Get the identity of the logged in user */
int agateJniGetCertificate(JNIEnv* env) {
    return agate_get_userId();
}
