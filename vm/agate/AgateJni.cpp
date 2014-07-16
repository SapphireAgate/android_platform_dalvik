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
<<<<<<< HEAD
char* agateJniEncodePolicy(JNIEnv* env, int* size, int tag, int extraSize) {
    PolicyObject* p = (PolicyObject*) tag;
    u4 v_size = p->readers->length;

    /* Compute total length of the serialized policy */
    int output_length = 2*sizeof(int); // one int to encode total_length
=======
char* agateJniEncodePolicy(JNIEnv* env, int* size, int tag) {

    Policy* p = (Policy*) tag;
    int readersetCount = p->length;

    /* Compute total length of the serialized policy */
    int output_length = sizeof(int); // one int to encode total_length
>>>>>>> c3db92f... finished policy merging (except jit) and did policy garbage collection
	int readerset_count = 0;
	for(int i = 0; i < readersetCount; i++) {
		ArrayObject* rs = ((ArrayObject**)p->contents)[i];
		ArrayObject* rus = ((ArrayObject**)rs->contents)[0];
		ArrayObject* rgs = ((ArrayObject**)rs->contents)[1];

		output_length += 2*sizeof(int);
		readerset_count++;

		int userCount = rus->length;
		for(int j = 0; j < userCount; j++) {
			output_length += sizeof(int);
		}

		int groupCount = rgs->length;
		for(int j = 0; j < groupCount; j++) {
			output_length += sizeof(int);
		}
	}

	/* Allocate memory */
<<<<<<< HEAD
    char* bytes = (char*)malloc(output_length + extraSize);

	/* Add the  policy as a continuous stream */
	char* q = _add_int(bytes, output_length - sizeof(int));
	q = _add_int(bytes, readerset_count);
=======
    char* bytes = (char*)malloc(output_length);

	/* Add the  policy as a continuous stream */
	char* q = _add_int(bytes, readerset_count);
>>>>>>> c3db92f... finished policy merging (except jit) and did policy garbage collection

	// fill with data
	for(int i = 0; i < readersetCount; i++) {
		ArrayObject* rs = ((ArrayObject**)p->contents)[i];
		ArrayObject* rus = ((ArrayObject**)p->contents)[0];
		ArrayObject* rgs = ((ArrayObject**)p->contents)[1];

		int userCount = rus->length;
		q = _add_int(q,userCount);
		for(int j = 0; j < userCount; j++) {
			int userId = ((int*)rus->contents)[j];
			q = _add_int(q,userId);
		}

		int groupCount = rgs->length;
		q = _add_int(q,groupCount);
		for(int j = 0; j < userCount; j++) {
			int groupId = ((int*)rgs->contents)[j];
			q = _add_int(q,groupId);
		}
	}

	*size = output_length;
	return bytes;
}

/*
 * De-codes a policy from a stream of bytes (De-serialization)
 */
<<<<<<< HEAD
int agateJniDecodePolicy(JNIEnv* env, char* s) {
    // TODO: for now only the readers
    u4 n_r;
    s = _get_int(s, (int*)&n_r); // get nr. of readers

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
    }

    return (int)p;
=======
int agateJniDecodePolicy(JNIEnv* env, char* p) {

    int readerset_count;
    
    char* q = _get_int(p, &readerset_count);

	if(readerset_count == 0) {
		return NULL;
	}

	ArrayObject** policies = (ArrayObject**)malloc(sizeof(u4)*readerset_count);

	for(int i = 0; i < readerset_count; i++) {
		int user_count;
		q = _get_int(q, &user_count);
		//fill user readers
		ArrayObject* uReaders = dvmAllocPrimitiveArray('I', user_count, 0);
		for(int j = 0; j < user_count; j++) {
			int userId;
			q = _get_int(q, &userId);
			((int*)uReaders->contents)[j] = userId;
		}

		int group_count;
		q = _get_int(q, &group_count);
		//fill group readers
		ArrayObject* gReaders = dvmAllocPrimitiveArray('I', group_count, 0);
		for(int j = 0; j < group_count; j++) {
			int groupId;
			q = _get_int(q, &groupId);
			((int*)gReaders->contents)[j] = groupId;
		}

		//make a readerset
		ClassObject* readersetclazz = dvmFindArrayClassForElement(uReaders->clazz);
		ArrayObject* readerset = dvmAllocArrayByClass(readersetclazz, 2, 0);

		((ArrayObject**)readerset->contents)[0] = uReaders;
		((ArrayObject**)readerset->contents)[1] = gReaders;
		dvmReleaseTrackedAlloc((Object *)uReaders, NULL);
		dvmReleaseTrackedAlloc((Object *)gReaders, NULL);

		policies[i] = readerset;
	}

	ClassObject* policyclazz = dvmFindArrayClassForElement(policies[0]->clazz);
	ArrayObject* out = dvmAllocArrayByClass(policyclazz, readerset_count, ALLOC_DONT_TRACK);

	for(int i = 0; i < readerset_count; i++) {
		((ArrayObject**)out->contents)[i] = policies[i];
		dvmReleaseTrackedAlloc((Object *)policies[i], NULL);
	}

	return (u4)out;
>>>>>>> c3db92f... finished policy merging (except jit) and did policy garbage collection
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
