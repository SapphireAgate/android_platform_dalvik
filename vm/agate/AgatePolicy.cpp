#include "Dalvik.h"
#include "agate/AgatePolicy.h"
#include "AgateUtil.h"
#include "JniInternal.h"

#include <set>
#include <algorithm>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

#include "time.h"

static ArrayObject* _encode_readers(ArrayObject* readers) {
    ArrayObject* r;
    /* Allocate space for the readers vector */
    int count = 0;
    if (readers != NULL) {
        count = readers->length;
    }
    r = dvmAllocPrimitiveArray('I', count + 1, ALLOC_DEFAULT);

    if (r == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return NULL;
    }

    /* First encode the size number of readers */
    int *r1 = (int*)(void*)r->contents;
    r1[0] = count;

    if (readers != NULL) {
        /* Copy contents from readers argument */
        int *r2 = (int*)(void*)readers->contents;

        for (u4 i = 0; i < readers->length; i++) {
            r1[i + 1] = r2[i];
        }
    }

    return r;
}

static ArrayObject* _encode_readers_from_stream(char* readers, int len) {
    ArrayObject* r;
    /* Allocate space for the readers vector */
    int count = len;
    r = dvmAllocPrimitiveArray('I', count + 1, ALLOC_DEFAULT);
    if (r == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return NULL;
    }

    /* First encode the size number of readers */
    int *r1 = (int*)(void*)r->contents;
    r1[0] = count;

    /* Copy contents from readers argument */
    for (int i = 0; i < count; i++) {
        readers = _agate_util_get_int(readers, r1 + i + 1);
    }
    return r;
}

/* General functions to work with  Policies: merge, create, delete, can flow.  */

/* 
 * Creates a policy for the given user_readers and group_readers ArrayObjects
 *
 *    The policy is allocated with the ALLOC_DEFAULT flag,
 *    which means that the allocation is tracked in the
 *    current thread reference table so it won't be GCed.
 *
 *    After the policy is saved inside an object or on the
 *    stack, it must be dvmReleaseTrack'ed.
 *
 * The policy object is a vector of policies (union of policies)
 *
 */

// TODO: vector of policy objects instead
PolicyObject* agate_create_policy(ArrayObject* user_readers, ArrayObject* group_readers)
{
    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);
    if (p == NULL) {
        ALOGE("AgateLog: [agate_create_policy] Could not allocate space for policy.");
        return NULL;
    }

    /* Encode user readers */
    p->user_readers = _encode_readers(user_readers);
    if (p->user_readers == NULL) {
        ALOGE("AgateLog: [agate_create_policy] Could not allocate space for user_readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return NULL;
    } else {
        // no need to track the allocation, p is already tracked and scanned by GC.
        dvmReleaseTrackedAlloc((Object*)p->user_readers, NULL);
    }

    /* Encode group readers */
    p->group_readers = _encode_readers(group_readers);
    if (p->group_readers == NULL) {
        ALOGE("AgateLog: [agate_create_policy] Could not allocate space for group_readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return NULL;
    } else {
        dvmReleaseTrackedAlloc((Object*)p->group_readers, NULL);
    }

    // TODO: make the same for writers
    return p;
}

PolicyObject* agate_create_policy_from_stream(char* readers)
{
    int size;

    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);
    if (p == NULL) {
        ALOGE("AgateLog: [agate_create_policy_from_stream] Could not allocate space for policy.");
        return NULL;
    }

    /* Encode user readers */
    readers = _agate_util_get_int(readers, &size);
    p->user_readers = _encode_readers_from_stream(readers, size);
    if (p->user_readers == NULL) {
        ALOGE("AgateLog: [agate_create_policy_from_stream] Could not allocate space for user_readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return NULL;
    } else {
        // no need to track the allocation, p is already tracked and scanned by GC.
        dvmReleaseTrackedAlloc((Object*)p->user_readers, NULL);
    }
    readers += size * sizeof(int);

    /* Encode group readers */
    readers = _agate_util_get_int(readers, &size);
    ALOGW("Group len = %d", size);
    p->group_readers = _encode_readers_from_stream(readers, size);
    if (p->group_readers == NULL) {
        ALOGE("AgateLog: [agate_create_policy_from_stream] Could not allocate space for group_readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return NULL;
    } else {
        dvmReleaseTrackedAlloc((Object*)p->group_readers, NULL);
    }

    // TODO: make the same for writers
    return p;
}

void agate_print_policy(int tag) {
    assert(tag != 0);
    PolicyObject* p = (PolicyObject*) tag;

    int* user_readers = (int*)(void*)p->user_readers->contents;

    ALOGE("AgateLog: [agate_print_policy] Policy = ");
    for(u4 i = 0; i < p->user_readers->length; i++)
        ALOGE("U_R:%d", user_readers[i]);
    int* group_readers = (int*)(void*)p->group_readers->contents;
    for(u4 i = 0; i < p->group_readers->length; i++)
        ALOGE("G_R:%d", group_readers[i]);
}

/* Un-tracks the policy, it will be GC'ed */
void agate_release_policy(int tag)
{
    ALOGW("AgateLog: [agate_release_policy] Releasing policy %p", (void*)tag);
    dvmReleaseTrackedAlloc((Object*) tag, NULL);
}


static ArrayObject* _merge_readers(ArrayObject* r1, ArrayObject* r2) {

    assert(r1 != NULL);
    assert(r2 != NULL);

    ArrayObject* r;
    u4 i;

    /* Allocate space for the readers vector */
    u4 count = r1->length + r2->length;
    r = dvmAllocPrimitiveArray('I', count, ALLOC_DEFAULT);

    if (r == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return NULL;
    }

    /* Simply concatenate the two vectors */
    int *r1_contents = (int*)(void*)r1->contents;
    int *r2_contents = (int*)(void*)r2->contents;
    int *r_contents = (int*)(void*)r->contents;

    count = 0;
    for (i = 0; i < r1->length; i++) {
        r_contents[count] = r1_contents[i];
        count++;
    }

    for (i = 0; i < r2->length; i++) {
        r_contents[count] = r2_contents[i];
        count++;
    }

    return r;
}


/* Merges two policies */
// TODO: check if existing sub-policies are subsets of other policies
int agate_merge_policies(int tag1, int tag2)
{
    if (tag1 == 0) {
        return tag2;
    }

    if (tag2 == 0) {
        return tag1;
    }

    if (tag1 == tag2) {
        return tag1;
    }

    PolicyObject* p1 = (PolicyObject*) tag1;
    PolicyObject* p2 = (PolicyObject*) tag2;

    /* Check if policies are equal */
    if ((p1->user_readers->length == p2->user_readers->length) &&
        (p1->group_readers->length == p2->group_readers->length) &&
        !memcmp(p1->user_readers->contents, p2->user_readers->contents, p1->user_readers->length * sizeof(int)) &&
        !memcmp(p1->group_readers->contents, p2->group_readers->contents, p1->group_readers->length * sizeof(int))) {
        return tag1;
    }


    /*
     * We perform the union (of user_readers and group_readers) of the two policies
     */

    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);
    if (p == NULL) {
        ALOGE("AgateLog: [agate_merge_policies] Could not allocate space for policy.");
        return 0;
    }

    /* Merge user readers */
    p->user_readers = _merge_readers(p1->user_readers, p2->user_readers);
    if (p->user_readers == NULL) {
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        ALOGE("AgateLog: [agate_merge_policies] Could not allocate space for merging user_readers.");
        return 0;
    } else {
        // no need to track the allocation, p is already tracked and scanned by GC.
        dvmReleaseTrackedAlloc((Object*)p->user_readers, NULL);
    }

    /* Merge group readers */
    p->group_readers = _merge_readers(p1->group_readers, p2->group_readers);
    if (p->group_readers == NULL) {
        ALOGE("AgateLog: [agate_merge_policies] Could not allocate space for merging group_readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return 0;
    } else {
        dvmReleaseTrackedAlloc((Object*)p->group_readers, NULL);
    }

    return (int) p; 
}

/* Checks if can flow from tag1 to tag2 */
//bool agate_can_flow(PolicyObject* fromPolicy, PolicyObject* toPolicy)
//{

    

//    return true;
    //if (fromPolicy == 0) {
    //    //ALOGI("can flow as no policy on data");
    //    return true;
    //}

    //if (toPolicy == 0) {
    //    //ALOGI("can't flow as target is not logged in");
    //    return false; 
    //}

    //assert(p1 != NULL);
    //assert(p2 != NULL);

    /*
     * Confidentiality check: Check if readers in _to_policy
     * are all included in the _from_policy
     */

    //int* fromReaders = (int*)(void*)fromPolicy->readers->contents;
    //int* toReaders = (int*)(void*)toPolicy->readers->contents;

    //ALOGI("AgateLog: [agate_can_flow] Complex can flow case, readers allowed to use data:");
    //for(u4 i = 0; i < fromPolicy->readers->length; i++) {
    //    ALOGI("%d", fromReaders[i]);
    //}

    //ALOGI("AgateLog: [agate_can_flow] Potential readers of data");
    //for(u4 i = 0; i < toPolicy->readers->length; i++) {
    //    ALOGI("%d", toReaders[i]);
    //}

    //bool result = true;
    //for (u4 i = 0; i < toPolicy->readers->length; i++) {
    //    result = false;

    //    // TODO: hard-coded ID
    //    if (toReaders[i] == 1) {
    //        // admin account is always a reader
    //        result = true;
    //        break;
    //    }

    //    for (u4 j = 0; j < fromPolicy->readers->length; j++) {
    //        if (toReaders[i] == fromReaders[j]) {
    //            result = true;
    //            break;
    //        }
    //    }
    //    if (result == false) {
    //        break;
    //    }
    //}

    //return result;
//}

/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* p)
{
    /* Don't add if no policy */
    if (p != NULL) {
        SocketTag* tmpT = (SocketTag*) malloc(sizeof(SocketTag));
        
        // pin the object to prevent the GC to collect it. (It is currently in
        // the thread's local ref table but the thread might die)
        pinObject((Object*)p);

        if (tmpT) {
            tmpT->policy = p;
            tmpT->fd = fd;

            //ALOGW("AgateLog: [agate_add_policy_on_socket] Trying to add 0x%08x on fd: %d", (u4)tmpT->policy, fd);
            dvmHashTableLock(gDvmAgate.socketPolicies);
            SocketTag* t = (SocketTag*) dvmHashTableLookup(gDvmAgate.socketPolicies, fd, tmpT, hashcmpSocketTags, true);
            if (t != tmpT) {
                // element already in the hash table
                t->policy = p;
                free(tmpT);
            }
            dvmHashTableUnlock(gDvmAgate.socketPolicies);
            ALOGW("AgateLog: [agate_add_policy_on_socket] added 0x%08x on fd: %d", (u4)t->policy, fd);
        } else {
            ALOGE("AgateLog: [agate_add_policy_on_socket] Could not allocate space for temporary SocketTag");
        }
    }
}

/* Retrieve the policy that has been set on a socket */
int agate_get_policy_on_socket(int fd)
{
    PolicyObject* p = 0;
    SocketTag* t;
    SocketTag* tmpT = (SocketTag*) malloc(sizeof(SocketTag));

    if (tmpT) {
        tmpT->policy = NULL;
        tmpT->fd = fd;

        //ALOGW("AgateLog: [agate_get_policy_on_socket] Trying to get policy from fd: %d", fd);
        dvmHashTableLock(gDvmAgate.socketPolicies);
        t = (SocketTag*) dvmHashTableLookup(gDvmAgate.socketPolicies, fd, tmpT, hashcmpSocketTags, false);
        dvmHashTableUnlock(gDvmAgate.socketPolicies);
        free(tmpT);
    } else {
        ALOGE("AgateLog: [agate_get_policy_on_socket] Could not allocate space for temporary SocketTag");
        return 0;
    }

    if (t != NULL) {
        p = t->policy;
    } else {
            //ALOGI("AgateLog: [agate_get_policy_on_socket] tried to get policy on socket without policy set fd:%d", fd);
    }

    if (p) {
        ALOGW("AgateLog: [agate_get_policy_on_socket(%d)] = 0x%08x", fd, (u4)p);
        agate_print_policy((int)p);
    }

    return (int)p;
}

/* Remove the policy from the socket */
void agate_remove_policy_from_socket(int fd)
{
    SocketTag* t;
    SocketTag* tmpT = (SocketTag*) malloc(sizeof(SocketTag));
    
    if (tmpT) {
        tmpT->policy = NULL;
        tmpT->fd = fd;

        dvmHashTableLock(gDvmAgate.socketPolicies);
        t = (SocketTag*) dvmHashTableLookup(gDvmAgate.socketPolicies, fd, tmpT, hashcmpSocketTags, false);

        if (t != NULL) {
            agate_release_policy((int)t->policy);
            dvmHashTableRemove(gDvmAgate.socketPolicies, fd, t);
            ALOGW("AgateLog: [agate_remove_policy_from_socket] Removing policy: %p; socket = %d", (void*)t->policy, fd);
            free(t);
        }
        dvmHashTableUnlock(gDvmAgate.socketPolicies);
        free(tmpT);
    } else { 
        ALOGE("AgateLog: [agate_remove_policy_from_socket] Could not allocate space for temporary SocketTag");
    }
}

static char* _add_readers_stream(char* s, ArrayObject* readers) {
    s = _agate_util_add_int(s, readers->length);
 
    for (u4 i = 0; i < readers->length; i++) {
        s = _agate_util_add_int(s, ((int*)(void*)readers->contents)[i]);
    }
    return s;
}

static char* _get_readers_from_stream(char* s, ArrayObject** r) {
    u4 r_len;
    s = _agate_util_get_int(s, (int*)&r_len); // get size of reader stream

    /* Allocate space for the reader's vector */
    *r = dvmAllocPrimitiveArray('I', r_len, ALLOC_DEFAULT);
    if (r == NULL) {
        ALOGE("AgateLog: [_get_readers_from_stream] Could not allocate space for readers.");
        return NULL;
    }

    /* Copy contents from readers argument */
    for (u4 i = 0; i < r_len; i++) {
        s = _agate_util_get_int(s, (int*)(void*)(*r)->contents + i);
        //ALOGW("AgateLog: [agateJniDecodePolicy] Reader: %d", (int)(int*)(void*)p->readers->contents[i]);
    }

    return s;
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
char* agate_encode_policy(int* size, int tag) {
    PolicyObject* p = (PolicyObject*) tag;
    if(p == NULL) {
        char* out = (char*)malloc(sizeof(int));
	_agate_util_add_int(out, 0);    // policy has size 0
 	*size = sizeof(int); // total length of stream has 4 bytes
        return out;
    }

    /* Compute total length of the serialized policy */
    u4 p_size = (p->user_readers->length + p->group_readers->length) * sizeof(u4) + 2 * sizeof(u4);

    /* Allocate memory */
    char* bytes = (char*)malloc(p_size + sizeof(int));

    /*
     *  Add the policy as a continuous stream
     */
    char* q = _agate_util_add_int(bytes, p_size); // TODO: add u4, but it's ok because sizeof(u4) = sizeof(int)

    /* Add user readers and group_readers */
    q = _add_readers_stream(q, p->user_readers);
    q = _add_readers_stream(q, p->group_readers);

    // TODO: add writers
    *size = p_size + sizeof(int); // total length of stream 
    return bytes;
}

/*
 * De-codes a policy from a stream of bytes (De-serialization)
 */
int agate_decode_policy(char* s) {
    // TODO: for now only the readers

    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);
    if (p == NULL) {
        ALOGE("AgateLog: [agateJniDecodePolicy] Could not allocate space for policy.");
        return 0;
    }

    s = _get_readers_from_stream(s, &p->user_readers);
    if (p->user_readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        ALOGE("AgateLog: [agateJniDecodePolicy] Could not allocate space for user readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return 0;
    } else {
        // no need to track the allocation, p is already tracked and scanned.
        dvmReleaseTrackedAlloc((Object*)p->user_readers, NULL);
    }

    s = _get_readers_from_stream(s, &p->group_readers);
    if (p->group_readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        ALOGE("AgateLog: [agateJniDecodePolicy] Could not allocate space for group readers.");
        dvmReleaseTrackedAlloc((Object*)p, NULL);
        return 0;
    } else {
        // no need to track the allocation, p is already tracked and scanned.
        dvmReleaseTrackedAlloc((Object*)p->group_readers, NULL);
    }

    ALOGW("Decoded policy: ");
    agate_print_policy((int)p);

    return (int)p;
}


/* Functions working on Tags */

/* function of type HashCompareFunc */
int hashcmpSocketTags(const void* p1, const void* p2)
{
    SocketTag* t1 = (SocketTag*) p1;
    SocketTag* t2 = (SocketTag*) p2;
    return t1->fd - t2->fd;
}

/* function of type HashFreeFunc */
void freeSocketTag(void* t)
{
    SocketTag* tag = (SocketTag*) t;
    agate_release_policy((int)tag->policy);
    if (tag != NULL) {
	free(tag);
    }
}

/* function of type HashUpdateFunc */
void hashupdateSocketTag(const void* oldTag, const void* newTag)
{
    ALOGW("Replacing a socket tag.");
    /* Just replace the old one. No need to merge multiple policies on a socket
     * (assume connection to one entity) */
    SocketTag* o = (SocketTag*) oldTag;
    SocketTag* n = (SocketTag*) newTag;

    assert(n != NULL);
    assert(o != NULL);

    agate_release_policy((int)o->policy);
    o->policy = n->policy;
}
