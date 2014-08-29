#include "Dalvik.h"
#include "agate/AgatePolicy.h"

#include <set>
#include <algorithm>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

/* General functions to work with  Policies: merge, create, delete, can flow.  */

/* 
 * Creates a policy for the given reader/writer ArrayObjects
 *
 *    The policy is allocated with the ALLOC_DEFAULT flag,
 *    which means that the allocation is tracked in the
 *    current thread reference table so it won't be GCed.
 *
 *    After the policy is saved inside an object or on the
 *    stack, it must be dvmReleaseTrack'ed.
 */
PolicyObject* agate_create_policy(ArrayObject* readers, ArrayObject* writers)
{
    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);

    /* Allocate space for the reader's vector */
    // no need to track the allocation, p is already tracked and scanned.
    p->readers = dvmAllocPrimitiveArray('I', readers->length, ALLOC_DEFAULT);
    dvmReleaseTrackedAlloc((Object*)p->readers, NULL);

    if (p->readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return NULL;
    }

    int *r1 = (int*)(void*)p->readers->contents;
    int *r2 = (int*)(void*)readers->contents;

    /* Copy contents from readers argument */
    for (u4 i = 0; i < readers->length; i++) {
        r1[i] = r2[i];
    }

    // TODO: make the same for writers
    return p;
}

void agate_print_policy(PolicyObject* p) {
    assert(p != NULL);

    int* readers = (int*)(void*)p->readers->contents;

    ALOGE("AgateLog: [agate_print_policy] Policy = ");
    for(u4 i = 0; i < p->readers->length; i++)
        ALOGE("R:%d", readers[i]);
}


/* Un-tracks the policy, it will be GC'ed */
void agate_release_policy(int tag)
{
    ALOGW("AgateLog: [agate_release_policy] Releasing policy %p", (void*)tag);
    dvmReleaseTrackedAlloc((Object*) tag, NULL);
}

/* Merges two policies */
int agate_merge_policies(int tag1, int tag2)
{
    PolicyObject* p1 = (PolicyObject*) tag1;
    PolicyObject* p2 = (PolicyObject*) tag2;

    if (p1 == NULL) {
        return tag2;
    }

    if (p2 == NULL) {
        return tag1;
    }

    if (p1 == p2) {
        return tag1;
    }

    /*
     * Confidentiality merge: Computes intersection of
     * readers.
     */
	//ALOGE("Non trivial merge between %p and %p",p1,p2);
    int* r1 = (int*)(void*)p1->readers->contents;
    u4 n_r1 = p1->readers->length;
    int* r2 = (int*)(void*)p2->readers->contents;
    u4 n_r2 = p2->readers->length;

    u4 n_r = 0;
    // compute intersection in m
    int* m = (int*) malloc(sizeof(u4) * ((n_r1 < n_r2)? n_r1 : n_r2));

    for (u4 i = 0; i < n_r1; i++) {
        for (u4 j = 0; j < n_r2; j++) {
            if (r1[i] == r2[j]) {
                m[n_r++] = r1[i];
                break;
            }
        }
    }

    /* Allocate space for a new policy */
    PolicyObject* p = (PolicyObject*) dvmMalloc(sizeof(PolicyObject), ALLOC_DEFAULT);

    /* Allocate space for the reader's vector */
    // no need to track the allocation, p is already tracked and scanned.
    p->readers = dvmAllocPrimitiveArray('I', n_r, ALLOC_DEFAULT);
    dvmReleaseTrackedAlloc((Object*) p->readers, NULL); 

    for (u4 i = 0; i < n_r; i++) {
        ((int*)(void*)p->readers->contents)[i] = m[i];
    }

    return (int) p; 
}

/* Checks if can flow from tag1 to tag2 */
bool agate_can_flow(PolicyObject* fromPolicy, PolicyObject* toPolicy)
{
    if (fromPolicy == 0) {
        //ALOGI("can flow as no policy on data");
        return true;
    }

    if (toPolicy == 0) {
        //ALOGI("can't flow as target is not logged in");
        return false; 
    }

    assert(p1 != NULL);
    assert(p2 != NULL);

    /*
     * Confidentiality check: Check if readers in _to_policy
     * are all included in the _from_policy
     */

    int* fromReaders = (int*)(void*)fromPolicy->readers->contents;
    int* toReaders = (int*)(void*)toPolicy->readers->contents;

    ALOGI("AgateLog: [agate_can_flow] Complex can flow case, readers allowed to use data:");
    for(u4 i = 0; i < fromPolicy->readers->length; i++) {
        ALOGI("%d", fromReaders[i]);
    }

    ALOGI("AgateLog: [agate_can_flow] Potential readers of data");
    for(u4 i = 0; i < toPolicy->readers->length; i++) {
        ALOGI("%d", toReaders[i]);
    }

    bool result = true;
    for (u4 i = 0; i < toPolicy->readers->length; i++) {
        result = false;

        // TODO: hard-coded ID
        if (toReaders[i] == 1) {
            // admin account is always a reader
            result = true;
            break;
        }

        for (u4 j = 0; j < fromPolicy->readers->length; j++) {
            if (toReaders[i] == fromReaders[j]) {
                result = true;
                break;
            }
        }
        if (result == false) {
            break;
        }
    }

    return result;
}

/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* p)
{
    /* Don't add if no policy */
    if (p != NULL) {
        SocketTag* tmpT = (SocketTag*) malloc(sizeof(SocketTag));
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
    }

    if (t != NULL) {
        p = t->policy;
    } else {
            //ALOGI("AgateLog: [agate_get_policy_on_socket] tried to get policy on socket without policy set fd:%d", fd);
    }

    if (p) {
        ALOGW("AgateLog: [agate_get_policy_on_socket(%d)] = 0x%08x", fd, (u4)p);
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
