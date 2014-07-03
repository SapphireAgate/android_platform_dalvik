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
    p->n_r = readers->length;
    p->readers = (u4*)dvmMalloc(sizeof(u4) * p->n_r, ALLOC_DONT_TRACK);

    if (p->readers == NULL) {
        // Probably OOM.
        assert(dvmCheckException(dvmThreadSelf()));
        return 0;
    }

    /* Copy contents from readers argument */
    for (u4 i = 0; i < p->n_r; i++) {
        p->readers[i] = ((u4*)(void*)(readers)->contents)[i];
    }

    // TODO: make the same for writers
    return p;
}

void agate_print_policy(PolicyObject* p) {
    assert(p != NULL);

    u4* readers = p->readers;

    ALOGE("AgateLog: [agate_print_policy] Policy = ");
    for(u4 i = 0; i < p->n_r; i++)
        ALOGE("R:%d", readers[i]);
}


/* Un-tracks the policy, it will be GC'ed */
void agate_release_policy(PolicyObject* p)
{
    dvmReleaseTrackedAlloc((Object*) p, NULL);
}

/* Merges two policies */
PolicyObject* agate_merge_policies(PolicyObject* p1, PolicyObject* p2)
{
    assert(p1 != NULL);
    assert(p2 != NULL);

    /*
     * Confidentiality merge: Computes intersection of
     * readers.
     */

    u4* r1 = p1->readers;
    u4 n_r1 = p1->n_r;
    u4* r2 = p2->readers;
    u4 n_r2 = p2->n_r;
 
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
    p->n_r = n_r;
    p->readers = (u4*) dvmMalloc(sizeof(u4) * n_r, ALLOC_DONT_TRACK);

    for (u4 i = 0; i < n_r; i++) {
        p->readers[i] = m[i];
    }

    return p; 
}

/* Checks if can flow from tag1 to tag2 */
bool agate_can_flow(PolicyObject* fromPolicy, PolicyObject* toPolicy)
{
    assert(p1 != NULL);
    assert(p2 != NULL);


    /* TODO: Hack! If no policy */
    //if (fromPolicy == NULL || toPolicy == NULL) {
    //    return true;
    //}

    /*
     * Confidentiality check: Check if readers in source policy
     * include all readers in the destination policy.
     */

    u4* fromReaders = fromPolicy->readers;
    u4* toReaders = toPolicy->readers;

    bool result = true;
    for (u4 i = 0; i < toPolicy->n_r; i++) {
        result = false;
        for (u4 j = 0; j < fromPolicy->n_r; j++) {
            if (toReaders[i] == fromReaders[j]) {
                result = true;
                break;
            }
        }
        if (result == false)
            break;
    }
 
    return result;
}

/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* p)
{
    Tag* tmpT = (Tag*) malloc(sizeof(Tag));
    tmpT->policy = p;

    if (tmpT) {
        dvmHashTableLock(gDvmAgate.socketPolicies);
        dvmHashTableLookupAndUpdate(gDvmAgate.socketPolicies, fd, tmpT,
                                    hashcmpTags, hashupdateTag, true);
        ALOGI("AgateLog: [addPolicySocket(%d)] adding 0x%08x",
                fd, (u4)tmpT->policy);
        dvmHashTableUnlock(gDvmAgate.socketPolicies);
    }
}

/* Retrieve the policy that has been set on a socket */
PolicyObject* agate_get_policy_on_socket(int fd)
{
    PolicyObject* p = 0;

    dvmHashTableLock(gDvmAgate.socketPolicies);
    Tag* t = (Tag*) dvmHashMapLookup(gDvmAgate.socketPolicies, fd);

    if (t != NULL)
        p = t->policy;

    dvmHashTableUnlock(gDvmAgate.socketPolicies);

    if (p) {
        ALOGI("AgateLog: [getPolicySocket(%d)] = 0x%08x", fd, (u4)p);
    }

    return p;
}

/* Functions working on Tags */

/* function of type HashCompareFunc */
int hashcmpTags(const void* p1, const void* p2)
{
    Tag* t1 = (Tag*) p1;
    Tag* t2 = (Tag*) p2;
    return (u4) t1->policy - (u4) t2->policy;
}

/* function of type HashFreeFunc */
void freeTag(void* t)
{
    Tag* tag = (Tag*) t;
    //agate_release_policy(tag->tag);
    if (tag != NULL) {
	free(tag);
    }
}

/* function of type HashUpdateFunc */
void hashupdateTag(const void* oldTag, const void* newTag)
{
    Tag* o = (Tag*) oldTag;
    Tag* n = (Tag*) newTag;

    assert(n != NULL);
    assert(o != NULL);
    
    // merge the two policies TODO: check of NULL; check if can free ...
    PolicyObject* m = agate_merge_policies(o->policy, n->policy);
    //agate_free_policy(o->tag);
    //agate_free_policy(n->tag); // TODO: check this

    o->policy = m;

    free(n);
}
