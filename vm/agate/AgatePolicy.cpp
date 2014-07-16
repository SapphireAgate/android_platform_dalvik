#include "Dalvik.h"
#include "agate/AgatePolicy.h"

#include <set>
#include <algorithm>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

/* General functions to work with  Policies: merge, create, delete, can flow.  */

/* Creates a policy for the given reader/writer vectors */
PolicyObject* agate_create_policy(ArrayObject* userReaders, ArrayObject* writers)
{
	return agate_create_policy_g(userReaders, NULL, writers);
}
PolicyObject* agate_create_policy_g(ArrayObject* userReaders, ArrayObject* groupReaders, ArrayObject* writers)
{
	// Create readerset
	int userReaderCount = 0;
	if(userReaders != NULL)
		userReaderCount = userReaders->length;
	ArrayObject* uReaders = dvmAllocPrimitiveArray('I', userReaderCount, 0);

	int groupReaderCount = 0;
	if(groupReaders != NULL)
		groupReaderCount = groupReaders->length;
	ArrayObject* gReaders = dvmAllocPrimitiveArray('I', groupReaderCount, 0);

	ClassObject* readersetclazz = dvmFindArrayClassForElement(uReaders->clazz);
	ArrayObject* readerset = dvmAllocArrayByClass(readersetclazz, 2, 0);

	// copy data into uReader and gReaders
	for(int i = 0; i < userReaderCount; i++) {
		((int*)uReaders->contents)[i] = ((int*)uReaders)[i];
	}
	for(int i = 0; i < groupReaderCount; i++) {
		((int*)gReaders->contents)[i] = ((int*)gReaders)[i];
	}
	((ArrayObject**)readerset->contents)[0] = uReaders;
	((ArrayObject**)readerset->contents)[1] = gReaders;
	dvmReleaseTrackedAlloc((Object *)uReaders, NULL);
	dvmReleaseTrackedAlloc((Object *)gReaders, NULL);

    // Allocate space for a new policy
	ClassObject* policyclazz = dvmFindArrayClassForElement(readerset->clazz);
	ArrayObject* p = dvmAllocArrayByClass(policyclazz, 1, ALLOC_DONT_TRACK);

	((ArrayObject**)p->contents)[0] = readerset;
	dvmReleaseTrackedAlloc((Object *)readerset, NULL);

    return p;
}

/* Merges two policies */
u4 agate_merge_policies(u4 tag1, u4 tag2)
{
	if(tag1 == (u4)NULL)
		return tag2;

	if(tag2 == (u4)NULL)
		return tag1;

	if(tag1 == tag2)
		return tag1;

	ALOGI("AgateLog: [mergePolicies] merging non-trival policies");

    ArrayObject* p1 = (ArrayObject*) tag1;
    ArrayObject* p2 = (ArrayObject*) tag2;

	int p1Count = p1->length;
	int p2Count = p2->length;
	ArrayObject* p = dvmAllocArrayByClass(p1->clazz, p1Count + p2Count, ALLOC_DONT_TRACK);

	for(int i = 0; i < p1Count; i++) {
		((ArrayObject*)p->contents)[i] = ((ArrayObject*)p1->contents)[i];
	}

	for(int i = 0; i < p2Count; i++) {
		((ArrayObject*)p->contents)[p1Count + i] = ((ArrayObject*)p2->contents)[i];
	}

    return (u4)p;
}

/* Checks if can flow from tag1 to tag2 */
bool agate_can_flow(PolicyObject* fromPolicy, PolicyObject* toPolicy)
{
	return true;
/*
    assert(p1 != NULL);
    assert(p2 != NULL);
*/
    /*
     * Confidentiality check: Check if readers in source policy
     * include all readers in the destination policy.
     */
/*
    int* fromReaders = (int*)(void*)fromPolicy->readers->contents;
    int* toReaders = (int*)(void*)toPolicy->readers->contents;

    bool result = true;
    for (u4 i = 0; i < toPolicy->readers->length; i++) {
        result = false;
        for (u4 j = 0; j < fromPolicy->readers->length; j++) {
            if (toReaders[i] == fromReaders[j]) {
                result = true;
                break;
            }
        }
        if (result == false)
            break;
    }
 
    return result;
*/
}

/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* p)
{
	Tag* tag = (Tag*) malloc(sizeof(Tag));
	if(tag == NULL) {
		ALOGE("AgateLog: [addPolicySocket(%d)] failed, out of memory",fd);
	}

	dvmAddTrackedAlloc((Object *)p, NULL);

    dvmHashTableLock(gDvmAgate.socketPolicies);
    dvmHashTableLookupAndUpdate(gDvmAgate.socketPolicies, fd, tag,
                                hashcmpTags, hashupdateTag, true);
    ALOGI("AgateLog: [addPolicySocket(%d)] adding 0x%08x",
            fd, p);
    dvmHashTableUnlock(gDvmAgate.socketPolicies);
}

/* Retrieve the policy that has been set on a socket */
PolicyObject* agate_get_policy_on_socket(int fd)
{
    dvmHashTableLock(gDvmAgate.socketPolicies);
    Tag* t = (Tag*) dvmHashMapLookup(gDvmAgate.socketPolicies, fd);

    dvmHashTableUnlock(gDvmAgate.socketPolicies);

	PolicyObject* p = t->policy;

    if (p) {
        ALOGI("AgateLog: [getPolicySocket(%d)] = 0x%08x", fd, (u4)p);
    }

    return p;
}

/* Functions working on Tags */

/* function of type HashCompareFunc */
int hashcmpTags(const void* p1, const void* p2)
{
	Tag* t1 = (Tag*)p1;
	Tag* t2 = (Tag*)p2;
    return (u4) t1->policy - (u4) t2->policy;
}

/* function of type HashFreeFunc */
void freeTag(void* t)
{
	Tag* tag = (Tag*)t;
	dvmReleaseTrackedAlloc((Object *) (tag->policy), NULL);
	free(tag);
}

/* function of type HashUpdateFunc */
void hashupdateTag(const void* oldTag, const void* newTag)
{
    Tag* o = (Tag*) oldTag;
    Tag* n = (Tag*) newTag;

    assert(n != NULL);
    assert(o != NULL);

    // merge the two policies
    u4 m = agate_merge_policies((u4) o->policy, (u4) n->policy);

    o->policy = (PolicyObject*)m;
}
