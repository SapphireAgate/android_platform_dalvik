#ifndef _DALVIK_AGATE_POLICY
#define _DALVIK_AGATE_POLICY

#include "Dalvik.h"

#include <set>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

#define AGATE_SOCKET_POLICIES_TABLE_SIZE 32 /* number of sockets */
#define AGATE_TAG_POLICIES_TABLE_SIZE 32 /* number of policies */

#define AGATE_OBJECT_TYPE_POLICY            1
#define AGATE_OBJECT_TYPE_POLICY_INT_ARRAY  2

/* The structure of a policy.
 *
 * A policy is a collection of Readersets and Writersets
 * anyone in all Readersets can read the data
 * anyone in any Writerset has written the data
 *
 * currenlty writers are not tracked, and thus are not in the data structure
 */

// a readerset is an ArrayObject of length 2
// r[0] an ArrayObject of users in the set (represented by userid)
// and r[1] an ArraybObject of groups in the set (represented by groupid)

//a policy is an ArrayObject of readersets
typedef ArrayObject PolicyObject;

/* Creates a policy for the given reader/writer vectors */
PolicyObject* agate_create_policy(ArrayObject* userReaders, ArrayObject* writers); //temporary to keep old interface
PolicyObject* agate_create_policy_g(ArrayObject* userReaders, ArrayObject* groupReaders, ArrayObject* writers);

/* Merges two policies */
u4 agate_merge_policies(u4 tag1, u4 tag2);

/* Policy flow check  */
bool agate_can_flow(PolicyObject* tag1, PolicyObject* tag2);

/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* tag);

/* Get the policy on a socket */
PolicyObject* agate_get_policy_on_socket(int fd);

typedef struct {
	PolicyObject* policy;
} Tag;

/* function of type HashCompareFunc */
int hashcmpTags(const void* p1, const void* p2);
/* function of type HashFreeFunc */
void freeTag(void* t);
/* function of type HashUpdateFunc */
void hashupdateTag(const void* oldTag, const void* newTag);

#endif /*_DALVIK_AGATEi_POLICY */
