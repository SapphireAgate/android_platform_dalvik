
#ifndef _DALVIK_AGATE_PRIV
#define _DALVIK_AGATE_PRIV

#include "Dalvik.h"

#include <set>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

#define AGATE_SOCKET_POLICIES_TABLE_SIZE 32 /* number of sockets */
#define AGATE_TAG_POLICIES_TABLE_SIZE 32 /* number of policies */


/* The Policy structure.
 *
 * Currently, a policy is defined in terms of User principals. A User
 * principal has a unique username. 
 */
typedef struct Policy {
    std::set<std::string>* readers;   // ordered set of readers (for now) Users (will be Groups)
    std::set<std::string>* writers;   // ordered set of writers (for now) Users (will be Groups)
    volatile int32_t no_references;   // number of references to this policy (useful for GC)
} Policy;

/* Creates a policy for the given reader/writer vectors */
u4 _create_policy(ArrayObject* readers, ArrayObject* writers);
/* De-allocates a policy */
void _delete_policy(u4 tag);
/* Checks if there are no more references to this policy, in
 * which case it deletes the policy */
void _free_policy(u4 tag);
/* Merges two policies */
u4 _merge_policies(u4 tag1, u4 tag2);


/* A Tag is a pointer to a policy. */
typedef struct Tag {
    u4 tag;
} Tag;

/* function of type HashCompareFunc */
int hashcmpTags(const void* p1, const void* p2);
/* function of type HashFreeFunc */
void freeTag(void* t);
/* function of type HashUpdateFunc */
void hashupdateTag(const void* oldTag, const void* newTag);

#endif /*_DALVIK_AGATEi_PRIV */
