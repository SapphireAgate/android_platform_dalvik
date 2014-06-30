
#ifndef _DALVIK_AGATE_POLICY
#define _DALVIK_AGATE_POLICY

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
u4 agate_create_policy(ArrayObject* readers, ArrayObject* writers);
/* De-allocates a policy */
void agate_delete_policy(u4 tag);
/* Checks if there are no more references to this policy, in
 * which case it deletes the policy */
void agate_free_policy(u4 tag);
/* Merges two policies */
u4 agate_merge_policies(u4 tag1, u4 tag2);
/* Policy flow check  */
bool agate_can_flow(u4 tag1, u4 tag2);
/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, u4 tag);
/* Retrieve the policy that has been set on a socket */
u4 agate_get_policy_on_socket(int fd);


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

#endif /*_DALVIK_AGATEi_POLICY */
