#ifndef _DALVIK_AGATE_POLICY
#define _DALVIK_AGATE_POLICY

#include "Dalvik.h"

#include <set>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

#define AGATE_SOCKET_POLICIES_TABLE_SIZE 32 /* number of sockets */
#define AGATE_TAG_POLICIES_TABLE_SIZE 32 /* number of policies */

/* The structure of a policy.
 *
 * Currently, a policy is defined in terms of User principals. A User
 * principal has a unique userId. 
 *
 *  We define PolicyObjects as Objects and take advantage
 *  of the GC to deallocate them when they are no longer
 *  in scope, like normal Java Objects.
 *
 *  The PolicyObject is not really an Object because they have no
 *  class to define the layout of its fields in memory (po->clazz is NULL).
 *  Therefore we need to modify a bit the GC to tell it how to scan
 *  these objects (right now the GC relies on the fact that each Object
 *  it needs to garbage collect has the class field set).
 *
 *  The ClassObject member of the ArrayObject* of ints is allocated just once
 *  and is already initialized, so the policy will still not consume much space.
 */
// TODO: find out why there is a lock inside the Object struct
struct PolicyObject : Object {
    ArrayObject* readers;  // array of int ids that specify who can read the data
                           // tagged with this policy
    ArrayObject* writers;  // array of ids that specify who can write the data
                           // tagged with this policy
};


/* Creates a policy for the given reader/writer vectors */
PolicyObject* agate_create_policy(ArrayObject* readers, ArrayObject* writers);
/* Prints the given policy */
void agate_print_policy(PolicyObject* p);
/* Un-tracks a policy */
void agate_release_policy(int tag);
/* Merges two policies */
int agate_merge_policies(int tag1, int tag2);
/* Policy flow check */
bool agate_can_flow(PolicyObject* p1, PolicyObject* p2);
/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* p);
/* Retrieve the policy that has been set on a socket */
PolicyObject* agate_get_policy_on_socket(int fd);


/* A Tag is a pointer to a policy. */
typedef struct Tag {
    PolicyObject* policy;
} Tag;

/* function of type HashCompareFunc */
int hashcmpTags(const void* p1, const void* p2);
/* function of type HashFreeFunc */
void freeTag(void* t);
/* function of type HashUpdateFunc */
void hashupdateTag(const void* oldTag, const void* newTag);

#endif /*_DALVIK_AGATEi_POLICY */
