#ifndef _DALVIK_AGATE_POLICY
#define _DALVIK_AGATE_POLICY

#include "Dalvik.h"

#include <set>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

#define AGATE_SOCKET_POLICIES_TABLE_SIZE 1024 /* number of sockets */
//#define AGATE_TAG_POLICIES_TABLE_SIZE 32 /* number of policies */

# define AGATE_MERGE_POLICIES(_tag1, _tag2) ({ \
    timeval start, stop; \
    gettimeofday(&start, 0); \
    u4 r = _tag1?(_tag2?agate_merge_policies(_tag1, _tag2):_tag1):_tag2; \
    gettimeofday(&stop, 0); \
    long elapsed = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec; \
    if (r != 0 && r!= _tag1 && r!= _tag2) \
        ALOGE("Merged complex policies in: %ld ns", elapsed); \
    r; })


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
    ArrayObject* user_readers;  // array of int ids that specify what users can read the data
                                // tagged with this policy
    ArrayObject* group_readers; // array of ids that specify what groups can write the data
                                // tagged with this policy
};


/* Creates a policy for the given reader/writer vectors */
PolicyObject* agate_create_policy(ArrayObject* user_readers, ArrayObject* group_readers);
PolicyObject* agate_create_policy_from_stream(char* readers);
/* Prints the given policy */
void agate_print_policy(int tag);
/* Un-tracks a policy */
void agate_release_policy(int tag);
/* Merges two policies */
int agate_merge_policies(int tag1, int tag2);

///* Policy flow check */
//bool agate_can_flow(PolicyObject* p1, PolicyObject* p2);

/* Add a policy on a socket */
void agate_add_policy_on_socket(int fd, PolicyObject* p);
/* Remove the policy from a socket */
void agate_remove_policy_from_socket(int fd);
/* Retrieve the policy that has been set on a socket */
int agate_get_policy_on_socket(int fd);
/* Encodes a policy as a stream of bytes */
char* agate_encode_policy(int* size, int tag);
/* Decodes a policy from a stream of bytes */
int agate_decode_policy(char* s);

/* A SocketTag is a mapping between a policy and a socket fd. */
typedef struct SocketTag {
    PolicyObject* policy;
    int fd;
} SocketTag;

/* function of type HashCompareFunc */
int hashcmpSocketTags(const void* p1, const void* p2);
/* function of type HashFreeFunc */
void freeSocketTag(void* t);
/* function of type HashUpdateFunc */
void hashupdateSocketTag(const void* oldTag, const void* newTag);

#endif /*_DALVIK_AGATE_POLICY */
