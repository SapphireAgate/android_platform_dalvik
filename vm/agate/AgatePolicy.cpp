#include "Dalvik.h"
#include "agate/AgatePolicy.h"

#include <set>
#include <algorithm>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

/* Functions working on Policies */

/* Creates a policy for the given reader/writer vectors */
u4 agate_create_policy(ArrayObject* readers, ArrayObject* writers)
{
    /* Allocate space for a new policy */
    Policy* p = (Policy*) malloc(sizeof(Policy));
    p->readers = new std::set<std::string>();
    //p->writers = new std::set<std::string>();
    p->no_references = 1;

    /* Copy the readers into the newly allocated policy */
    Object** _readers = (Object**)(void*)readers->contents;
    for (u4 i = 0; i < readers->length; i++) {
        StringObject* s = (StringObject*) _readers[i];
        std::string str(dvmCreateCstrFromString(s)); //TODO: this seems redundant - 2Xcopy
        p->readers->insert(str); // makes a copy of str
    }

    return (u4)p;
}

/* De-allocates a policy */
void agate_delete_policy(u4 tag)
{
    Policy* p = (Policy*) tag;

    p->readers->clear(); // calls destructor on std::string elements inside
                         // this vector
    delete p->readers;   // deallocate memory

    //p->writers->clear();
    //delete p->writers;

    free(p);
}

/* Checks if there are no more references to this policy, in
 * which case it deletes the policy */
void agate_free_policy(u4 tag)
{
    Policy* p = (Policy*) tag;
    if (android_atomic_dec(&(p->no_references)) == 1) {
         agate_delete_policy(tag);
    }
}

/* Merges two policies */
u4 agate_merge_policies(u4 tag1, u4 tag2)
{
    Policy* p1 = (Policy*) tag1;
    Policy* p2 = (Policy*) tag2;

    std::set<std::string> r1 = *(p1->readers);
    std::set<std::string> r2 = *(p2->readers);

    /*
     * Confidentiality merge: Computes intersection of
     * readers.
     */
    Policy* p = (Policy*) malloc(sizeof(Policy));
    std::set<std::string>* readers = new std::set<std::string>();
    p->readers = readers;
    p->no_references = 1;

    std::set<std::string> r = *(p->readers);
    
    std::set_intersection(r1.begin(), r1.end(), r2.begin(), r2.end(),
                  std::inserter(r, r.begin()));

    return (u4)p;    
}

/* Checks if can flow from tag1 to tag2 */
bool agate_can_flow(u4 tag1, u4 tag2)
{
    Policy* fromPolicy = (Policy*) tag1;
    Policy* toPolicy = (Policy*) tag2;
    bool result;

    ALOGW("AgateLog: canFlow");

    /* TODO: Hack! If no policy */
    if (fromPolicy == NULL || toPolicy == NULL) {
        return true;
    }

    /*
     * Confidentiality check: Check if readers in source policy
     * include all readers in the destination policy.
     */

    std::set<std::string> fromReaders = *(fromPolicy->readers);
    std::set<std::string> toReaders = *(toPolicy->readers);

    result = std::includes(fromReaders.begin(), fromReaders.end(),
                  toReaders.begin(), toReaders.end());

    return result;
}


/* Functions working on Tags */

/* function of type HashCompareFunc */
int hashcmpTags(const void* p1, const void* p2)
{
    Tag* t1 = (Tag*) p1;
    Tag* t2 = (Tag*) p2;
    return (u4) t1->tag - (u4) t2->tag;
}

/* function of type HashFreeFunc */
void freeTag(void* t)
{
    Tag* tag = (Tag*) t;
    agate_free_policy(tag->tag);
    if (tag != NULL) {
	free(tag);
    }
}

/* function of type HashUpdateFunc */
void hashupdateTag(const void* oldTag, const void* newTag)
{
    Tag* o = (Tag*) oldTag;
    Tag* n = (Tag*) newTag;

    // merge the two policies
    u4 m = agate_merge_policies(o->tag, n->tag);
    agate_free_policy(o->tag);
    agate_free_policy(n->tag); // TODO: check this

    o->tag = m;

    free(n);
}
