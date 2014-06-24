#include "Dalvik.h"
#include "agate/AgatePriv.h"

#include <set>
#include <algorithm>
#include <string>
#include <cutils/atomic.h> /* use common Android atomic ops */

/* Functions working on Policies */

/* Creates a policy for the given reader/writer vectors */
u4 _create_policy(ArrayObject* readers, ArrayObject* writers)
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
void _delete_policy(u4 tag)
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
void _free_policy(u4 tag)
{
    Policy* p = (Policy*) tag;
    if (android_atomic_dec(&(p->no_references)) == 1) {
         _delete_policy(tag);
    }
}

/* Merges two policies */
u4 _merge_policies(u4 tag1, u4 tag2)
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
    _free_policy(tag->tag);
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
    u4 m = _merge_policies(o->tag, n->tag);
    _free_policy(o->tag);
    _free_policy(n->tag); // TODO: check this

    o->tag = m;

    free(n);
}
