
#ifndef _DALVIK_AGATE_PRIV
#define _DALVIK_AGATE_PRIV

#include "Dalvik.h"

#define AGATE_SOCKET_POLICIES_TABLE_SIZE 32 /* number of sockets */

/* The Policy structure */
// TODO: Maximum 2 readers for now
typedef struct Policy {
    u4 n_readers;        // number of readers
    u4 readers[2];         // vector of reader (for now) Users (will be Groups)
    u4 n_writers;        // number of writers
    u4 writers[2];         // vector of writer (for now) Users (will be Groups)
} Policy;


typedef struct Label {
    u4 label;
} Label;

/* function of type HashCompareFunc */
static int hashcmpLabels(const void* p1, const void* p2)
{
    Label* l1 = (Label*) p1;
    Label* l2 = (Label*) p2;
    return (u4) l1->label - (u4) l2->label;
}

/* function of type HashFreeFunc */
static void freeLabel(void* l)
{
    Label* ll = (Label*) l;
    if (ll != NULL) {
	free(ll);
    }
}

/* function of type HashUpdateFunc */
static void hashupdateLabel(const void* oldLabel, const void* newLabel)
{
    Label* o = (Label*) oldLabel;
    Label* n = (Label*) newLabel;
    o->label = o->label | n->label;
    free(n);
}

#endif /*_DALVIK_AGATEi_PRIV */
