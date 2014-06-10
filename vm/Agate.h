/*
 * Dalvik vm public definitions.
 */
#ifndef _DALVIK_AGATE
#define _DALVIK_AGATE

/* The Policy structure */
typedef struct Policy {
    u4 n_readers;        // number of readers
    u4 readers[2];         // vector of reader (for now) Users (will be Groups)
    u4 n_writers;        // number of writers
    u4 writers[2];         // vector of writer (for now) Users (will be Groups)
} Policy;


#endif /*_DALVIK_AGATE*/
