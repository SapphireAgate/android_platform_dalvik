#include "Dalvik.h"
#include "agate/AgatePriv.h"

/* 
 * Functions to initialize/shutdown Agate modules
 *
 * For now Agate has two modules: for user and policy
 * management.
 */

bool dvmAgateStartup()
{
    /* Initialize the socket policy table. This table associates a
     * policy label with every opened socket.
     */
    gDvmAgate.socketPolicies = dvmHashTableCreate(
	    dvmHashSize(AGATE_SOCKET_POLICIES_TABLE_SIZE), 
	    (HashFreeFunc) freeTag);

    if (gDvmAgate.socketPolicies == NULL)
        return false;

    return true;
}

void dvmAgateShutdown()
{
    /*
     * Deallocates the socket policies table. 
     */
    dvmHashTableFree(gDvmAgate.socketPolicies);
}
