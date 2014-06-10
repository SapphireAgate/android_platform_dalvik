#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "attr/xattr.h"

#include <errno.h>


#define TAINT_XATTR_NAME "user.UserMgmtModule"

/*
 * public static void login()
 */
static int Dalvik_dalvik_system_UserMgmtModule_getID()
{
    	return ID;
}


const DalvikNativeMethod dvm_dalvik_system_UserMgmtModule[] = {
    	{ "getID",  "()I",
        Dalvik_dalvik_system_UserMgmtModule_getID},
	{ NULL, NULL, NULL },
};

