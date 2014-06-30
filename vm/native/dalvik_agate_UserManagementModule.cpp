#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "agate/AgateUser.h"
#include <sys/types.h> 


static void Dalvik_dalvik_agate_UserManagementModule_getUserName(const u4* args,
    JValue* pResult)
{
    char* res = agate_get_user();
    if(res == NULL) {
        RETURN_PTR(NULL);
    } else {
        StringObject *user = dvmCreateStringFromCstr(res);
	dvmReleaseTrackedAlloc((Object *)user, NULL);
	RETURN_PTR(user);
    }
}


/*
 * public static int loginImpl(String user, String password)
 */
static void Dalvik_dalvik_agate_UserManagementModule_login(const u4* args,
    JValue* pResult)
{
    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjPassword = (StringObject*) args[1];

    if(agate_login((char*) dvmCreateCstrFromString(strObjUser),
		   (char*) dvmCreateCstrFromString(strObjPassword))) {
        RETURN_INT(0);
    }
    RETURN_INT(-1);
}

/*
 * public static void addUser(char user[256], char password[256]))
 */
static void Dalvik_dalvik_agate_UserManagementModule_addUser(const u4* args,
    JValue* pResult)
{
    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjPassword = (StringObject*) args[1];

    if(agate_add_user((char*) dvmCreateCstrFromString(strObjUser),
		      (char*) dvmCreateCstrFromString(strObjPassword))) {
        RETURN_INT(0);
    }
    RETURN_INT(-1);

}

/*
 * public static void addGroup(char group[256]))
 */
static void Dalvik_dalvik_agate_UserManagementModule_addGroup(const u4* args,
    JValue* pResult)
{
    StringObject *strObjGroup = (StringObject*) args[0];

    if(agate_add_group((char*) dvmCreateCstrFromString(strObjGroup))) {
        RETURN_INT(0);
    }
    RETURN_INT(-1);

}

/*
 * public static void addUserToGroup(char user[256], char group[256]))
 */
static void Dalvik_dalvik_agate_UserManagementModule_addUserToGroup(const u4* args,
    JValue* pResult)
{
    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjGroup = (StringObject*) args[1];

    if(agate_add_user_to_group((char*) dvmCreateCstrFromString(strObjUser),
			       (char*) dvmCreateCstrFromString(strObjGroup))) {
        RETURN_INT(0);
    }
    RETURN_INT(-1);

}

const DalvikNativeMethod dvm_dalvik_agate_UserManagementModule[] = {
        { "getUserName", "()Ljava/lang/String;",
        Dalvik_dalvik_agate_UserManagementModule_getUserName},
    	{ "login",  "(Ljava/lang/String;Ljava/lang/String;)I",
        Dalvik_dalvik_agate_UserManagementModule_login},
        { "addUser", "(Ljava/lang/String;Ljava/lang/String;)I",
	  Dalvik_dalvik_agate_UserManagementModule_addUser},
    	{ "addGroup",  "(Ljava/lang/String;)I",
        Dalvik_dalvik_agate_UserManagementModule_addGroup},
    	{ "addUserToGroup",  "(Ljava/lang/String;Ljava/lang/String;)I",
        Dalvik_dalvik_agate_UserManagementModule_addUserToGroup},
	{ NULL, NULL, NULL },
};
