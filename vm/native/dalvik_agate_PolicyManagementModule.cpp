/*
 * dalvik.agate.PolicyManagementModule
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "attr/xattr.h"
#include "agate/AgatePolicy.h"

#include <cutils/atomic.h> /* use common Android atomic ops */
#include <errno.h>
#include <string>
#include <algorithm>
#include <set>

#define FILE_XATTR_NAME "file.policy"


/*
 * Determines if data is allowed to flow from a policy to another 
 *
 * public static boolean canFlow(int fromPolicy, int toPolicy)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_canFlow(const u4* args,
    JValue* pResult)
{
    bool result = agate_can_flow(args[0], args[1]);
    RETURN_BOOLEAN(result);
}

/* Add policy to String */
static void _add_policy_string(StringObject* strObj, u4 tag) {
    ArrayObject *value = NULL;
 
    if (strObj) {
        value = strObj->array();
        if (value->taint.tag == 0) {
	    value->taint.tag = tag;
        } else {
            // merge the two policies
            u4 m = agate_merge_policies(value->taint.tag, tag);
            agate_free_policy(value->taint.tag);
            agate_free_policy(tag);
            value->taint.tag = m;
        }
    }
}

/*
 * public static void addPolicyString(String str, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyString__(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    //ALOGW("AgateLog: addPolicyString created policy: %d", (u4)p);

    //std::set<std::string> v = *(p->readers);
    //for (std::set<std::string>::iterator i = v.begin(); i != v.end(); i++) {
    //    std::string e = *i;
    //    ALOGW("AgateLog: addPolicyString reader: %s", (*i).c_str());
    //}

    _add_policy_string(strObj, (u4)p);

    RETURN_VOID();
}

/*
 * public static void addPolicyString(String str, int tag)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyString__I(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    _add_policy_string(strObj, args[1]);
    RETURN_VOID();
}

/* Adds a policy on an array */
static void _add_policy_array(ArrayObject* arr, u4 tag)
{
    if (arr) {
        if (arr->taint.tag == 0) {
	    arr->taint.tag = tag;
        } else {
            // merge the two policies
            u4 m = agate_merge_policies(arr->taint.tag, tag);
            agate_free_policy(arr->taint.tag);
            agate_free_policy(tag);
            arr->taint.tag = m;
        }
    }
}

/*
 * public static void addPolicyObjectArray(Object[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyObjectArray__(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);

    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyObjectArray(Object[] array, int tag)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyObjectArray__I(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    _add_policy_array(arr, args[1]);
    RETURN_VOID();
}

/*
 * public static void addPolicyBooleanArray(boolean[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyBooleanArray__(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);

    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyBooleanArray(boolean[] array, int tag)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyBooleanArray__I(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    _add_policy_array(arr, args[1]);
    RETURN_VOID();
}

/*
 * public static void addPolicyCharArray(char[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyCharArray__(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyCharArray(char[] array, int tag)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyCharArray__I(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    _add_policy_array(arr, args[1]);
    RETURN_VOID();
}

/*
 * public static void addPolicyByteArray(byte[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyByteArray__(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyByteArray(byte[] array, int tag)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyByteArray__I(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    _add_policy_array(arr, args[1]);
    RETURN_VOID();
}

/*
 * public static void addPolicyIntArray(int[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyShortArray(short[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyLongArray(long[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyFloatArray(float[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyDoubleArray(double[] array, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    _add_policy_array(arr, (u4)p);
    RETURN_VOID();
}

/*
 * public static void addPolicyBoolean(boolean val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyBoolean(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 poid    = args[1];	 /* the tag to add */
    u4* rtaint = (u4*) &args[2]; /* pointer to return taint tag */
    u4 vtaint  = args[3];	 /* the existing taint tag on val */
    *rtaint    = (vtaint | poid);
    RETURN_BOOLEAN(val);
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyChar(char val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyChar(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 poid    = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint    = (vtaint | poid);
    RETURN_CHAR(val);
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyByte(byte val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyByte(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 poid    = args[1];         /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint    = (vtaint | poid);
    RETURN_BYTE(val);
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyInt(int val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyInt(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 poid    = args[1];	  /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint    = (vtaint | poid);
    RETURN_INT(val);
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyShort(short val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyShort(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 poid    = args[1];	  /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint    = (vtaint | poid);
    RETURN_SHORT(val);
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyLong(long val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyLong(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 poid    = args[2];	     /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    u4 vtaint  = args[4];	     /* the existing taint tag on val */
    memcpy(&val, &args[0], 8);	     /* EABI prevents direct store */
    *rtaint    = (vtaint | poid);
    RETURN_LONG(val);
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyFloat(float val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyFloat(const u4* args,
    JValue* pResult)
{
    u4 val     = args[0];
    u4 poid    = args[1];	  /* the tag to add */
    u4* rtaint = (u4*) &args[2];  /* pointer to return taint tag */
    u4 vtaint  = args[3];	  /* the existing taint tag on val */
    *rtaint    = (vtaint | poid);
    RETURN_INT(val);		  /* Be opaque; RETURN_FLOAT doesn't work */
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyDouble(double val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyDouble(const u4* args,
    JValue* pResult)
{
    u8 val;
    u4 poid    = args[2];	     /* the tag to add */
    u4* rtaint = (u4*) &args[3];     /* pointer to return taint tag */
    u4 vtaint  = args[4];	     /* the existing taint tag on val */
    memcpy(&val, &args[0], 8);	     /* EABI prevents direct store */
    *rtaint = (vtaint | poid);
    RETURN_LONG(val);		     /* Be opaque; RETURN_DOUBLE doesn't work */
}

/*
 * public static void getPolicyString(String str);
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    ArrayObject *value = NULL;

    if (strObj) {
    value = strObj->array();
	RETURN_INT(value->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyObjectArray(Object[] obj)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyBooleanArray(boolean[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyCharArray(char[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyByteArray(byte[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyIntArray(int[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyShortArray(short[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyLongArray(long[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyFloatArray(float[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else {
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyDoubleArray(double[] array)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    if (arr) {
	RETURN_INT(arr->taint.tag);
    } else{
	RETURN_INT(TAINT_CLEAR);
    }
}

/*
 * public static int getPolicyBoolean(boolean val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyBoolean(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyChar(char val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyChar(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyByte(byte val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyByte(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyInt(int val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyInt(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyShort(int val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyShort(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyLong(long val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyLong(const u4* args,
    JValue* pResult)
{
    // args[0:1] = the value
    // args[2] = the return taint
    u4 tag = args[3]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyFloat(float val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyFloat(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyDouble(long val)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyDouble(const u4* args,
    JValue* pResult)
{
    // args[0:1] = the value
    // args[2] = the return taint
    u4 tag = args[3]; /* the existing taint */
    RETURN_INT(tag);
}

/*
 * public static int getPolicyRef(Object obj)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyRef(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

static u4 getPolicyXattr(int fd)
{
    int ret;
    u4 buf;
    u4 tag = 0;

    ret = fgetxattr(fd, FILE_XATTR_NAME, &buf, sizeof(buf));
    if (ret > 0) {
	tag = buf;
    } else {
	if (errno == ENOATTR) {
	    /* do nothing */
	} else if (errno == ERANGE) {
	    ALOGW("AgateLog: fgetxattr(%d) contents to large", fd);
	} else if (errno == ENOTSUP) {
	    /* XATTRs are not supported. No need to spam the logs */
	    ALOGW("AgateLog: fgetxattr(%d): xattrs not suported", fd);
	} else if (errno == EPERM) {
	    /* Strange interaction with /dev/log/main. Suppress the log */
	} else {
	    ALOGW("AgateLog: fgetxattr(%d): unknown error code %d", fd, errno);
	}
    }

    return tag;
}

static void setPolicyXattr(int fd, u4 tag)
{
    int ret;

    ALOGW("AgateLog: [setPolicyXattr]: Set tag 0x%08x on fd %d", tag, fd);
    ret = fsetxattr(fd, FILE_XATTR_NAME, &tag, sizeof(tag), 0);

    if (ret < 0) {
	if (errno == ENOSPC || errno == EDQUOT) {
	    ALOGW("AgateLog: fsetxattr(%d): not enough room to set xattr", fd);
	} else if (errno == ENOTSUP) {
	    /* XATTRs are not supported. No need to spam the logs */
	    ALOGW("AgateLog: fsetxattr(%d): xattrs not suported", fd);
	} else if (errno == EPERM) {
	    /* Strange interaction with /dev/log/main. Suppress the log */
	    ALOGW("AgateLog: fsetxattr(%d): xattrs something with permissions /dev/log/main ", fd);
	} else {
	    ALOGW("AgateLog: fsetxattr(%d): unknown error code %d", fd, errno);
	}
    }

}

/*
 * public static int getPolicyFile(int fd)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicyFile(const u4* args,
    JValue* pResult)
{
    u4 tag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    // args[1] = the return taint
    // args[2] = fd taint

    tag = getPolicyXattr(fd);

    if (tag) {
	ALOGI("AgateLog: getPolicyFile(%d) = 0x%08x", fd, tag);
    }

    RETURN_INT(tag);
}

/*
 * public static int addPolicyFile(int fd, u4 tag)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicyFile(const u4* args,
    JValue* pResult)
{
    u4 otag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    u4 tag = args[1];      // args[1] = the taint tag

    otag = getPolicyXattr(fd);

    if (tag) {
	ALOGI("AgateLog: addPolicyFile(%d): adding 0x%08x to 0x%08x = 0x%08x",
		fd, tag, otag, tag | otag);
    }

    setPolicyXattr(fd, tag | otag);

    RETURN_VOID();
}

/*
 * public static int getPolicySocket(int fd)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_getPolicySocket(const u4* args,
    JValue* pResult)
{
    int fd = (int)args[0]; // args[0] = the file descriptor
    u4 tag = agate_get_policy_on_socket(fd);

    RETURN_INT(tag);
}

/*
 * public static int addPolicySocket(int fd, String[] readers, String[] writers)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_addPolicySocket(const u4* args,
    JValue* pResult)
{
    int fd = (int)args[0]; // args[0] = the file descriptor

    ArrayObject* readers = (ArrayObject*) args[1];
    ArrayObject* writers = (ArrayObject*) args[2];

    Policy* p = (Policy*) agate_create_policy(readers, writers);
    agate_add_policy_on_socket(fd, (u4)p);

    RETURN_VOID();
}

/*
 * public static void log(String msg)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_log(const u4* args,
    JValue* pResult)
{
    StringObject* msgObj = (StringObject*) args[0];
    char *msg;

    if (msgObj == NULL) {
	dvmThrowNullPointerException("msgObj == NULL");
	RETURN_VOID();
    }

	msg = dvmCreateCstrFromString(msgObj);
	ALOG(LOG_WARN, "TaintLog", "%s", msg);
	char *curmsg = msg;
	while(strlen(curmsg) > 1013)
	{   
		curmsg = curmsg+1013;
		ALOG(LOG_WARN, "TaintLog", "%s", curmsg);
	}
	free(msg);

    RETURN_VOID();
}

/*
 * public static void logPathFromFd(int fd)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_logPathFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];
    pid_t pid;
    char ppath[20]; // these path lengths should be enough
    char rpath[80];
    int err;


    pid = getpid();
    snprintf(ppath, 20, "/proc/%d/fd/%d", pid, fd);
    err = readlink(ppath, rpath, 80);
    if (err >= 0) {
	ALOGW("TaintLog: fd %d -> %s", fd, rpath);
    } else {
	ALOGW("TaintLog: error finding path for fd %d", fd);
    }

    RETURN_VOID();
}

/*
 * public static void logPeerFromFd(int fd)
 */
static void Dalvik_dalvik_agate_PolicyManagementModule_logPeerFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];

    ALOGW("TaintLog: logPeerFromFd not yet implemented");

    RETURN_VOID();
}

const DalvikNativeMethod dvm_dalvik_agate_PolicyManagementModule[] = {
    { "canFlow",  "(II)Z",
        Dalvik_dalvik_agate_PolicyManagementModule_canFlow},
    { "addPolicyString",  "(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyString__},
    { "addPolicyString",  "(Ljava/lang/String;I)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyString__I},
    { "addPolicyObjectArray",  "([Ljava/lang/Object;[Ljava/lang/String;[Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyObjectArray__},
    { "addPolicyObjectArray",  "([Ljava/lang/Object;I)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyObjectArray__I},
    { "addPolicyBooleanArray",  "([Z[Ljava/lang/String;[Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyBooleanArray__},
    { "addPolicyBooleanArray",  "([ZI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyBooleanArray__I},
    { "addPolicyCharArray",  "([C[Ljava/lang/String;[Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyCharArray__},
    { "addPolicyCharArray",  "([CI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyCharArray__I},
    { "addPolicyByteArray",  "([B[Ljava/lang/String;[Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyByteArray__},
    { "addPolicyByteArray",  "([BI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyByteArray__I},
    { "addPolicyIntArray",  "([II)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyIntArray},
    { "addPolicyShortArray",  "([SI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyShortArray},
    { "addPolicyLongArray",  "([JI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyLongArray},
    { "addPolicyFloatArray",  "([FI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyFloatArray},
    { "addPolicyDoubleArray",  "([DI)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyDoubleArray},
    { "addPolicyBoolean",  "(ZI)Z",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyBoolean},
    { "addPolicyChar",  "(CI)C",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyChar},
    { "addPolicyByte",  "(BI)B",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyByte},
    { "addPolicyInt",  "(II)I",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyInt},
    { "addPolicyShort",  "(SI)S",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyShort},
    { "addPolicyLong",  "(JI)J",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyLong},
    { "addPolicyFloat",  "(FI)F",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyFloat},
    { "addPolicyDouble",  "(DI)D",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyDouble},
    { "getPolicyString",  "(Ljava/lang/String;)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyString},
    { "getPolicyObjectArray",  "([Ljava/lang/Object;)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyObjectArray},
    { "getPolicyBooleanArray",  "([Z)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyBooleanArray},
    { "getPolicyCharArray",  "([C)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyCharArray},
    { "getPolicyByteArray",  "([B)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyByteArray},
    { "getPolicyIntArray",  "([I)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyIntArray},
    { "getPolicyShortArray",  "([S)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyShortArray},
    { "getPolicyLongArray",  "([J)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyLongArray},
    { "getPolicyFloatArray",  "([F)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyFloatArray},
    { "getPolicyDoubleArray",  "([D)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyDoubleArray},
    { "getPolicyBoolean",  "(Z)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyBoolean},
    { "getPolicyChar",  "(C)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyChar},
    { "getPolicyByte",  "(B)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyByte},
    { "getPolicyInt",  "(I)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyInt},
    { "getPolicyShort",  "(S)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyShort},
    { "getPolicyLong",  "(J)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyLong},
    { "getPolicyFloat",  "(F)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyFloat},
    { "getPolicyDouble",  "(D)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyDouble},
    { "getPolicyRef",  "(Ljava/lang/Object;)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyRef},
    { "getPolicyFile",  "(I)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicyFile},
    { "addPolicyFile",  "(II)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicyFile},
    { "getPolicySocket",  "(I)I",
        Dalvik_dalvik_agate_PolicyManagementModule_getPolicySocket},
    { "addPolicySocket",  "(I[Ljava/lang/String;[Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_addPolicySocket},
    { "log",  "(Ljava/lang/String;)V",
        Dalvik_dalvik_agate_PolicyManagementModule_log},
    { "logPathFromFd",  "(I)V",
        Dalvik_dalvik_agate_PolicyManagementModule_logPathFromFd},
    { "logPeerFromFd",  "(I)V",
        Dalvik_dalvik_agate_PolicyManagementModule_logPeerFromFd},
    { NULL, NULL, NULL },
};
