/*
 * dalvik.system.UserFlowPolicy
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "attr/xattr.h"

#include <errno.h>

#define TAINT_XATTR_NAME "user.policy"

/* Hardcode some policies? */

//Policy policies[3] = {{1, {1}, 0, NULL},
//                      {1, {2}, 0, NULL},
//                      {2, {1, 3}, 0, NULL}};

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyString(String str, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyString(const u4* args,
    JValue* pResult)
{
    StringObject *strObj = (StringObject*) args[0];
    u4 poid = args[1];
    ArrayObject *value = NULL;

    if (strObj) {
    value = strObj->array();
	value->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyObjectArray(Object[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyObjectArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyBooleanArray(boolean[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyBooleanArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyCharArray(char[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyCharArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyByteArray(byte[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyByteArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyIntArray(int[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyIntArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyShortArray(short[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyShortArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyLongArray(long[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyLongArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyFloatArray(float[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyFloatArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyDoubleArray(double[] array, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyDoubleArray(const u4* args,
    JValue* pResult)
{
    ArrayObject *arr = (ArrayObject *) args[0];
    u4 poid = args[1];
    if (arr) {
	arr->taint.tag |= poid;
    }
    RETURN_VOID();
}

/*
 * TODO: for now select a hard-coded policy
 * public static void addPolicyBoolean(boolean val, (int policyId,) int[] readers, int[] writers)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyBoolean(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyChar(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyByte(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyInt(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyShort(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyLong(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyFloat(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyDouble(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyString(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyObjectArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyBooleanArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyCharArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyByteArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyIntArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyShortArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyLongArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyFloatArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyDoubleArray(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyBoolean(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyChar(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyByte(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyInt(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyShort(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyLong(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyFloat(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyDouble(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyRef(const u4* args,
    JValue* pResult)
{
    // args[0] = the value
    // args[1] = the return taint
    u4 tag = args[2]; /* the existing taint */
    RETURN_INT(tag);
}

static u4 getTaintXattr(int fd)
{
    int ret;
    u4 buf;
    u4 tag = TAINT_CLEAR;

    ret = fgetxattr(fd, TAINT_XATTR_NAME, &buf, sizeof(buf));
    if (ret > 0) {
	tag = buf;
    } else {
	if (errno == ENOATTR) {
	    /* do nothing */
	} else if (errno == ERANGE) {
	    ALOGW("TaintLog: fgetxattr(%d) contents to large", fd);
	} else if (errno == ENOTSUP) {
	    /* XATTRs are not supported. No need to spam the logs */
	} else if (errno == EPERM) {
	    /* Strange interaction with /dev/log/main. Suppress the log */
	} else {
	    ALOGW("TaintLog: fgetxattr(%d): unknown error code %d", fd, errno);
	}
    }

    return tag;
}

static void setTaintXattr(int fd, u4 tag)
{
    int ret;

    ret = fsetxattr(fd, TAINT_XATTR_NAME, &tag, sizeof(tag), 0);

    if (ret < 0) {
	if (errno == ENOSPC || errno == EDQUOT) {
	    ALOGW("TaintLog: fsetxattr(%d): not enough room to set xattr", fd);
	} else if (errno == ENOTSUP) {
	    /* XATTRs are not supported. No need to spam the logs */
	} else if (errno == EPERM) {
	    /* Strange interaction with /dev/log/main. Suppress the log */
	} else {
	    ALOGW("TaintLog: fsetxattr(%d): unknown error code %d", fd, errno);
	}
    }

}

/*
 * public static int getPolicyFile(int fd)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_getPolicyFile(const u4* args,
    JValue* pResult)
{
    u4 tag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    // args[1] = the return taint
    // args[2] = fd taint

    tag = getTaintXattr(fd);

    if (tag) {
	ALOGI("TaintLog: getTaintFile(%d) = 0x%08x", fd, tag);
    }

    RETURN_INT(tag);
}

/*
 * public static int addPolicyFile(int fd, u4 tag)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_addPolicyFile(const u4* args,
    JValue* pResult)
{
    u4 otag;
    int fd = (int)args[0]; // args[0] = the file descriptor
    u4 tag = args[1];      // args[1] = the taint tag
    // args[2] = the return taint
    // args[3] = fd taint
    // args[4] = tag taint

    otag = getTaintXattr(fd);

    if (tag) {
	ALOGI("TaintLog: addTaintFile(%d): adding 0x%08x to 0x%08x = 0x%08x",
		fd, tag, otag, tag | otag);
    }

    setTaintXattr(fd, tag | otag);

    RETURN_VOID();
}

/*
 * public static void log(String msg)
 */
static void Dalvik_dalvik_system_UserFlowPolicy_log(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_logPathFromFd(const u4* args,
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
static void Dalvik_dalvik_system_UserFlowPolicy_logPeerFromFd(const u4* args,
    JValue* pResult)
{
    int fd = (int) args[0];

    ALOGW("TaintLog: logPeerFromFd not yet implemented");

    RETURN_VOID();
}

const DalvikNativeMethod dvm_dalvik_system_UserFlowPolicy[] = {
    { "addPolicyString",  "(Ljava/lang/String;I)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyString},
    { "addPolicyObjectArray",  "([Ljava/lang/Object;I)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyObjectArray},
    { "addPolicyBooleanArray",  "([ZI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyBooleanArray},
    { "addPolicyCharArray",  "([CI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyCharArray},
    { "addPolicyByteArray",  "([BI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyByteArray},
    { "addPolicyIntArray",  "([II)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyIntArray},
    { "addPolicyShortArray",  "([SI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyShortArray},
    { "addPolicyLongArray",  "([JI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyLongArray},
    { "addPolicyFloatArray",  "([FI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyFloatArray},
    { "addPolicyDoubleArray",  "([DI)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyDoubleArray},
    { "addPolicyBoolean",  "(ZI)Z",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyBoolean},
    { "addPolicyChar",  "(CI)C",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyChar},
    { "addPolicyByte",  "(BI)B",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyByte},
    { "addPolicyInt",  "(II)I",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyInt},
    { "addPolicyShort",  "(SI)S",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyShort},
    { "addPolicyLong",  "(JI)J",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyLong},
    { "addPolicyFloat",  "(FI)F",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyFloat},
    { "addPolicyDouble",  "(DI)D",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyDouble},
    { "getPolicyString",  "(Ljava/lang/String;)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyString},
    { "getPolicyObjectArray",  "([Ljava/lang/Object;)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyObjectArray},
    { "getPolicyBooleanArray",  "([Z)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyBooleanArray},
    { "getPolicyCharArray",  "([C)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyCharArray},
    { "getPolicyByteArray",  "([B)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyByteArray},
    { "getPolicyIntArray",  "([I)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyIntArray},
    { "getPolicyShortArray",  "([S)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyShortArray},
    { "getPolicyLongArray",  "([J)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyLongArray},
    { "getPolicyFloatArray",  "([F)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyFloatArray},
    { "getPolicyDoubleArray",  "([D)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyDoubleArray},
    { "getPolicyBoolean",  "(Z)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyBoolean},
    { "getPolicyChar",  "(C)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyChar},
    { "getPolicyByte",  "(B)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyByte},
    { "getPolicyInt",  "(I)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyInt},
    { "getPolicyShort",  "(S)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyShort},
    { "getPolicyLong",  "(J)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyLong},
    { "getPolicyFloat",  "(F)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyFloat},
    { "getPolicyDouble",  "(D)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyDouble},
    { "getPolicyRef",  "(Ljava/lang/Object;)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyRef},
    { "getPolicyFile",  "(I)I",
        Dalvik_dalvik_system_UserFlowPolicy_getPolicyFile},
    { "addPolicyFile",  "(II)V",
        Dalvik_dalvik_system_UserFlowPolicy_addPolicyFile},
    { "log",  "(Ljava/lang/String;)V",
        Dalvik_dalvik_system_UserFlowPolicy_log},
    { "logPathFromFd",  "(I)V",
        Dalvik_dalvik_system_UserFlowPolicy_logPathFromFd},
    { "logPeerFromFd",  "(I)V",
        Dalvik_dalvik_system_UserFlowPolicy_logPeerFromFd},
    { NULL, NULL, NULL },
};
