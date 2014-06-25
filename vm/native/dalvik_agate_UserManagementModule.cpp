#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>

/* Verify a name is actually a name */
bool validateName(StringObject* name) {
    char* n = (char*)dvmCreateCstrFromString(name);

    char cur = 1;
    for(int i = 0; cur != 0; i++) {
        cur = n[i];
	if(cur >= 'a' && cur <= 'z') {
	} else if(cur >= 'A' && cur <= 'Z') {
	} else if(cur >= '0' && cur <= '9') {
	} else {
	    return false;
	}
    } 
    return true;
}

/* Send Query request */
void sendQuery(char buffer[256], char out[256])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    portno = 24068;
    bzero(out, 256);
    /* Create a socket point */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot open socket");
        strcpy(out,"-2");
        return;
    }

    //server = gethostbyname("localhost");
    // TODO: This is hard-coded for now
    /* Check if connectivity with server */
    server = gethostbyname("dunbar.cs.washington.edu");
    if (server == NULL) {
        ALOGE("ERROR: UserMgmtModule: no such host\n");
        strcpy(out,"-3");
        return;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
    (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    /* Connect to the server */
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot connect to User Management Service");
        strcpy(out,"-4");
        return;
    }

    /* Send message to the server */
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot writing to socket open to User Management Service");
        strcpy(out,"-5");
        return;
    }

    /* Get server response */
    bzero(out, 256);
    n = read(sockfd, out, 255);
    if (n < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot read from socket, response from User Management Service");
        strcpy(out,"-6");
        return;
    }
}


/* abort transaction and return */
void abortAndFail(bool inTransaction, const char* message) {
    ALOGE("%s",message);
    if(inTransaction) {
        char buffer[256];
	char out[256];
        bzero(buffer,256);
	strcpy(buffer,"ROLLBACK");
	sendQuery(buffer,out);
    }
}


/*
 * public static int loginImpl(String user, String password)
 */
static void Dalvik_dalvik_agate_UserManagementModule_loginImpl(const u4* args,
    JValue* pResult)
{
    char buffer[256];
    char out[256];

    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjPassword = (StringObject*) args[1];

    if (strObjUser == NULL || strObjPassword == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [login] at least one of the arguments is null.");
	RETURN_INT(-1);
        return;
    } else if(!validateName(strObjUser) || !validateName(strObjPassword)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [login] at least one of the arguments is invalid name.");
	RETURN_INT(-1);
        return;
    }

    //ArrayObject *value1 = NULL;
    //ArrayObject *value2 = NULL;
    //value1 = strObjUser->array();
    //value2 = strObjPassword->array();

    //strcpy(buffer, (char*) );
    //strcpy(password,"12345678");

    /* Now define the query
    */
    bzero(buffer,256);
    int ret = snprintf(buffer, 256, "SELECT userId FROM Users where username='%s' and password='%s'",
		       (char*) dvmCreateCstrFromString(strObjUser),
		       (char*) dvmCreateCstrFromString(strObjPassword));
    if(ret >= 256) {
        abortAndFail(false, "ERROR: UserMgmtModule: [login] username password combination too long");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer, out);

    int userId = atoi(out);
    if(userId < 0) {
        abortAndFail(false, "ERROR: UserMgmtModule: [login] query failed");
	RETURN_INT(-1);
    } else if(userId > 0) {
        RETURN_INT(userId);
    } else {
        //failed to parse return (presumably bad login attempt
        RETURN_INT(-1);
    }
}

/*
 * public static void addUser(char user[256], char password[256]))
 */
static void Dalvik_dalvik_agate_UserManagementModule_addUser(const u4* args,
    JValue* pResult)
{
    char buffer[256];
    char out[256];

    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjPassword = (StringObject*) args[1];

    if (strObjUser == NULL || strObjPassword == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUser] at least one of the arguments is null.");
	RETURN_INT(-1);
        return;
    } else if(!validateName(strObjUser) || !validateName(strObjPassword)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUser] at least one of the arguments is invalid name.");
	RETURN_INT(-1);
        return;
    }

    bzero(buffer,256);
    strcpy(buffer,"START TRANSACTION");
    sendQuery(buffer,out);
    if(atoi(out) < 0) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }

    //check that username is free
    bzero(buffer,256);
    int ret = snprintf(buffer, 256, "Select u.username From Users u Where u.username = '%s'",
		       (char*) dvmCreateCstrFromString(strObjUser));
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] username too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer, out);
    if(strlen(out) > 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] username already used.");
	RETURN_INT(-1);
        return;
    }

    // find a new id for this user
    bzero(buffer,256);
    strcpy(buffer,"Select max(u.userId) From Users u");
    sendQuery(buffer, out);

    //if fails to parse, atoi returns zero
    int newId = atoi(out);
    if(newId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	RETURN_INT(-1);
        return;
    } else {
        newId++;
    }

    // perform the insertion
    bzero(buffer,256);
    ret = snprintf(buffer, 256, "Insert Into Users(userId, username, password) Values ( %d, %s, %s)",newId, 
	    (char*) dvmCreateCstrFromString(strObjUser), (char*) dvmCreateCstrFromString(strObjPassword));
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] userId, username, password combination too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer, out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }

    //commit
    bzero(buffer,256);
    strcpy(buffer,"COMMIT");
    sendQuery(buffer,out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }
  
    RETURN_VOID();
}

/*
 * public static void addGroup(char group[256]))
 */
static void Dalvik_dalvik_agate_UserManagementModule_addGroup(const u4* args,
    JValue* pResult)
{
    char buffer[256];
    char out[256];

    StringObject *strObjGroup = (StringObject*) args[0];
    int ownerId = (int)args[1];

    if (strObjGroup == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addGroup] group argument is null.");
	RETURN_INT(-1);
        return;
    } else if(!validateName(strObjGroup)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addGroup] group argument is invalid name.");
	RETURN_INT(-1);
        return;
    }

    bzero(buffer,256);
    strcpy(buffer,"START TRANSACTION");
    sendQuery(buffer,out);
    if(atoi(out) < 0) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addGroup] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }

    //check the groupname is free
    bzero(buffer,256);
    int ret = snprintf(buffer, 256, "Select g.groupName From Groups g Where g.groupName = '%s'",
		       (char*) dvmCreateCstrFromString(strObjGroup));
    if(ret >= 256) {
        abortAndFail(true, "ERROR: UserMgmtModule: [addGroup] groupname too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer, out);
    if(strlen(out) > 0) {
        abortAndFail(true, "ERROR: UserMgmtModule: [addGroup] groupName already used.");
	RETURN_INT(-1);
        return;
    }

    //find a new group id
    bzero(buffer,256);
    strcpy(buffer,"Select max(g.groupID) From Groups g");
    sendQuery(buffer, out);

    int newId = atoi(out);
    if(newId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [AddGroup] couldn't get group id.");
	RETURN_INT(-1);
        return;
    } else {
        newId++;
    }

    // perform the insertion
    bzero(buffer,256);
    ret = snprintf(buffer, 256, "Insert Into Groups(groupID, groupName, owner) Values ( %d, %s, %d)",newId, 
		   (char*) dvmCreateCstrFromString(strObjGroup), ownerId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] groupname, groupid and ownerID combination too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer, out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }

    //commit
    bzero(buffer,256);
    strcpy(buffer,"COMMIT");
    sendQuery(buffer,out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }  


    RETURN_VOID();
}

/*
 * public static void addUserToGroup(char user[256], char group[256]))
 */
static void Dalvik_dalvik_agate_UserManagementModule_addUserToGroup(const u4* args,
    JValue* pResult)
{
    char buffer[256];
    char out[256];

    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjGroup = (StringObject*) args[1];
    int ownerId = (int)args[2];

    if (strObjUser == NULL || strObjGroup == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUserToGroup] at least one argument is null.");
	RETURN_INT(-1);
        return;
    } else if(!validateName(strObjUser) || !validateName(strObjGroup)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUserToGroup] at least one of the arguments is invalid name.");
	RETURN_INT(-1);
        return;
    }

    bzero(buffer,256);
    strcpy(buffer, "START TRANSACTION");
    sendQuery(buffer,out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }

    //verify we are the owner of the group
    bzero(buffer,256);
    int ret = snprintf(buffer,256,"Select g.owner From Groups g Where g.groupName = '%s'",
		       (char*) dvmCreateCstrFromString(strObjGroup));
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] groupname is too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer,out);
    if(atoi(out) != ownerId) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] Caller is not owner of group.");
	RETURN_INT(-1);
	return;
    }

    // Identify a new id
    int newId, gId, uId;
    bzero(buffer,256);
    strcpy(buffer,"Select max(ug.id) From UserGroups ug");
    sendQuery(buffer, out);
    newId = atoi(out);
    if(newId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't create new id.");
	RETURN_INT(-1);
	return;
    } else {
        newId++;
    }

    //find the group id
    ret = snprintf(buffer, 256, "Select g.groupID From Groups g Where g.groupName = '%s'",
		   (char*) dvmCreateCstrFromString(strObjGroup));
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] groupname is too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer,out);
    gId = atoi(out);
    if(gId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] Tried to add to non-existent group.");
	RETURN_INT(-1);
	return;
    }

    //find the user id
    ret = snprintf(buffer, 256, "Select u.userID From Users u Where u.username = '%s'",
		   (char*) dvmCreateCstrFromString(strObjUser));
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] username is too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer,out);
    uId = atoi(out);
    if(uId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] Tried to add non-existent user.");
	RETURN_INT(-1);
	return;
    }

    //perform insertion
    bzero(buffer,256);
    ret = snprintf(buffer, 256, "Insert Into UserGroups(id, groupId, userId) Values ( %d, %d, %d)", newId, gId, uId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] id, groupId, userId combination too long.");
	RETURN_INT(-1);
	return;
    }
    sendQuery(buffer, out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }


    //commit
    bzero(buffer,256);
    strcpy(buffer,"COMMIT");
    sendQuery(buffer,out);
    if(atoi(out) < 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't contact database.");
	RETURN_INT(-1);
	return;
    }
  
    RETURN_VOID();
}

const DalvikNativeMethod dvm_dalvik_agate_UserManagementModule[] = {
    	{ "loginImpl",  "(Ljava/lang/String;Ljava/lang/String;)I",
        Dalvik_dalvik_agate_UserManagementModule_loginImpl},
        { "addUser", "(Ljava/lang/String;)I",
	  Dalvik_dalvik_agate_UserManagementModule_addUser},
    	{ "addGroup",  "(Ljava/lang/String;I)I",
        Dalvik_dalvik_agate_UserManagementModule_addGroup},
    	{ "addUserToGroup",  "(Ljava/lang/String;Ljava/lang/String;I)I",
        Dalvik_dalvik_agate_UserManagementModule_addUserToGroup},
	{ NULL, NULL, NULL },
};
