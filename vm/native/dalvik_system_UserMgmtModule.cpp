#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>

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

/*
 * public static int login(String user, String password)
 */
static void Dalvik_dalvik_system_UserMgmtModule_loginImpl(const u4* args,
    JValue* pResult)
{
    char buffer[256];
    char out[256];


    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjPassword = (StringObject*) args[1];

    if (strObjUser == NULL || strObjPassword == NULL) {
        ALOGE("ERROR: UserMgmtModule: [login] at least one of the arguments is null.");
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
    strcpy(buffer,"SELECT userId FROM Users where username='");
    strcat(buffer, (char*) dvmCreateCstrFromString(strObjUser));
    strcat(buffer,"' AND password='");
    strcat(buffer, (char*) dvmCreateCstrFromString(strObjPassword));
    strcat(buffer,"'");

    sendQuery(buffer, out);

    RETURN_INT(atoi(out));
}

/*
 * public static void addUser(char user[256], char password[256]))
 */
static void Dalvik_dalvik_system_UserMgmtModule_addUser(const u4* args,
    JValue* pResult)
{
    ALOGW("UserMgmtModule: addUser not implemented yet");

    RETURN_VOID();
}

/*
 * public static void addGroup(char group[256]))
 */
static void Dalvik_dalvik_system_UserMgmtModule_addGroup(const u4* args,
    JValue* pResult)
{
    ALOGW("UserMgmtModule: addGroup not implemented yet");

    RETURN_INT(0);
}

/*
 * public static void addUserToGroup(char user[256], char group[256]))
 */
static void Dalvik_dalvik_system_UserMgmtModule_addUserToGroup(const u4* args,
    JValue* pResult)
{
    ALOGW("UserMgmtModule: addUserToGroup not implemented yet");

    RETURN_INT(0);
}

const DalvikNativeMethod dvm_dalvik_system_UserMgmtModule[] = {
    	{ "loginImpl",  "(Ljava/lang/String;Ljava/lang/String;)I",
        Dalvik_dalvik_system_UserMgmtModule_loginImpl},
    	{ "addGroup",  "(Ljava/lang/String;)I",
        Dalvik_dalvik_system_UserMgmtModule_addGroup},
    	{ "addUserToGroup",  "(Ljava/lang/String;Ljava/lang/String;)I",
        Dalvik_dalvik_system_UserMgmtModule_addUserToGroup},
	{ NULL, NULL, NULL },
};
