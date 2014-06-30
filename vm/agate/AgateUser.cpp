#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>

#include "agate/AgateUser.h"

//values for the currently logged in user
static char* cur_username = NULL;
static int cur_userId = -1;
static int sockfd = -1;

/* Verify a name is actually a name */
static bool validateName(char* name) {
    char cur = name[0];
    for(int i = 0; cur != 0; i++) {
	if(cur >= 'a' && cur <= 'z') {
	} else if(cur >= 'A' && cur <= 'Z') {
	} else if(cur >= '0' && cur <= '9') {
	} else {
	    return false;
	}
        cur = name[i];
    }
    return true;
}

/* Send Query request */
static void sendQuery(char buffer[256], char out[256])
{
    if(sockfd < 0) {
        int portno;
        struct sockaddr_in serv_addr;
        struct hostent *server;

        portno = 24068;
        bzero(out, 256);
        /* Create a socket point */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            ALOGE("ERROR: UserMgmtModule: cannot open socket %d %d",sockfd, errno);
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
            ALOGE("ERROR: UserMgmtModule: cannot connect to User Management Service %d",errno);
            strcpy(out,"-4");
            return;
        }
    }

    int n;

    /* Send message to the server */
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot write to socket open to User Management Service %d",errno);
        strcpy(out,"-5");
	sockfd = -1;
        return;
    }

    /* Get server response */
    bzero(out, 256);
    n = read(sockfd, out, 255);
    if (n < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot read from socket, response from User Management Service %d",errno);
        strcpy(out,"-6");
	sockfd = -1;
        return;
    }
}


/* abort transaction and return */
static void abortAndFail(bool inTransaction, const char* message) {
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
 * returns the currently logged in user's username or null if no
 * such user. Please do not modify or free as is used internally
 */
char* agate_get_user() {
    return cur_username;
}

/*
 *  attempt to login as username using password, return true on success
 */
bool agate_login(char* username, char* password) {

    char buffer[256];
    char out[256];

    if (username == NULL || password == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [login] at least one of the arguments is null.");
	return false;
    } else if(!validateName(username) || !validateName(password)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [login] at least one of the arguments is invalid name.");
	return false;
    }

    //perform check
    bzero(buffer,256);
    int ret = snprintf(buffer, 256, "SELECT userId FROM Users where username='%s' and password='%s'",
		       username, password);
    if(ret >= 256) {
        abortAndFail(false, "ERROR: UserMgmtModule: [login] username password combination too long");
	return false;
    }
    sendQuery(buffer, out);

    int userId = atoi(out);
    if(userId < 0) {
        abortAndFail(false, "ERROR: UserMgmtModule: [login] query failed");
	return false;
    } else if(userId > 0) {
        cur_userId = userId;
	if(cur_username != NULL)
  	    free(cur_username);
        cur_username = strdup(username);
	if(cur_username == NULL)
	    return false;
	return true;
    } else {
        //failed to parse return (presumably bad login attempt)
        return false;
    }
}

/*
 * Adds a user with the specified username and password, returns true on success
 */
bool agate_add_user(char* username, char* password) {
    char buffer[256];
    char out[256];

    if (username == NULL || password == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUser] at least one of the arguments is null.");
        return false;
    } else if(!validateName(username) || !validateName(password)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUser] at least one of the arguments is invalid name.");
        return false;
    }

    bzero(buffer,256);
    strcpy(buffer,"START TRANSACTION;");
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	return false;
    }

    //check that username is free
    bzero(buffer,256);
    int ret = snprintf(buffer, 256, "Select u.username From Users u Where u.username = '%s';",
		       username);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] username too long.");
	return false;
    }
    sendQuery(buffer, out);
    if(strcmp(out,"-1") != 0) { //"-1" represents no result
	ALOGW("%s", out);
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] username already used.");
        return false;
    }

    // perform the insertion
    bzero(buffer,256);
    ret = snprintf(buffer, 256, "Insert Into Users(username, password) Values ('%s', '%s');", username, password);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] username, password combination too long.");
	return false;
    }
    sendQuery(buffer, out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	return false;
    }

    //commit
    bzero(buffer,256);
    strcpy(buffer,"COMMIT;");
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUser] couldn't contact database.");
	return false;
    }
  
    return true;
}


/*
 * add a group owned by current logged in user, returns true on success
 */
bool agate_add_group(char* groupName) {

    char buffer[256];
    char out[256];

    if(cur_userId == -1) {
        abortAndFail(false, "ERROR: UserMgmtModule: [addGroup] no currently logged in user.");
	return false;
    }

    if (groupName == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addGroup] group argument is null.");
        return false;
    } else if(!validateName(groupName)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addGroup] group argument is invalid name.");
        return false;
    }

    bzero(buffer,256);
    strcpy(buffer,"START TRANSACTION;");
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addGroup] couldn't contact database.");
	return false;
    }

    //check the groupname is free
    bzero(buffer,256);
    int ret = snprintf(buffer, 256, "Select g.groupName From Groups g Where g.groupName = '%s' and g.owner = %d;",
		       groupName, cur_userId);
    if(ret >= 256) {
        abortAndFail(true, "ERROR: UserMgmtModule: [addGroup] groupname too long.");
	return false;
    }
    sendQuery(buffer, out);
    if(strcmp(out,"-1") != 0) {
        abortAndFail(true, "ERROR: UserMgmtModule: [addGroup] groupName already used.");
        return false;
    }

    // perform the insertion
    bzero(buffer,256);
    ret = snprintf(buffer, 256, "Insert Into Groups(groupName, owner) Values ('%s', '%d');", groupName, cur_userId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] groupname, groupid and ownerID combination too long.");
	return false;
    }
    sendQuery(buffer, out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] couldn't contact database.");
	return false;
    }

    //commit
    bzero(buffer,256);
    strcpy(buffer,"COMMIT;");
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] couldn't contact database.");
	return false;
    }  

    return true;
}

/*
 * Adds specified user to specified group. Fails if currently logged in user
 * is not owner of group. Returns true on success
 */
bool agate_add_user_to_group(char* username, char* group) {

    if(cur_userId == -1) {
        abortAndFail(false, "ERROR: UserMgmtModule: [addUserToGroup] no currently logged in user.");
	return false;
    }

    char buffer[256];
    char out[256];

    if (username == NULL || group == NULL) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUserToGroup] at least one argument is null.");
        return false;
    } else if(!validateName(username) || !validateName(group)) {
        abortAndFail(false,"ERROR: UserMgmtModule: [addUserToGroup] at least one of the arguments is invalid name.");
        return false;
    }

    bzero(buffer,256);
    strcpy(buffer, "START TRANSACTION;");
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't contact database.");
	return false;
    }

    //verify we are the owner of the group
    bzero(buffer,256);
    int ret = snprintf(buffer,256,"Select g.owner From Groups g Where g.groupName = '%s' and g.owner = %d;",group,cur_userId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] groupname is too long.");
	return false;
    }
    sendQuery(buffer,out);
    if(atoi(out) != cur_userId) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] Caller is not owner of group.");
	return false;
    }

    int gId, uId;
    //find the group id
    ret = snprintf(buffer, 256, "Select g.groupID From Groups g Where g.groupName = '%s' and owner = %d;",
		   group, cur_userId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] groupname is too long.");
	return false;
    }
    sendQuery(buffer,out);
    gId = atoi(out);
    if(gId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] Tried to add to non-existent group.");
	return false;
    }

    //find the user id
    ret = snprintf(buffer, 256, "Select u.userID From Users u Where u.username = '%s';",
		   username);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] username is too long.");
	return false;
    }
    sendQuery(buffer,out);
    uId = atoi(out);
    if(uId <= 0) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] Tried to add non-existent user.");
	return false;
    }

    //verify the user isn't already in the group
    bzero(buffer,256);
    ret = snprintf(buffer,256,"Select * From UserGroups ug Where ug.groupID = '%d' and ug.userID = %d;",gId,uId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] some numbers are too large");
	return false;
    }
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] User already in group.");
	return false;
    }

    //perform insertion
    bzero(buffer,256);
    ret = snprintf(buffer, 256, "Insert Into UserGroups(groupId, userId) Values (%d, %d);", gId, uId);
    if(ret >= 256) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addGroup] id, groupId, userId combination too long.");
	return false;
    }
    sendQuery(buffer, out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't contact database.");
	return false;
    }


    //commit
    bzero(buffer,256);
    strcpy(buffer,"COMMIT;");
    sendQuery(buffer,out);
    if(atoi(out) != -1) {
        abortAndFail(true,"ERROR: UserMgmtModule: [addUserToGroup] couldn't contact database.");
	return false;
    }
    
    return true;
}
