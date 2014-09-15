#include "Dalvik.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>
#include <unistd.h>

#include "agate/AgateUser.h"
#include "agate/AgatePolicy.h"
#include "AgateUtil.h"

//values for the currently logged in user
static char* cur_username = NULL;
static int cur_userId = -1;
static int admin_id = -1;
//static int sockfd = -1;

// hard-coded info about the UMS
static const char* HOST = "howe.cs.washington.edu";
static int PORT = 24068; 

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

/* Send Command request */
static int _send_command(char* command, int command_len, char** out, int* out_len) {
    struct sockaddr_in serv_addr;
    struct hostent *server;

    /* Create a socket point */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot open socket %d %d",sockfd, errno);
        return -1;
    }
    
    // TODO: This is hard-coded for now
    /* Check if connectivity with server */
    server = gethostbyname(HOST);
    if (server == NULL) {
        ALOGE("ERROR: UserMgmtModule: no such host\n");
        return -1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(PORT);

    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        ALOGE("ERROR: UserMgmtModule: cannot connect to User Management Service %d",errno);
        return -1;
    }

    /* Send message to the server */
    _agate_util_write_x_bytes_to_socket(sockfd, command, command_len);

    /* Get server response */
    char* buf = _agate_util_read_x_bytes_from_socket(sockfd, sizeof(int));
    *out_len = _agate_util_int_from_byte_array(buf);
    free(buf);
    *out = _agate_util_read_x_bytes_from_socket(sockfd, *out_len);

    /* Close socket */
    close(sockfd);

    return 0;
}

/*
 * returns the currently logged in user's username or null if no
 * such user. Please do not modify or free as is used internally
 */
char* agate_get_user() {
    return cur_username;
}

int agate_get_userId() {
    return cur_userId;
}

static int get_admin_id() {
    // TODO: for now assume the admin id doesn't change
    if (admin_id != -1)
        return admin_id;

    // else, make request to the User Management Service and ask for a user's id
    // we can use for now the get_users_and_groups_ids
    char admin_username[] = "admin";
    int u_size = sizeof(int) + strlen(admin_username) + 1;
    char* users_stream = (char*)malloc(u_size);
    char* tmp = _agate_util_add_int(users_stream, 1);
    memcpy(tmp, admin_username, strlen(admin_username));
    *(tmp + strlen(admin_username)) = ' ';

    int g_size = sizeof(int);
    char* groups_stream = (char*)malloc(g_size);
    _agate_util_add_int(groups_stream, 0);

    char* out = get_users_and_groups_ids(users_stream, u_size, groups_stream, g_size, 1);
    out = _agate_util_get_int(out, &u_size);
    assert(u_size == 1);
    _agate_util_get_int(out, &admin_id);

    free(users_stream);
    free(groups_stream);

    ALOGW("AgateLog: [get_admin_id] Got admin id from User Management Module: %d", admin_id);
    return admin_id;
}

/*
 *  Command id 1.
 *  attempt to login as username using password, return true on success
 */
bool agate_login(char* username, char* password) {
    char* out;
    char* command;
    char* tmp;
    int message_len, command_len, out_len;

    if (username == NULL || password == NULL) {
        ALOGE("ERROR: UserMgmtModule: [login] at least one of the arguments is null.");
	return false;
    } else if(!validateName(username) || !validateName(password)) {
        ALOGE("ERROR: UserMgmtModule: [login] at least one of the arguments is invalid name.");
	return false;
    }

    /* Compose command for login */
    message_len = strlen(username) + strlen(password) + 1; // 1 char for space between the two strings
    command_len = message_len + sizeof(int) + 1;           // 1 char for command_type
    command = (char*)malloc(command_len);
    tmp = command;
    *tmp++ = '1'; // command_type for login
    tmp = _agate_util_add_int(tmp, message_len);
    sprintf(tmp, "%s %s", username, password);

    /* Send command 1 = login */
    _send_command(command, command_len, &out, &out_len);
    free(command);

    int userId = _agate_util_int_from_byte_array(out);
    free(out);

    if(userId < 0) {
        ALOGE("ERROR: UserMgmtModule: [login] query failed.");
	return false;
    }

    if(userId > 0) {
        cur_userId = userId;
	if(cur_username != NULL)
  	    free(cur_username);
        cur_username = strdup(username);
	if(cur_username == NULL)
	    return false;
        ALOGW("User logged in. Current userId = %d, username = %s.", cur_userId, cur_username);
	return true;
    }

    return false;
}

/*
 * Adds a user with the specified username and password, returns true on success
 */
bool agate_add_user(char* username, char* password) {
    char* out;
    char* command;
    char* tmp;
    int message_len, command_len, out_len;

    if (username == NULL || password == NULL) {
        ALOGE("ERROR: UserMgmtModule: [addUser] at least one of the arguments is null.");
        return false;
    } else if(!validateName(username) || !validateName(password)) {
        ALOGE("Name = %s; Pass = %s", username, password);
        ALOGE("ERROR: UserMgmtModule: [addUser] at least one of the arguments is invalid name.");
        return false;
    }
 
    /* Compose command for add_user */
    message_len = strlen(username) + strlen(password) + 1; // 1 char for space between the two strings
    command_len = message_len + sizeof(int) + 1;           // 1 char for command_type
    command = (char*)malloc(command_len + 1);              // 1 char for null terminating sprintf
    tmp = command;
    *tmp++ = '2'; // command_type for add_user
    tmp = _agate_util_add_int(tmp, message_len);
    sprintf(tmp, "%s %s", username, password);

    /* Send command 2 = add_user */
    _send_command(command, command_len, &out, &out_len);
    free(command);
    
    int result = _agate_util_int_from_byte_array(out);
    free(out);

    return result;
}

/*
 * add a group owned by current logged in user, returns true on success
 */
bool agate_add_group(char* groupname) {
    char* out;
    char* command;
    char* tmp;
    int message_len, command_len, out_len;

    if(cur_userId == -1) {
        ALOGE("ERROR: UserMgmtModule: [agate_add_group] no currently logged in user.");
	return false;
    }

    if (groupname == NULL) {
        ALOGE("ERROR: UserMgmtModule: [agate_add_group] group argument is null.");
        return false;
    } else if(!validateName(groupname)) {
        ALOGE("ERROR: UserMgmtModule: [agate_add_group] group argument is invalid name.");
        return false;
    }
    
    /* Compose command for add_group */
    message_len = sizeof(int) + strlen(groupname);
    command_len = message_len + sizeof(int) + 1; // 1 char for command_type
    command = (char*)malloc(command_len + 1);
    tmp = command;
    *tmp++ = '3'; // command_type for add_group
    tmp = _agate_util_add_int(tmp, message_len);
    tmp = _agate_util_add_int(tmp, cur_userId);
    sprintf(tmp, "%s", groupname);

    /* Send command 3 = add_group */
    _send_command(command, command_len, &out, &out_len);
    free(command);

    int result = _agate_util_int_from_byte_array(out);
    free(out);

    return result;
}

/*
 * Adds specified user to specified group. Fails if currently logged in user
 * is not owner of group. Returns true on success
 */
bool agate_add_user_to_group(char* username, char* group) {
    char* out;
    char* command;
    char* tmp;
    int message_len, command_len, out_len;

    if(cur_userId == -1) {
        ALOGE("ERROR: UserMgmtModule: [addUserToGroup] no currently logged in user.");
	return false;
    }

    if (username == NULL || group == NULL) {
        ALOGE("ERROR: UserMgmtModule: [addUserToGroup] at least one argument is null.");
        return false;
    } else if(!validateName(username) || !validateName(group)) {
        ALOGE("ERROR: UserMgmtModule: [addUserToGroup] at least one of the arguments is invalid name.");
        return false;
    }

    /* Compose command for add_user_to_group */
    message_len = sizeof(int) + 1 + strlen(username) + 1 + strlen(group);
    command_len = message_len + sizeof(int) + 1; // 1 char for command_type
    command = (char*)malloc(command_len + 1);
    tmp = command;
    *tmp++ = '4'; // command_type for add_user_to_group
    tmp = _agate_util_add_int(tmp, message_len);
    tmp = _agate_util_add_int(tmp, cur_userId);
    sprintf(tmp, " %s %s", group, username);

    /* Send command 4 = add_user_to_group */
    _send_command(command, command_len, &out, &out_len);
    free(command);

    int result = _agate_util_int_from_byte_array(out);
    free(out);

    return result;
}

/* Asks user management to check if data can flow*/
bool agate_can_flow(int from, int to) {
    char* out;
    char* command;
    char* tmp;
    int message_len, command_len, out_len;

    if (from == 0) {
        //ALOGI("can flow as no policy on data");
        return true;
    }

    if (to == 0) {
        //ALOGI("can't flow as target is not logged in");
        return false; 
    }

    assert(from != 0);
    assert(to != 0);

    ALOGE("From policy:");
    agate_print_policy(from);

    ALOGE("To policy:");
    agate_print_policy(to);

    /* First, check if admin */
    int a_id = get_admin_id();
    ALOGE("AgateLog: Got admin id: %d", a_id);
    // for now, assume the to policy has just one user reader
    assert(((int*)(void*)((PolicyObject*)to)->user_readers->contents)[0] == 1);

    if ( ((int*)(void*)((PolicyObject*)to)->user_readers->contents)[1] == a_id)
        return true;

    int e_from_size;
    char* e_from = agate_encode_policy(&e_from_size, from);
    ALOGE("From policy: e_from_size = %d.", e_from_size);

    int e_to_size;
    char* e_to = agate_encode_policy(&e_to_size, to);
    ALOGE("To policy: e_to_size = %d.", e_to_size);

    /* Compose command for add_user_to_group */
    message_len = e_from_size + e_to_size;
    command_len = message_len + sizeof(int) + 1; // 1 char for command_type
    command = (char*)malloc(command_len + 1);
    tmp = command;
    *tmp++ = '5'; // command_type for add_user_to_group
    tmp = _agate_util_add_int(tmp, message_len);

    /* Put first the to policy, we assume it is only one reader */
    memcpy(tmp, e_to, e_to_size);
    memcpy(tmp + e_to_size, e_from, e_from_size);

    /* Send command 5 = can_flow */
    _send_command(command, command_len, &out, &out_len);
    free(command);

    int result = _agate_util_int_from_byte_array(out);
    free(out);

    return result;
}

/* The streams must be preceded by the number of elements.
 *
 *      Example stream: "3 username1 username2 username3 "
 *
 *  Each name must be followed by a space. If there are no names, a space at
 *  the end is still required.
 *
 *      Example stream: "0 "
 */
char* get_users_and_groups_ids(char* users_stream, int u_size, char* groups_stream, int g_size, int total_len) {
    char* out;
    char* command;
    char* tmp;
    int message_len, command_len, out_len;

    /* Compose command for get_users_and_groups_ids */
    message_len = 2 * sizeof(int) + u_size + g_size;
    command_len = message_len + sizeof(int) + 1; // 1 char for command_type
    command = (char*)malloc(command_len + 1);
    tmp = command;
    *tmp++ = '6'; // command_type for get_users_and_groups_ids
    tmp = _agate_util_add_int(tmp, message_len);
    tmp = _agate_util_add_int(tmp, cur_userId);
    tmp = _agate_util_add_int(tmp, total_len); // need total_len to know how mush space to allocate
    memcpy(tmp, users_stream, u_size);
    memcpy(tmp + u_size, groups_stream, g_size);

    ALOGW("AgateLog: [AgateUser.cpp get_users_and_groups_ids] u_size = %d", u_size);
    ALOGW("AgateLog: [AgateUser.cpp get_users_and_groups_ids] g_size = %d", g_size);

    int g_len;
    _agate_util_get_int(tmp + u_size, &g_len);
    ALOGW("AgateLog: [AgateUser.cpp get_users_and_groups_ids] Groups len = %d", g_len);

    /* Send command 6 = get_users_and_groups_ids */
    _send_command(command, command_len, &out, &out_len);
    free(command);

    return out;
}


/* For testing */
//int main(int argc, char ** argv) {
//    printf("%d", agate_login((char*)"aaasz", (char*)"aaasz"));
//    printf("%d", agate_add_user((char*)"user0", (char*)"user0"));
//    printf("%d", agate_add_group((char*)"followers"));
//    printf("%d", agate_add_user_to_group((char*)"user0", (char*)"followers"));
//}
