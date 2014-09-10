
#ifndef _DALVIK_AGATE_USER
#define _DALVIK_AGATE_USER

#include "Dalvik.h"

/*
 * returns the currently logged in user's username or null if no
 * such user. Please do not modify or free as is used internally
 */
char* agate_get_user();
int agate_get_userId();

/*
 *  attempt to login as username using password, return true on success
 */
bool agate_login(char* username, char* password);

/*
 * Adds a user with the specified username and password, returns true on success
 */
bool agate_add_user(char* username, char* password);

/*
 * add a group owned by current logged in user, returns true on success
 */
bool agate_add_group(char* group);

/*
 * Adds specified user to specified group. Fails if currently logged in user
 * is not owner of group. Returns true on success
 */
bool agate_add_user_to_group(char* username, char* group);

/* Policy flow check */
bool agate_can_flow(int from, int to);

/* Get IDs of users and groups */
char* get_users_and_groups_ids(char* users_stream, int u_size, char* groups_stream, int g_size, int total_len);

#endif /*_DALVIK_AGATE_USER */
