#include "Dalvik.h"
#include "native/InternalNativePriv.h"
#include "attr/xattr.h"
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>


#define XATTR_NAME "user.UserMgmtModule"


/* Send Query request */
void sendQuery(char buffer[256],char out[256])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    portno = 24068;
    bzero(out,256);
    /* Create a socket point */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        strcpy(out,"-2");
    }else{
	    //server = gethostbyname("localhost");
	    server = gethostbyname("dunbar.cs.washington.edu");
	    if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		strcpy(out,"-3");
	    }else{
		    bzero((char *) &serv_addr, sizeof(serv_addr));
		    serv_addr.sin_family = AF_INET;
		    bcopy((char *)server->h_addr,
			   (char *)&serv_addr.sin_addr.s_addr,
				server->h_length);
		    serv_addr.sin_port = htons(portno);

		    /* Now connect to the server */
		    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
		    {
			 perror("ERROR connecting");
			 strcpy(out,"-4");
		    }else{

			    /* Send message to the server */
			    n = write(sockfd,buffer,strlen(buffer));
			    if (n < 0)
			    {
				 perror("ERROR writing to socket");
				 strcpy(out,"-5");
			    }else{
				    /* Get server response */
				    bzero(out,256);
				    n = read(sockfd,out,255);
				    if (n < 0) 
				    {
					 perror("ERROR reading from socket");
					 strcpy(out,"-6");
				    }
			    }
		    }
	    }
    }
}

/*
 * public static void getID(char user[256],char password[256]))
 */
static void Dalvik_dalvik_system_UserMgmtModule_getID(const u4* args,
    JValue* pResult)
{
    char buffer[256];
    char out[256];


    StringObject *strObjUser = (StringObject*) args[0];
    StringObject *strObjPassword = (StringObject*) args[1];
    if (strObjUser == NULL || strObjPassword == NULL) {
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
    strcpy(buffer,"SELECT * FROM Users where username='");
    strcat(buffer, (char*) strObjUser->chars());
    strcat(buffer,"' AND password='");
    strcat(buffer, (char*) strObjPassword->chars());
    strcat(buffer,"'");

    sendQuery(buffer, out);

    RETURN_INT(atoi(out));
}



const DalvikNativeMethod dvm_dalvik_system_UserMgmtModule[] = {
    	{ "getID",  "(Ljava/lang/String;Ljava/lang/String)V",
        Dalvik_dalvik_system_UserMgmtModule_getID},
	{ NULL, NULL, NULL },
};
