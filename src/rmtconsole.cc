#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

#include "tm.h"
#include "Storage.hh"
#include "conf.h"
#include "bro_inet_ntop.h"

/* External functions and vars */
extern Storage* storage;



/* like (f)gets, but uses fds CR/NL are omitted*/
char* llgets(char* s, int size, int fd) {
	int res;
	char *e=s+size, *p;
	for (p=s; p<e; ++p) {
		res=read(fd, p, 1);
		if (res<0 || (res==0 && p==s))  /* error while reading or  EOF von fd */
			return NULL;
		if (res==0 || *p=='\n' || *p=='\r') {
			*p='\0';
			return s;
		}
	}
	*e='\0';
	return s;
}

void *
rmtconsole_worker_thread(void *arg) {
	int sock = *((int*)arg);
	FILE *sock_as_fp;
	char line[512];
		
	tmlog(TM_LOG_NOTE, "rmtconsole", "CLI worker thread started with fd %u", sock);
	sock_as_fp = fdopen(sock, "w");
	if (sock_as_fp==NULL) {
		//TODO: decent error handling
		tmlog(TM_LOG_ERROR, "rmtconsole", "ERROR: something's strange with the socket. Couldn't fdopen the socket");
		close(sock);
		return NULL;
	}
	setlinebuf(sock_as_fp);

		/* Request aus dem Stream lesen */
	while (llgets(line, sizeof(line), sock)!=NULL) {
		if (strlen(line)!=0) { // ignore empty lines
			//fprintf(stderr, "RECEIVED CMD FROM NET: >>%s<<\n", line);
			parse_cmd(line, sock_as_fp, storage, 0);
		}
	} 
	tmlog(TM_LOG_NOTE, "rmtconsole", "CLI worker thread is exiting");
	fclose(sock_as_fp);
	free(arg);
	pthread_exit(NULL);
	return NULL;
}


//TODO: error handling 
void *
rmtconsole_listen_thread(void *arg) {

	int listen_sock;
	int *conn_sock_p;
	pthread_t cli_thread_tid;
	int one=1;
	struct sockaddr_in local_addr, remote_addr;
	socklen_t addrlen;
	char addrbuf[32];

	/* Socketadresse vorbereiten */
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family=AF_INET;
	local_addr.sin_port=htons(conf_main_rmtconsole_port);
	//local_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	local_addr.sin_addr = conf_main_rmtconsole_listen_addr;


	/* Create listen socket */
	listen_sock=socket(PF_INET, SOCK_STREAM, 0);
	if (listen_sock<0) {
		tmlog(TM_LOG_ERROR, "rmtconsole", "Could not create a listen socket");
		return NULL;
		exit(1);
	}
	

	/* reuse address */
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int))) {
		tmlog(TM_LOG_ERROR, "rmtconsole", "Could not set SO_REUSEADDR for listen socket");
		return NULL;
	}

	/* Socket an Port binden */
	if (bind(listen_sock, (struct sockaddr*) &local_addr, sizeof(local_addr))) {
		tmlog(TM_LOG_ERROR, "rmtconsole", "Could not bind for listen socket");
		return NULL;
	}
	if (listen(listen_sock, 5)) {
		tmlog(TM_LOG_ERROR, "rmtconsole", "Could not listen on listen socket");
		return NULL;
	}
	tmlog(TM_LOG_NOTE, "rmtconsole", "socket ready, listening on port %d",
			conf_main_rmtconsole_port);


	/* Accept connections, spwan threads */
	while(1) {
		conn_sock_p = (int *)malloc(sizeof(int));
		addrlen=sizeof(remote_addr);
		memset(&remote_addr, 0, sizeof(remote_addr));
		*conn_sock_p=accept(listen_sock, (struct sockaddr*) &remote_addr, &addrlen);
		if (*conn_sock_p<0) {
			tmlog(TM_LOG_ERROR, "rmtconsole", "Could not accept incoming connection.");
			continue;
		}

		
		tmlog(TM_LOG_NOTE, "rmtconsole", "incoming connection from %s port %d",
		       bro_inet_ntop(AF_INET, &remote_addr.sin_addr,
		                 addrbuf, sizeof(addrbuf)),
		       ntohs(remote_addr.sin_port));
		// FIXME: Check return values
		pthread_create(&cli_thread_tid, NULL, rmtconsole_worker_thread, conn_sock_p);
		pthread_detach(cli_thread_tid); // we don't want to join our worker threads


	} 
	//printf("rmtconsole_listen_thread\n");
	return NULL;

}

