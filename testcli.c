/*
Timemachine
Copyright (c) 2006 Technische Universitaet Muenchen,
                   Technische Universitaet Berlin,
                   The Regents of the University of California
All rights reserved.


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the names of the copyright owners nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// $Id: testcli.c 112 2006-11-11 04:30:51Z gregor $

#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/fd.h>


/***************************************************************************
 * CLI wthread linehandler
 */

void *cli_thread_lhandler(char* line) {
	printf("lhandler: %s\n", line);
}


/***************************************************************************
 * CLI (worker) thread
 * args: filedescriptor from accept() call in dispatcher
 */

void *cli_thread(void *arg) {
#include <readline/readline.h>
	unsigned char buf[8192];
	ssize_t n;
	char *line;
#define FD *(int *)arg
	int pipe_fd[2][2];
	FILE *stream[2][2], *netsock_r, *netsock_w;
	int sockoptval, i, j;

	printf("CLI worker thread started with fd %d\n", FD);


	if (pipe(pipe_fd[0]) || pipe(pipe_fd[1])) {
		perror("pipe");
		exit(-1);
	}

	stream[0][0]=fdopen(pipe_fd[0][0], "r");
	stream[0][1]=fdopen(pipe_fd[0][1], "w");
	stream[1][0]=fdopen(pipe_fd[1][0], "r");
	stream[1][1]=fdopen(pipe_fd[1][1], "w");

	for (i=0; i<2; i++)
		for (j=0; j<2; j++)
			if (stream[i][j]==NULL) {
				perror("fdopen");
				exit(-1);
			}

	/*
	sockoptval=1;

	if (setsockopt(FD, SOL_SOCKET, SO_SNDBUF, (const int *)&sockoptval, 
	 sizeof(sockoptval))) {
	  perror("setsockopt SO_SNDBUF");
	  exit(-1);
	}
	*/

	netsock_r=fdopen(FD, "r");
	netsock_w=fdopen(FD, "w");
	if (netsock_r==NULL || netsock_w==NULL) {
		perror("fdopen");
		exit(-1);
	}

	if (setvbuf(netsock_w, NULL, _IONBF, 0)) {
		perror("setvbuf");
		exit(-1);
	}

	/*  rl_instream=stream[0][0];
	    rl_outstream=stream[1][1]; */
	rl_instream=netsock_r;
	rl_outstream=netsock_w;

	rl_terminal_name="xterm";
	printf("rl_terminal_name %s\n",rl_terminal_name);

	//  rl_callback_handler_install("hi# ", (rl_vcpfunc_t *)cli_thread_lhandler);

	const char* telnet_init=
		"\xFF\xFB\x01" // will echo
		"\xFF\xFE\x01" // don't echo
		"\xFF\xFE\x22" // don't linemode
		"\xFF\xFB\x03" // will suppress gohead
		;
	send(FD, telnet_init, strlen(telnet_init), 0);

	/*
	do {
	  i=recv(FD, buf, 1, 0);
	  switch (buf[0]) {
	  case 0xFF:
	    // telnet ESC
	    i=recv(FD, buf+1, 2, 0);
	    if (i==2) printf(" tn %02X %02X %02X\n", buf[0],buf[1],buf[2]);
	    else printf(" tn fail! i=%d\n",i);
	    break;
	  case 0x00:
	    break;
	  case 0x0D:
	    // CR
	    buf[1]=0x0a; // LF
	    j=send(FD, buf, 2, 0);
	    //      break;
	  default:
	    j=send(FD, buf, 1, 0);
	    printf("putc\n");
	    putc(buf[0], stream[0][1]);
	    fflush(stream[0][1]);
	    printf("putc done\n");
	    printf("rl_callback_read_char\n");
	    rl_callback_read_char();
	    printf("rl_callback_read_char done\n");
	    printf("-- %c\n", buf[0]);
	  } // switch
	  //    if (select(stream[1][0])) 

	} while (i>0 && j>0);
	*/


	do {
		line=readline("hi# ");
		fflush(netsock_w);
		if (line !=NULL ) {
			printf("CLI fd %d len %d# %s\n", FD, strlen(line), line);
			add_history(line);

		}
	} while (line != NULL);

	/* w/o readline
	while ((n=read(FD, buf, 8192))>0) {
	  buf[n+1]=0;
	  printf("CLI worker thread fd %d: read %d bytes --\n -- %s", FD, n, buf);
	}
	*/

	//  fclose(rstream);
	//  fclose(wstream);

	printf("CLI worker thread fd %d exiting, recv() rc was %d, send() rc was %d\n", FD, i, j);

	close(FD);

	free(arg);

} /* cli_thread */



/***************************************************************************
 * CLI server (dispatcher) thread
 * sets up socket, "bind"s, "setsockopt"s, "listen"s and "accept"s
 * dispatches incoming connections to "cli_thread"s
 */

void *cli_server_thread(void *arg) {
	int server_sock;
	int *worker_sock;
	struct sockaddr_in local_sin, remote_sin;
	int remote_sin_len=sizeof(remote_sin);

	pthread_t cli_thread_tid;

	int sockoptval;

	memset(&local_sin, 0, sizeof(local_sin));
	memset(&remote_sin, 0, sizeof(remote_sin));

	//  local_sin.sin_addr.s_addr=htonl(INADDR_ANY);
	if (!inet_aton("127.0.0.1", &local_sin.sin_addr)) {
		perror("inet_aton");
		exit(-1);
	}
	local_sin.sin_family=AF_INET;
	local_sin.sin_port=htons(42042);

	server_sock=socket(PF_INET, SOCK_STREAM, 0);
	if (server_sock==-1) {
		perror("socket");
		exit(-1);
	}

	sockoptval=1;
	if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&sockoptval,
				   sizeof(sockoptval))) {
		perror("setsockopt SO_REUSEADDR");
		exit(-1);
	}


	/*
	sockoptval=2;
	if (setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, (const int *)&sockoptval, 
	 sizeof(sockoptval))) {
	  perror("setsockopt SO_SNDBUF");
	  exit(-1);
	}
	*/

	if (bind(server_sock, (struct sockaddr *)&local_sin, sizeof(local_sin))) {
		perror("bind");
		exit(-1);
	}

	if (listen(server_sock, 2)==-1) {
		perror("listen");
		exit(-1);
	}

	printf("CLI server thread started, socket fd %d in listening state\n",
		   server_sock);

	while (1) {
		worker_sock=(int *)malloc(sizeof(worker_sock));
		*worker_sock=accept(server_sock, (struct sockaddr *)&remote_sin,
							&remote_sin_len);
		if (*worker_sock==-1) {
			perror("accept");
			continue;
		}
		pthread_create(&cli_thread_tid, NULL, cli_thread, worker_sock);
		printf("client connection from %s:%d dispatched to thread id %d\n",
			   inet_ntoa(remote_sin.sin_addr),
			   ntohs(remote_sin.sin_port),
			   cli_thread_tid);
	}

	printf("CLI thread exiting\n");
} /* cli_server_thread() */



int main(int argc, char** argv) {
	pthread_t cli_server_thread_tid;
	int i;
	i=pthread_create(&cli_server_thread_tid, NULL, cli_server_thread, NULL);
	if (i) {
		perror("thread");
		exit(-1);
	}

	while (1) {
		sleep(1);
		printf(".");
		fflush(stdout);
	}

}
