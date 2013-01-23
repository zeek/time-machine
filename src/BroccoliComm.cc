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

// $Id: Storage.hh 191 2007-03-08 22:16:21Z gregor $

#include "BroccoliComm.hh"

#ifdef HAVE_LIBBROCCOLI

#include <errno.h>
#include <broccoli.h>
#include <list>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include "tm.h"

pthread_mutex_t bc_mutex;
pthread_t broccoli_listen_thread_tid = 0;
int broccoli_recv_q=0;
int broccoli_recv_q_peak=0;

struct broccoli_worker_thread_data {
	int fd;
	pthread_t tid;
	BroConn *bc;
	bool active;
};

pthread_mutex_t broccoli_workers_mutex;
std::list<broccoli_worker_thread_data *> broccoli_workers;

void broccoli_cmd_callback(BroConn* bc, void* userdata, BroString* bro_str) {
	broccoli_worker_thread_data* thread = (broccoli_worker_thread_data *)userdata;

	char *c_str=(char *)malloc(bro_str->str_len+1);
	memcpy(c_str, bro_str->str_val, bro_str->str_len);
	c_str[bro_str->str_len]='\0';
	parse_cmd(c_str, NULL, storage, thread);

	BroEvent *ev = bro_event_new("cmd_done");
	if ( ! ev ) 
		tmlog(TM_LOG_WARN, "broccoli-worker",  "cannot create reply event [%x]", thread->tid);
	else {
		// TODO: Turn output into event parameter.
		bro_event_send(thread->bc, ev);
		bro_event_free(ev);
		bro_event_queue_flush(thread->bc);
	}
	
	free(c_str);
};


void broccoli_worker_thread_cleanup(void *arg) {

	broccoli_worker_thread_data* thread = (broccoli_worker_thread_data *)arg;

	tmlog(TM_LOG_DEBUG, "broccoli-worker",  "cleaning up Broccoli worker [%x]", thread->tid);

	if ( thread->fd >= 0 )
		close(thread->fd);

	pthread_mutex_lock(&bc_mutex);
	bro_conn_delete(thread->bc);
	pthread_mutex_unlock(&bc_mutex);
}

void *broccoli_worker_thread(void *arg) {

	broccoli_worker_thread_data* thread = (broccoli_worker_thread_data *)arg;

	const char* peer_name = conf_main_bro_connect_str ? conf_main_bro_connect_str : "remote host";
    
	tmlog(TM_LOG_DEBUG, "broccoli-worker",  "running Broccoli worker [%x]", thread->tid);

	// Schedule cleanup of thread data.
	pthread_cleanup_push(broccoli_worker_thread_cleanup, thread);

	if (conf_main_bro_connect_str || thread->fd >= 0) {
        
		pthread_mutex_lock(&bc_mutex);
		bro_init(NULL);
	
        if ( thread->fd < 0 )
            thread->bc=bro_conn_new_str(conf_main_bro_connect_str,
                                BRO_CFLAG_YIELD
                                // | BRO_CFLAG_ALWAYS_QUEUE
                                // | BRO_CFLAG_SHAREABLE
                                );
        else
            thread->bc = bro_conn_new_socket(thread->fd, BRO_CFLAG_YIELD);
        
		if (!thread->bc) {
			tmlog(TM_LOG_ERROR, "broccoli-worker", "connection to %s failed (could not get broccoli handle); "
						  "terminating Broccoli thread [%d]",
						  peer_name, thread->tid);
			pthread_mutex_unlock(&bc_mutex);
			return(NULL);
		}

		bro_event_registry_add(thread->bc, "TimeMachine::command",
							   (BroEventFunc)broccoli_cmd_callback, thread);
		bro_event_registry_request(thread->bc);

		if (!bro_conn_connect(thread->bc)) {
			tmlog(TM_LOG_ERROR, "broccoli-worker", "connection to %s failed; "
						  "terminating Broccoli thread [%x]",
						  peer_name, thread->tid);
			pthread_mutex_unlock(&bc_mutex);
			return(NULL);
		}
  	    
	    tmlog(TM_LOG_NOTE, "broccoli-worker", "connected to %s [%x]", peer_name, thread->tid);

		bro_conn_set_packet_ctxt(thread->bc, storage->getPcapDatalink());

		// select loop
		int bc_fd=bro_conn_get_fd(thread->bc);

		if (bc_fd<0) {
			tmlog(TM_LOG_ERROR, "broccoli-worker", "bro_conn_get_fd() failed; terminating broccoli thread [%x]", thread->tid);
			pthread_mutex_unlock(&bc_mutex);
			return(NULL);
		}

		pthread_mutex_unlock(&bc_mutex);
	
		/* select loop
		 */
		while (1) {
            
			fd_set rfds;
			fd_set wfds;
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(bc_fd, &rfds);
			FD_SET(bc_fd, &wfds);

			bool need_write = bro_event_queue_length(thread->bc) > 0;
            
			// We use a small timeout with the select() as there might still
			// be some unprocessed data in Broccoli's buffers which we
			// wouldn't get to work on otherwise. 
			struct timeval timeout;
			timeout.tv_sec = 0;
			timeout.tv_usec = 100; 
            
			int sel_rc = select(bc_fd+1, &rfds, (need_write ? &wfds : NULL), NULL, &timeout);
		
			if ( sel_rc < 0 && (errno == EINTR || errno == EAGAIN) )
				continue;
		
			bool closed = sel_rc < 0;

			if ( ! closed ) {
				pthread_mutex_lock(&bc_mutex);
				int proc = bro_conn_process_input(thread->bc);

				if ( proc == 0 ) 
					closed = !bro_conn_alive(thread->bc); 
                
				pthread_mutex_unlock(&bc_mutex);
			
			}
		
			if ( closed ) {
			
			    if ( thread->fd >= 0 ) {
    				// Remote side initiated connection. Just terminate the thread.
					tmlog(TM_LOG_NOTE, "broccoli-worker", "connection closed [%x]", thread->tid);
					break;
				}
			
				tmlog(TM_LOG_ERROR, "broccoli-worker", "connection broke; attempting reconnect [%x]", thread->tid);
			
				pthread_mutex_lock(&bc_mutex);
				int i = bro_conn_reconnect(thread->bc);
				pthread_mutex_unlock(&bc_mutex);
			
				if ( ! i )
					sleep(5);
			}
		} // while (1)
	} // if (conf_main_bro_connect_str)

	pthread_mutex_lock(&broccoli_workers_mutex);
	thread->active = false;
	pthread_mutex_unlock(&broccoli_workers_mutex);

	tmlog(TM_LOG_DEBUG, "broccoli-worker",  "terminating Broccoli worker [%x]", thread->tid );

	pthread_cleanup_pop(0); // must be paired with _push().
	broccoli_worker_thread_cleanup(thread);
	
	return NULL;
}

void broccoli_start_worker_thread(int fd) {

	const char* const dbg_tag = fd >= 0 ? "broccoli-listen" : "broccoli-init";

	// Collect old threads.
	std::list<broccoli_worker_thread_data *> terminated; 
	std::list<broccoli_worker_thread_data *>::iterator i;

	pthread_mutex_lock(&broccoli_workers_mutex);

	for ( i = broccoli_workers.begin();  i != broccoli_workers.end(); i++ ) {
		if ( ! (*i)->active )
			terminated.push_back(*i);
	}

	pthread_mutex_unlock(&broccoli_workers_mutex);

	for ( i = terminated.begin(); i != terminated.end(); i++ ) {
	
		tmlog(TM_LOG_DEBUG, dbg_tag,  "joining Broccoli worker [%x]", (*i)->tid);
	
		pthread_join((*i)->tid, NULL);
		delete *i;
		
		pthread_mutex_lock(&broccoli_workers_mutex);
		broccoli_workers.remove(*i);
		pthread_mutex_unlock(&broccoli_workers_mutex);
	}

	// Init data for new threa.
	broccoli_worker_thread_data* thread = new broccoli_worker_thread_data;
	thread->fd = fd;
	thread->bc = 0;
	thread->active = true;

	// Start thread.
	int failed = pthread_create(&thread->tid, NULL, broccoli_worker_thread, thread);
	if ( failed ) {
		tmlog(TM_LOG_ERROR, dbg_tag, "could not start broccoli thread");
		exit(1);
	}

	// Add thread to list of currently active threads.
	pthread_mutex_lock(&broccoli_workers_mutex);
	broccoli_workers.push_back(thread);
	pthread_mutex_unlock(&broccoli_workers_mutex);

	tmlog(TM_LOG_DEBUG, dbg_tag, "started Broccoli worker [%x]", thread->tid );
}

void *broccoli_listen_thread(void *arg) {
    int fd = 0;
    struct sockaddr_in server;
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    const int turn_on = 1;

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if ( fd < 0 ) {
        tmlog(TM_LOG_ERROR, "broccoli-listen", "can't create listen socket: %s\n", strerror(errno));
        exit(-1);
	}
    
    // Set SO_REUSEADDR.
    if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &turn_on, sizeof(turn_on)) < 0 ) {
        tmlog(TM_LOG_ERROR, "broccoli-listen", "can't set SO_REUSEADDR: %s\n", strerror(errno));
        exit(-1);
	}

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(conf_main_bro_listen_port);
    server.sin_addr = conf_main_bro_listen_addr;

    if ( bind(fd, (struct sockaddr*) &server, sizeof(server)) < 0 ) {
        tmlog(TM_LOG_ERROR, "broccoli-listen", "can't bind to port %d: %s\n", conf_main_bro_listen_port, strerror(errno));
        exit(-1);
	}

    if ( listen(fd, 50) < 0 ) {
        tmlog(TM_LOG_ERROR, "broccoli-listen", "can't listen: %s\n", strerror(errno));
        exit(-1);
	}

    tmlog(TM_LOG_NOTE, "broccoli-listen", "listening for incoming connections on port %d...", conf_main_bro_listen_port);

    // Loop for incoming connections.
    while ( true ) {
    
        int client_fd = accept(fd, (struct sockaddr*) &client, &len);
        if ( client_fd < 0 )  {
            tmlog(TM_LOG_ERROR, "broccoli-listen", "can't accept: %s\n", strerror(errno));
            exit(-1);
        }

        tmlog(TM_LOG_NOTE, "broccoli-listen", "accepted connection");
        broccoli_start_worker_thread(client_fd);
    }
    
	return(NULL);
} 

void broccoli_start_listen_thread() {
	int i=pthread_create(&broccoli_listen_thread_tid, NULL, broccoli_listen_thread, NULL);
	if (i) {
		tmlog(TM_LOG_ERROR, "broccoli-init", "could not start listen thread");
		exit(1);
	}
	tmlog(TM_LOG_NOTE, "broccoli-init", "listen_thread started [%x]", broccoli_listen_thread_tid);
	}

void broccoli_send_packet(broccoli_worker_thread_data* bc_thread, 
		const struct pcap_pkthdr *header, const unsigned char *packet, const string& tag)
	{
	if ( ! bro_conn_alive(bc_thread->bc))
		return ;
	
	BroPacket* broccoli_packet_p=bro_packet_new(header, packet, tag.c_str());
	bro_packet_send(bc_thread->bc, broccoli_packet_p);
	bro_packet_free(broccoli_packet_p);
	}

void broccoli_init()
{
	// bro_debug_messages = 1;

	pthread_mutex_init(&broccoli_workers_mutex, NULL);
	pthread_mutex_init(&bc_mutex, NULL);

	if ( conf_main_bro_listen )
    	broccoli_start_listen_thread();

	if ( conf_main_bro_connect_str )
		broccoli_start_worker_thread(-1);
}

void broccoli_exit()
{
	// Cancel Broccoli listen thread.
	if ( broccoli_listen_thread_tid >= 0 ) {
		tmlog(TM_LOG_DEBUG, "broccoli-exit",  "canceling Broccoli listen");
		pthread_cancel(broccoli_listen_thread_tid);
		tmlog(TM_LOG_DEBUG, "broccoli-exit",  "joining Broccoli listen");
		pthread_join(broccoli_listen_thread_tid, NULL);
	}

	// Cancel Broccoli worker threads.
	std::list<broccoli_worker_thread_data *>::iterator i;
	for ( i = broccoli_workers.begin(); i != broccoli_workers.end(); i++ ) {
		
		broccoli_worker_thread_data* thread = *i;
	
		pthread_mutex_lock(&broccoli_workers_mutex);
		bool active = thread->active;
		pthread_mutex_unlock(&broccoli_workers_mutex);

		if ( active ) {
			tmlog(TM_LOG_DEBUG, "broccoli-exit",  "canceling Broccoli worker [%x]", thread->tid );
			pthread_cancel(thread->tid);
		}
	
		tmlog(TM_LOG_DEBUG, "broccoli-exit",  "joining Broccoli worker [%x]", thread->tid);
		pthread_join(thread->tid, NULL);
	
		delete thread;
	}
	
	broccoli_workers.clear();

}

#endif
