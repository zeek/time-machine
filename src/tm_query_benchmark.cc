#include "config.h"
#include <sys/time.h>
#include <string.h>
#include <broccoli.h>
#include <unistd.h>

#include "types.h"

/***************************************************************************
 * usage()
 */

void usage() {
	fprintf(stderr,
			"usage: tm_query_benchmark [-c bro_connect_string] [-q query] [-n queries/sec]\n"
			"         [-s runtime_seconds]\n");
	exit(1);
}


/***************************************************************************
 * callback handler for events received by broccoli
 */

void cmd_callback(BroConn* bc, void* userdata, BroString* bro_str) {
	// duplicate BroString, convert to a NULL-terminated char*
	char *c_str=(char *)malloc(bro_str->str_len+1);
	memcpy(c_str, bro_str->str_val, bro_str->str_len);
	c_str[bro_str->str_len]='\0';
	printf("cmd_callback(%p, %p, \"%s\")\n", bc, userdata, c_str);
	free(c_str);
};


/***************************************************************************
 * main()
 */

int main(int argc, char** argv) {
	BroConn *bc=NULL;
	bro_init(NULL);

	const char *conn_str="localhost:47757";
	int n=10, s=10;
	/*  char *query="query to_file file1 conn proto 6 131.159.74.1:80 "
	    "- 70.86.37.242:* start 1 end 1";*/
	char query[1000];

	/*******************************************************
	 * read command line arguments
	 */

	int opt;
	while ((opt=getopt(argc, argv, "c:q:n:s:h")) != -1) {
		switch(opt) {
		case 'c':
			conn_str=strdup(optarg);
			break;
		case 'q':
			//      query=strdup(optarg);
			break;
		case 'n':
			n=atoi(optarg);
			break;
		case 's':
			s=atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;



	/***************************************************************************
	 * connect to bro peer
	 */

	bc=bro_conn_new_str(conn_str, BRO_CFLAG_NONE);
	if (!bc) {
		fprintf(stderr, "Bro connection to %s failed "
				"(could not get broccoli handle)\n", conn_str);
		exit(-1);
	}

	bro_event_registry_add(bc, "TimeMachine::command",
		 (BroEventFunc)cmd_callback, NULL);
	bro_event_registry_request(bc);

	bro_conn_set_class(bc, "tm-proxy");

	if (!bro_conn_connect(bc)) {
		fprintf(stderr, "Bro connection to %s failed (could not connect)\n",
				conn_str);
		exit(-1);
	}

	printf("connected to %s\n", conn_str);

	//  bro_conn_set_packet_ctxt(bc, pcap_datalink(ph));

	// select loop
	fd_set rfds;
	int bc_fd=bro_conn_get_fd(bc);

	if (bc_fd<0) {
		fprintf(stderr, "bro_conn_get_fd() failed\n");
		exit(-1);
	}

	FD_ZERO(&rfds);
	FD_SET(bc_fd, &rfds);

	BroEvent *ev;

	struct timeval start, t;
	gettimeofday(&start, NULL);
	tm_time_t start_tm=to_tm_time(&start), t_tm=0;

	int i=0;

	for ( ; t_tm<start_tm+s ; ) {
		gettimeofday(&t, NULL);
		t_tm=to_tm_time(&t);
		int i_dest = (int)((to_tm_time(&t)-start_tm)*n);
		for (; i<i_dest; i++) {
			if (! (ev = bro_event_new("TimeMachineProxy::SendToTM"))) {
				fprintf(stderr, "Could not allocate new event\n");
				exit(-1);
			}

			BroString tm_cmd;
			snprintf(query, 1000, "query to_file file%d "
					 "conn proto 6 131.159.74.1:%d "
					 "- 70.86.37.242:* start 1 end 1", i, i);
			bro_string_set(&tm_cmd, query);

			bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &tm_cmd);
			bro_string_cleanup(&tm_cmd);

			bro_event_send(bc, ev);
			printf("sent event %d\n", i);
			bro_event_free(ev);

			/*
			printf("bro_event_queue_length() is %d\n",
			bro_event_queue_length(bc));
			*/
		}

		usleep(1);
	}


	/* select loop  */
	while (0) {
		int sel_rc=select(bc_fd+1, &rfds, NULL, NULL, NULL);
		if (sel_rc<0) {
			//	fprintf(stderr, "Bro connection broke; terminating Broccoli thread\n");
			fprintf(stderr, "Bro connection broke; attempting reconnect\n");
			if (!bro_conn_reconnect(bc)) {
				sleep(1);
				fprintf(stderr, "reconnection attempt failed\n");
			}

			/*
			log_file->log("broccoli",
			"Bro connection broke; terminating Broccoli thread");
			return(NULL);
			*/
		} // if (select error)
		if (!bro_conn_process_input(bc)) {
			fprintf(stderr, "Bro connection broke; attempting reconnect\n");
			if (!bro_conn_reconnect(bc)) sleep(1);
			/*
			fprintf(stderr, "Bro connection broke; terminating Broccoli thread\n");
			log_file->log("broccoli",
			"Bro connection broke; terminating Broccoli thread");
			return(NULL);
			*/
		}
	} // while (1)

}

