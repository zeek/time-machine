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
// bropipe.cc: pipe version of generic client
// 02/04/05

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include "broccoli.h"

using std::string;
using std::vector;
using std::cout;
using std::cin;
using std::cerr;

#define FIFONAME "brocsock"
string default_host = "127.0.0.1";
string default_port = "47757";
string host;
string port;
int count = -1;
int seq;

void usage(void) {
	cout << "broclient - sends events with string arguments from stdin to a\n"
	"	running Bro\n"
	"USAGE: broclient [-p port=47757] [host=127.0.0.1]\n"
	"Input format (each line): event_name type=arg1 type=arg2...\n";
	exit(0);
}

void showtypes(void) {
	cout << "Legitimate event types are:\n"
	"	string, int, count, double, bool, time, \n"
	"	interval, port, addr, net, subnet\n\n"
	"	examples: string=foo, port=23/tcp, addr=10.10.10.10, \n"
	"	net=10.10.10.0 and subnet=10.0.0.0/8\n";
	exit(0);
}

void tokenize(const string& str, vector<string>& tokens) {
	int num_tokens = 0;
	char delim = '\0';

	for ( unsigned int i = 0; i < str.length(); ++i ) {
		while ( isspace(str[i]) )
			++i;

		string next_arg;

		if (str[i] == '"' || str[i] == '\'') {
			delim = str[i];
			++i;
		} else
			delim = '\0';

		for ( ; str[i]; ++i ) {
			if ( delim && str[i] == '\\' &&
					i < str.length() && str[i+1] == delim ) {
				++i;
				next_arg.push_back(str[i]);
			}
			else if ( delim && str[i] == delim ) {
				++i;
				break;
			}
			else if ( ! delim && isspace(str[i]) )
				break;
			else
				next_arg.push_back(str[i]);
		}

		tokens.push_back(next_arg);
	}
}

void ntokenize(const string& str, vector<string>& inText) {
	int num_tokens = 0;
	char delim = '\n';

	for ( unsigned int i = 0; i < str.length(); ++i ) {
		while ( isspace(str[i]) )
			++i;

		string next_arg;

		if (str[i] == '"' || str[i] == '\'') {
			delim = str[i];
			++i;
		} else
			delim = '\n';

		for ( ; str[i]; ++i ) {
			if ( delim && str[i] == '\\' &&
					i < str.length() && str[i+1] == delim ) {
				next_arg.push_back(str[i]);
				++i;
			}
			else if ( delim && str[i] == delim ) {
				break;
			}
			else if ( ! delim && isspace(str[i]) )
				break;
			else
				next_arg.push_back(str[i]);
		}

		inText.push_back(next_arg);
	}
}

int main(int argc, char **argv) {
	int fp,rc,n,c=0;
	int j;
	fd_set readfds;
	char buf[1024];
	struct timeval tv;
	BroConn *bc;

	int opt, use_record = 0, debugging = 0;
	extern char *optarg;
	extern int optind;

	host = default_host;
	port = default_port;

	while ( (opt = getopt(argc, argv, "p:dh?")) != -1) {
		switch (opt) {
		case 'd':
			debugging++;

			if (debugging == 1)
				bro_debug_messages = 1;

			if (debugging > 1)
				bro_debug_calltrace = 1;
			break;

		case 'h':
		case '?':
			usage();
			break;

		case 'p':
			port = optarg;
			break;

		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		host = argv[0];

	// now connect to the bro host - on failure, try again three times
	while (! (bc = bro_connect_str( (host + ":" + port).c_str(), BRO_CFLAG_COMPLETE_HANDSHAKE ))) {
		if ( c == 4 ) {
			cerr << "\n" << "Could not connect to Bro (" << host << ") at " <<
			host.c_str() << ":" << port.c_str() << "\n";
			exit(-1);
		}
		c = c +1;
		cerr << ".";
		sleep(1);
	}

	cerr << "\n" << "Connected to Bro (" << host << ") at " <<
	host.c_str() << ":" << port.c_str() << "\n";

	// take care of the pipe
	unlink(FIFONAME);

	if ( mkfifo(FIFONAME,0666) < 0) {
		perror("mkfifo");
		exit(1);
	}

	fp = open(FIFONAME, O_RDONLY);
	if(fp <= 0)
		return(-1);

	FD_ZERO(&readfds);
	FD_SET(fp, &readfds);

	// socket and pipe are set up, now start processing
	while(1) {
		string inp;
		vector<string> inText; //text inputts within the pipe
		vector<string> tokens;

		// select loop
		tv.tv_sec = tv.tv_usec = 1;
		tv.tv_sec = 0;
		rc = select(1, &readfds, NULL, NULL, &tv);

		if(rc < 0) {
			close(fp);
			return(-1);
		}

		n = read(fp, buf, sizeof(buf)-1);
		buf[n]='\0';

		inp = buf;


		// we may have several lines put into the pipe at once.
		// chop the input up on '\n' boundries and feed it to the
		// rest of the program...
		ntokenize(inp, inText);

		BroEvent *ev;
		bro_conn_process_input(bc);

		for(j=0;j<inText.size();++j) {

			tokens.clear(); // make sure that the vector is clear
			tokenize(inText[j].c_str(), tokens);

			fprintf(stderr, "event \"%s\"\n", tokens[0].c_str());

			if ( (ev = bro_event_new(tokens[0].c_str())) ) {
				for ( unsigned int i = 1; i < tokens.size(); ++i ) {
					// this is something of a nasty hack, but it does work
					string tkn,tkn_type,tkn_data;
					char delim = '=';

					tkn=tokens[i].c_str();
					string::size_type position = tkn.find_first_of("=",0);

					tkn_type = tkn.substr(0,position);
					tkn_data = tkn.substr(position+1,tkn.length());

					if ( tkn_type == "string" ) {
						BroString arg;
						bro_string_init(&arg);
						bro_string_set(&arg,tkn_data.c_str());
						fprintf(stderr, "string = \"%s\"\n", tkn_data.c_str());
						bro_event_add_val(ev, BRO_TYPE_STRING, &arg);
						bro_string_cleanup(&arg);
					} else if ( tkn_type == "int" ) {
						int bint;
						bint = atoi(tkn_data.c_str());
						bro_event_add_val(ev, BRO_TYPE_INT, &bint);
					} else if ( tkn_type == "count" ) {
						uint32 buint;
						buint = atoi(tkn_data.c_str());
						bro_event_add_val(ev, BRO_TYPE_COUNT, &buint);
					} else if ( tkn_type == "double" ) {
						double bdouble;
						char* end_s;
						bdouble = strtod(tkn_data.c_str(),&end_s);
						bro_event_add_val(ev, BRO_TYPE_DOUBLE, &bdouble);
					} else if ( tkn_type == "bool" ) {
						int bbool=0;

						if ( tkn_data.c_str() == "T" ||
								tkn_data.c_str() == "TRUE" ||
								tkn_data.c_str() == "1" )
							bbool = 1;

						bro_event_add_val(ev, BRO_TYPE_BOOL, &bbool);
					} else if ( tkn_type == "time" ) {
						double btime;
						char* end_s;
						btime = strtod(tkn_data.c_str(),&end_s);
						bro_event_add_val(ev, BRO_TYPE_TIME, &btime);
					} else if ( tkn_type == "interval" ) {
						double binterval;
						char* end_s;
						binterval = strtod(tkn_data.c_str(),&end_s);
						bro_event_add_val(ev, BRO_TYPE_INTERVAL, &binterval);
					} else if ( tkn_type == "port" ) {
						BroPort BP;
						string port_value;
						string::size_type port_offset;
						int broport;

						//determine protocol type, start with tcp/udp do icmp
						// later since the 'ports' are not as simple...
						if ( tkn_data.find("tcp",0) <tkn_data.length() )
							BP.port_proto = IPPROTO_TCP;
						else BP.port_proto = IPPROTO_UDP;

						// parse out the numeric values
						port_offset = tkn_data.find_first_of("/",0);
						port_value = tkn_data.substr(0,port_offset);

						broport = atoi(port_value.c_str());
						BP.port_num = broport;
						bro_event_add_val(ev, BRO_TYPE_PORT, &BP);
					} else if ( tkn_type == "addr" ) {
						uint32 badd;
						badd=htonl((uint32)inet_addr(tkn_data.c_str()));

						bro_event_add_val(ev, BRO_TYPE_IPADDR, &badd);
					} else if ( tkn_type == "net" ) {
						uint32 bnet;
						bnet=htonl((uint32)inet_addr(tkn_data.c_str()));

						bro_event_add_val(ev, BRO_TYPE_NET, &bnet);
					} else if ( tkn_type == "subnet" ) {
						// this is assuming a string that looks like
						// "subnet=10.0.0.0/8"
						BroSubnet BS;
						string subnet_value;
						string subnet_width;
						string::size_type mask_offset;
						uint32 sn_net, sn_width;

						//parse out numeric values
						mask_offset = tkn_data.find_first_of("/",0);
						subnet_value = tkn_data.substr(0,mask_offset);
						subnet_width = tkn_data.substr(mask_offset+1,tkn_data.length());

						sn_net = (uint32)inet_addr(subnet_value.c_str());
						sn_width = (uint32)atol(subnet_width.c_str());

						BS.sn_net = sn_net;
						BS.sn_width = sn_width;

						bro_event_add_val(ev, BRO_TYPE_SUBNET, &BS);
					} else {
						// there is something wrong here with the data
						// type.  since it might be binary data, don't
						// punt it out.  Also showtypes() will just toss
						// junk to the bro, so comment out.
						cerr << "unknown data type " << tkn_type << "\n";
						//cerr << " from -|" << inText[j].c_str() << "|-\n";
						//showtypes();
					}

				}
			}
			/* Ship it -- sends it if possible, queues it otherwise */
			if ( ! bro_event_send(bc, ev) )
				cerr << "event could not be sent right away\n";

			// now clean up after ourselves...
			bro_event_free(ev);
		}
	} // while (1)
	close(fp);
}


