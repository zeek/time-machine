/* cmd_parser.yy         (emacs mode for this is --*-indented-text-*--)
 *
 * Parse online commands.
 *
 * NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE
 * This parser is not reentrant. Since it is called from multiple threads,
 * it protects itself with a mutex. Therefor the mutex must be initialized
 * before you first use the parser. 
 * So don't forget to call: cmd_parser_init() (and cmd_parser_finish(), when
 * you are done with the parser
 */

%name_prefix="cmd"

// Make the parser re-entrant
//%pure-parser

%{ 
	#include <string.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <netinet/in.h>
	#include <pthread.h>
	#include <string>

	#include "tm.h"
	#include "config.h"

	#ifdef USE_BROCCOLI
	#include "BroccoliComm.hh"
	#endif

	#include "Storage.hh"
	#include "Query.hh"
	#include "Index.hh"

	// Work around a bug in the relation between bison and GCC 3.x:
	#if defined (__GNUC__) && 3 <= __GNUC__
	#define __attribute__(arglist)
	#endif

	/* Internal datastructures whilse parsing */ 
	static QueryRequest * q_req;
	static QueryResult *q_res; 
	static IndexField *q_idxfield;
	static bool q_mem_only;
	static bool q_subscribe;
	static tm_time_t q_start;
	static tm_time_t q_end;
	static broccoli_worker_thread_data* q_bc_thread;

	static int nextQueryID = 0;

	//extern int yylex(YYSTYPE *lvalp, YYLTYPE *llocp);
	extern int yylex();
	struct yy_buffer_state;
	static pthread_mutex_t cmd_parser_lock;

	typedef struct yy_buffer_state *YY_BUFFER_STATE;
	extern void cmd_delete_buffer (YY_BUFFER_STATE b);
	extern YY_BUFFER_STATE cmd_scan_string (const char *yy_str);

	int cmderror(const char*);
	int cmd_parse_lineno=0;
	int cmd_parse_errors=0;
	//  const char* parse_filename=NULL;

	/*
	 * symbols shared with main.cc
	 */
	Storage* cmd_parser_storage=NULL;
	FILE *cmd_parser_outfp;
	extern void print_stats(FILE *fp);
	extern pcap_t* ph;
%}

%union {
	int i;
	int64_t i64;
	char* s;
	double d;
	IndexField* indexfield_p;
	IPAddress* ipaddress_p;
	ConnectionID4* connectionid4_p;
	QueryResult* queryresult_p;
	QueryRequest* queryrequest_p;
}

%token SEMICOLON COLON DASH ASTERISK
%token LBRACE RBRACE LPAREN RPAREN LBRACK RBRACK
%token <i64> TOK_INTEGER
%token <s> TOK_STRING
%token <d> TOK_DOUBLE
%token <s> TOK_ID
%token <ipaddress_p> TOK_IP_ADDR
%token TOK_SET_DYN_CLASS TOK_UNSET_DYN_CLASS TOK_ORIG TOK_RESP
%token TOK_CLASS TOK_FILTER TOK_MAIN TOK_LOG_INTERVAL TOK_DEVICE
%token TOK_LOGFILE TOK_WORKDIR
%token TOK_READ_TRACEFILE TOK_BRO_CONNECT_STR
%token TOK_MEM TOK_DISK TOK_K TOK_M TOK_G TOK_CUTOFF TOK_PRECEDENCE
%token TOK_NO TOK_PKTS_TO_DISK TOK_CONSOLE TOK_MAX_INDEX_ENTRIES
%token TOK_FILESIZE TOK_CONN_TIMEOUT
%token TOK_QUERY TOK_FEED TOK_TO_FILE TOK_SUBSCRIBE
%token TOK_CONN TOK_START TOK_END TOK_TAG TOK_TS TOK_PROTO
%token TOK_PRINT TOK_NOP
%token TOK_BRO_CONNECT TOK_SUSPEND_CUTOFF TOK_UNSUSPEND_CUTOFF
%token TOK_SUSPEND_TIMEOUT TOK_UNSUSPEND_TIMEOUT
%token TOK_SHOW TOK_STATS TOK_CONNS TOK_INDEX TOK_MEM_ONLY
%token TOK_DEBUG_FIFOMEM TOK_SAMPLE
%token TOK_HELP

%type <d> timestamp
%type <s> string_id
%type <connectionid4_p> connection4
%type <i> orig_or_resp

%start cmd

%%

cmd:
// debugging-the-scanner-and-parser commands
	TOK_NOP { 
		if(cmd_parser_outfp)
			fprintf(cmd_parser_outfp, "TOK_NOP\n"); 
	}
	| TOK_PRINT  {
		if(cmd_parser_outfp)
			fprintf(cmd_parser_outfp, "PRINT\n");
	}
	| TOK_PRINT TOK_STRING {
		if(cmd_parser_outfp)
			fprintf(cmd_parser_outfp, "PRINT string \"%s\"\n", $2);
		free($2);
	}
	| TOK_HELP {
		if (cmd_parser_outfp) {
			fprintf(cmd_parser_outfp, "Online help not yet implemented. See doc/howto.rst\n");
		}
	}
/*
	| TOK_PRINT connection {
		printf("PRINT connection %s\n", $2->getStr().c_str());
	}
	| TOK_PRINT connection connection {
		printf("PRINT connection %s connection %s equivalence %d\n",
		 $2->getStr().c_str(), $3->getStr().c_str(), *$2==*$3);
	}
*/
// query
	| TOK_QUERY queryresult queryspec_key queryspec_flags
	{
		int ok = 1;
		if (!q_res) {
			 /* queryresult can be NULL if no Broccoli support
			 * and Broccoli feed requested
			 */
			if(cmd_parser_outfp)
				fprintf(cmd_parser_outfp, "QUERY RESULT DESTINATION UNDEFINED\n");
			ok = 0;
		}
		if (ok && !q_idxfield) {
			if(cmd_parser_outfp)
				fprintf(cmd_parser_outfp, "QUERY KEY UNDEFINED\n");
			ok = 0;
		}

		if (ok) {
			//printf("DEBUG: start=%lf end=%lf, mem_only=%d, subscribe=%d\n", q_start, q_end, q_mem_only, q_subscribe);
			q_req = new QueryRequest(q_idxfield, q_start, q_end, q_mem_only, q_subscribe,
				cmd_parser_storage->getPcapDatalink(), cmd_parser_storage->getPcapSnaplen());
			if (!q_req) {
				if(cmd_parser_outfp)
					fprintf(cmd_parser_outfp, "COULD NOT CREATE QUERY REQUEST\n");
				ok = 0;
			}
		}
		if (ok) {
			cmd_parser_storage->query(q_req, q_res);
			/* queryresult will be `delete'd by storage->query
			 * (or later at connection inactivity timeout
			 * if a subscription is involved)
			 * Queryspec will be delete'd by storage->query
			 */
		} 
		else { 
			/* Cleanup */
			if (q_res)
				delete q_res;
			if (q_idxfield)
				delete q_idxfield;
			if (q_req)
				delete q_req;
		}
	}
// cutoff suspension
	| TOK_SUSPEND_CUTOFF connection4 {
		if ($2 != NULL) {
	        if(!cmd_parser_storage->suspendCutoff(*(ConnectionID4*)$2, true))
				if(cmd_parser_outfp)
					fprintf(cmd_parser_outfp, "NOT IN CONNECTION TABLE\n");
			delete($2);
		}
	}
	| TOK_UNSUSPEND_CUTOFF connection4 {
		if ($2 != NULL)  {
	        if (!cmd_parser_storage->suspendCutoff(*(ConnectionID4*)$2, false))
				if(cmd_parser_outfp)
					fprintf(cmd_parser_outfp, "NOT IN CONNECTION TABLE\n");
			delete($2);
		}
	}
	| TOK_SUSPEND_TIMEOUT connection4 {
		if ($2 != NULL) {
			if (!cmd_parser_storage->suspendTimeout(*(ConnectionID4*)$2, true))
				if(cmd_parser_outfp)
					fprintf(cmd_parser_outfp, "NOT IN CONNECTION TABLE\n");
			/*
			   printf("successfully suspended timeout\n");
			else
			   printf("Connection wasn't in table. added it\n");
			  */
			delete($2);
		}
	}
	| TOK_UNSUSPEND_TIMEOUT connection4 {
		if ($2 != NULL) {
			if(!cmd_parser_storage->suspendTimeout(*(ConnectionID4*)$2, false))
				if(cmd_parser_outfp)
					fprintf(cmd_parser_outfp, "NOT IN CONNECTION TABLE\n");
			delete($2);
		}
	}
	| TOK_SET_DYN_CLASS TOK_IP_ADDR TOK_ID orig_or_resp {
		/* FIXME: do the call to setDynClass later, otherwise this function
		might be called even if a parse error is discovered later!!! */
		if ($2 != NULL && $3 != NULL) {
			cmd_parser_storage->setDynClass($2, $4, $3);
			/* storage class owns $2 (IPAddress) and will take care of
			   deleting it */
		}
		if ($3 != NULL) {
			free($3);
		}
	}
	| TOK_UNSET_DYN_CLASS TOK_IP_ADDR {
		if ($2 != NULL) {
			cmd_parser_storage->unsetDynClass($2);
			/* storage class owns $2 (IPAddress) and will take care of
			   deleting it */
		}
	}
			
// establish bro connection
	| TOK_BRO_CONNECT TOK_STRING {
		if(cmd_parser_outfp)
			fprintf(cmd_parser_outfp, "BRO_CONNECT  <string> NOT IMPLEMENTED\n");
		free($2);
	}
// re-establish bro connection
	| TOK_BRO_CONNECT {
//		printf("BRO_CONNECT\n");
#ifdef USE_BROCCOLI
		broccoli_start_worker_thread(-1);
#else
		if(cmd_parser_outfp) {
			fprintf(cmd_parser_outfp,
			        "TIMEMACHINE WAS COMPILED WITHOUT BROCCOLI SUPPORT\n");
		}
#endif
	}
// display information
	| TOK_SHOW TOK_CONN connection4 {
		if ($3 != NULL) {

			ConnectionID4 cid=*(ConnectionID4*)$3;
			//printf("show conn %s\n", cid.getStr().c_str());
			printf("getCopy...\n");
			Connection *c=cmd_parser_storage->getConns().getCopy(&cid);
			printf("... getCopy\n");
	//		Connection *c=cmd_parser_storage->getConns().get(&cid);
			if (c) {
		          	if(cmd_parser_outfp);
					//fprintf(cmd_parser_outfp, "* %s\n", c->getStr().c_str());
					//fprintf(cmd_parser_outfp, "* %s\n%s\n", $3->getStr().c_str(),
					//	  c->getStr().c_str());
			} else if(cmd_parser_outfp)
				fprintf(cmd_parser_outfp, "NOT IN CONNECTION TABLE\n");
			delete $3;
		}
	}
	| TOK_SHOW TOK_STATS {
		if(cmd_parser_outfp)
			print_stats(cmd_parser_outfp);
	}
	| TOK_SHOW TOK_CONN TOK_SAMPLE {
		if(cmd_parser_outfp)
			cmd_parser_storage->getConns().printConnSample(cmd_parser_outfp);
	} /* 
	| TOK_SHOW TOK_INDEX string_id {
		IndexType *idx=cmd_parser_storage->getIndexes()
				->getIndexByName($3);
		if (idx) idx->debugPrint();
		else fprintf(cmd_parser_outfp, "NO SUCH INDEX\n");
		free($3);
	} */
	/*
	| TOK_SHOW TOK_DEBUG_FIFOMEM string_id {
	        Fifo *f = cmd_parser_storage->getFifoByName($3);
		if (f) f->getFm()->debugPrint();
		else fprintf(cmd_parser_outfp, "not found: %s\n", $3);
		free($3);
	}
	*/
	;

orig_or_resp: 
	/* empty */ {
		$$ = TM_DYNCLASS_BOTH;
	}
	| TOK_ORIG {
		$$ = TM_DYNCLASS_ORIG;
	}
	| TOK_RESP {
		$$ = TM_DYNCLASS_RESP;
	}
	;
	
queryspec_flags: 
	/* empty */
	| queryspec_flags queryspec_flag
	;

queryspec_flag:
	TOK_MEM_ONLY {
		q_mem_only = true;
	}
	| TOK_START timestamp TOK_END timestamp
	{
		q_start = $2;
		q_end = $4;
	}
	| TOK_SUBSCRIBE
	{
		q_subscribe = true;
	}
	;

queryspec_key:
	TOK_INDEX TOK_ID TOK_STRING {
		//fprintf(stderr, "INDEX QUERY: <%s>, string <%s>\n", $2, $3);
		IndexType *idx=cmd_parser_storage->getIndexes()->getIndexByName($2);
		if (idx) {
			IndexField *ifp;
			//fprintf(stderr, "found the index\n");
			ifp = idx->parseQuery($3);
			//DEBUG fprintf(stderr, ">>>>> %s\n", ifp->getStr().c_str());
			if (ifp==NULL) 
				cmderror("invalid query string");
			q_idxfield=ifp;
			//idx->debugPrint();
		}
		else {
			if(cmd_parser_outfp)
				fprintf(cmd_parser_outfp, "NO SUCH INDEX\n");
			q_idxfield = NULL;
		}
		free($2);
		free($3);
	}
	;

queryresult: TOK_FEED TOK_ID TOK_TAG TOK_ID {
		/* TODO: identify bc by $2 */
#ifdef USE_BROCCOLI
		if (q_res != NULL) {
			cmderror("query result object already exists");
		}
		else {
			assert(q_bc_thread);
			q_res = new QueryResultBroConn(nextQueryID, q_bc_thread, $4);
			nextQueryID++;
		}
#else
		if(cmd_parser_outfp) {
			fprintf(cmd_parser_outfp,
			        "TimeMachine was compiled without broccoli support\n");
		}
		q_res=NULL;
#endif
		free($2);
		free($4);
	}
	| TOK_TO_FILE string_id {
		if (q_res != NULL) {
			cmderror("query result object already exists");
		}
		else {
			q_res = new QueryResultFile(nextQueryID, $2, cmd_parser_storage->getPcapDatalink(),cmd_parser_storage->getPcapSnaplen());
			nextQueryID++;
		}
		free($2);
	}
	;

connection4:
	TOK_STRING {
		$$ = ConnectionID4::parse($1);
		if ($$ == NULL) 
			cmderror("invalid connection specification");
		delete($1);
	}
	;

timestamp: TOK_INTEGER { $$=$1; }
	| TOK_DOUBLE { $$=$1; }
	;

string_id: TOK_STRING { $$=$1; }
	| TOK_ID { $$=$1; }
	;	 
%%
     
void 
cmd_parser_init(void) {
	pthread_mutex_init(&cmd_parser_lock, NULL);	
}

void
cmd_parser_finish(void) {
	pthread_mutex_destroy(&cmd_parser_lock);
}

int
cmderror(const char *msg) {
	if(cmd_parser_outfp)
		fprintf(cmd_parser_outfp, "PARSER ERROR - %s\n", msg);
	tmlog(TM_LOG_NOTE, "query", "PARSER ERROR - %s", msg); 
	cmd_parse_errors++;
	return 0;
}

/* Don't forget to call cmd_parser_init(), before you call the parser */
int
parse_cmd(const char* cmd, FILE *outfp, Storage* s, broccoli_worker_thread_data* thread) {
	if ( strstr(cmd, "query") != NULL ) {
		tmlog(TM_LOG_NOTE, "query", "Query submitted: %s", cmd); 
	}

	pthread_mutex_lock(&cmd_parser_lock);
	// set variable parser_storage global to conf_parser.cc
	q_req = NULL;
	q_res = NULL;
	q_mem_only = false;
	q_subscribe = false;
	q_start = 0;
	q_end = 1e13; /* a long time in the future */
	q_bc_thread = thread;
	
	cmd_parser_storage=s;
	cmd_parser_outfp = outfp;
	YY_BUFFER_STATE bufstate=cmd_scan_string(cmd);
	cmd_parse_errors=0;
	cmdparse();
	fflush(outfp);
	cmd_delete_buffer(bufstate);
	pthread_mutex_unlock(&cmd_parser_lock);
	return cmd_parse_errors;
}
