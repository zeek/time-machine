/* cmd_parser.yy         (emacs mode for this is --*-indented-text-*--)
 *
 * Parse online commands.
 */

%name_prefix="conf"

%{ 
  #include <string.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <netinet/in.h>
  #include <string>
  #include <list>

  #include "tm.h"
  #include "conf.h"

  #include "Fifo.hh"
  #include "Storage.hh"
  #include "Index.hh"

  // Work around a bug in the relation between bison and GCC 3.x:
  #if defined (__GNUC__) && 3 <= __GNUC__
  #define __attribute__(arglist)
  #endif

  extern int yylex();
  int parse_config(const char*, StorageConfig*);

  int conferror(const char*);
  int conf_parse_lineno=0;
  int conf_parse_errors=0;
  const char* conf_parse_filename=NULL;

  Fifo* newclass=NULL;
  void new_class() { if (!newclass) newclass=new Fifo(); }
  void end_new_class() { assert(newclass); newclass=NULL; }

  void conf_add_index(const char* name, bool do_disk_index);
	bool diskIndexesExist();
/*
  IndexType* newindex=NULL;
  void new_index() { if (!newindex) newindex=new IndexType(); }
  void end_new_index() { assert(newindex); newindex=NULL; }
*/
  StorageConfig * conf_parser_storageConf=NULL;
%}

%union {
  int i;
  int64_t i64;
  char* s;
//  std::string s;
  double d;
  Fifo* fifo_p;
  struct in_addr ipaddr;
/*
  IndexType* index_type_p;
*/
}

%token SEMICOLON
%token LBRACE RBRACE LPAREN RPAREN LBRACK RBRACK LCOMMENT RCOMMENT
%token <i64> TOK_INTEGER
%token <s> TOK_STRING
%token <d> TOK_DOUBLE
%token <s> TOK_ID
%token <ipaddr> TOK_IPADDRESS;
%token TOK_CLASS TOK_FILTER TOK_MAIN TOK_LOG_INTERVAL TOK_LOG_LEVEL TOK_DEVICE
%token TOK_CLASSDIR
%token TOK_LOGFILE TOK_WORKDIR TOK_QUERYFILEDIR TOK_INDEXDIR TOK_PROFILEPATH
%token TOK_READ_TRACEFILE TOK_BRO_CONNECT_STR
%token TOK_MEM TOK_DISK TOK_K TOK_M TOK_G TOK_CUTOFF TOK_PRECEDENCE
%token TOK_DYN_TIMEOUT
%token TOK_NO TOK_PKTS_TO_DISK TOK_CONSOLE TOK_DAEMON TOK_MAX_INDEX_ENTRIES
%token TOK_FILESIZE TOK_CONN_TIMEOUT TOK_MAX_SUBSCRIPTIONS
%token TOK_RMTCONSOLE TOK_RMTCONSOLE_PORT TOK_RMTCONSOLE_LISTEN_ADDR
%token TOK_BRO_LISTEN TOK_BRO_LISTEN_PORT TOK_BRO_LISTEN_ADDR
%token TOK_TWEAK_CAPTURE_THREAD TOK_SCOPE TOK_PRIORITY 
%token TOK_INDEX
%token TOK_FILENAME_FORMAT TOK_CLASSDIR_FORMAT
%token TOK_UNLIMITED

%type <s> classname option
%type <i64> size
%type <fifo_p> class classoptions classoption
/*
%type <index_type_p> index indexoptions indexoption
*/

%%

config:
	statements
	;
statements:
	| statements option SEMICOLON
	| statements class { 
/*
	  printf("statements: got a class named %s\n", 
			      $2->getClassname().c_str());
*/
	  conf_parser_storageConf->fifos.push_back($2);
	}
/*	| statements index {
	  conf_parser_fifos->getIndexes()->addIndex($2);
	}
*/
	| statements main
	| statements SEMICOLON
	;
/*
index:  TOK_INDEX TOK_STRING LBRACE indexoptions RBRACE {
          
	  if (!strcmp($2, "IPAddress"))
	    new_index=new Index<IPAddress>(
	}
indexoptions:
	{ new_index;
*/
class:
	TOK_CLASS classname LBRACE classoptions RBRACE {
	  std::string s="class_";
	  s+=$2;
	  $4->setClassname(s);
	  $4->setClassnameId($2);
	  $$=$4;
	  end_new_class();
	}
	;
classname:
	TOK_STRING { $$=$1; }
	;
classoptions:
	{ new_class(); $$=newclass; }
/*	| classoption { $$=$1; } */
/*	| classoptions SEMICOLON { $$=$1; } */
	| classoptions classoption SEMICOLON { $$=$1; }
	;
classoption:
	TOK_MEM size {
	  new_class();
	  newclass->setFifoMemSz($2);
	  $$=newclass;
	}
	| TOK_DISK size {
	  new_class();
	  newclass->setFifoDiskSz($2);
	  $$=newclass;
	}
	| TOK_DISK TOK_UNLIMITED {
	  new_class();
		if (diskIndexesExist()) {
			char msg[2048];
			snprintf(msg, sizeof(msg), "In class %s, cannot specify disk infinite when disk indexes are used\n", newclass->getClassname().c_str());
			conferror(msg);
		}
	  newclass->setFifoDiskSzUnlimited();
	  $$=newclass;
	}
	| TOK_FILESIZE size {
	  new_class();
	  newclass->setFifoDiskFileSz($2);
	  $$=newclass;
	}
	| TOK_CUTOFF size {
	  new_class();
	  newclass->setCutoff($2);
	  newclass->enableCutoff();
	  $$=newclass;
	}
	| TOK_CUTOFF TOK_NO {
	  new_class();
	  newclass->disableCutoff();
	  $$=newclass;
	}
	| TOK_FILTER TOK_STRING {
	  new_class();
	  std::string s=$2;
	  newclass->setFilter(s);
	  $$=newclass;
	}
	| TOK_PRECEDENCE TOK_INTEGER {
	  new_class();
	  newclass->setPrecedence($2);
	  $$=newclass;
	}
	| TOK_PKTS_TO_DISK TOK_INTEGER {
	  new_class();
	  newclass->setPktsToDisk($2);
	  $$=newclass;
	}
	| TOK_DYN_TIMEOUT TOK_DOUBLE {
		new_class();
		newclass->setDynTimeout($2);
		$$=newclass;
	}
	| TOK_DYN_TIMEOUT TOK_INTEGER {
		new_class();
		newclass->setDynTimeout($2);
		$$=newclass;
	}
    | TOK_CLASSDIR TOK_STRING {
		new_class();
        //conf_classdir = ($2);
        newclass->setClassdir($2);
        $$=newclass;
	}
	| TOK_FILENAME_FORMAT TOK_STRING {
		new_class();
		newclass->setFilenameFormat($2);
		$$=newclass;
	}
	| TOK_CLASSDIR_FORMAT TOK_STRING {
		new_class();
		newclass->setClassdirFormat($2);
		$$=newclass;
	}
	;
size:
	TOK_INTEGER { $$=$1; }
	| TOK_INTEGER TOK_K { $$=$1*1024; }
	| TOK_INTEGER TOK_M { $$=$1*1024*1024; }
	| TOK_INTEGER TOK_G { $$=$1*int64_t(1024*1024*1024); }
	;
option:
	TOK_ID TOK_INTEGER {
	  printf("option: ignored option %s int value %" PRIi64 "\n", $1, $2);
	  $$=(char*)malloc(31);
	  snprintf($$, 30, "%" PRIi64, $2);
	  free($1);
	}
	| TOK_ID TOK_STRING {
	  printf("option: ignored option %s str value %s\n", $1, $2);
	  $$=strdup($2);
	  free($1);
	  free($2);
	}
	;
main:
	TOK_MAIN LBRACE main_options RBRACE
	;
main_options:
	| main_option
	| main_option SEMICOLON main_options
	;
main_option:
	TOK_LOGFILE TOK_STRING {
	  conf_main_logfile_name=$2;
	}
	| TOK_CONN_TIMEOUT TOK_DOUBLE {
	  conf_parser_storageConf->conn_timeout=$2;
	}
	| TOK_CONN_TIMEOUT TOK_INTEGER {
	  conf_parser_storageConf->conn_timeout=$2;
	}
	| TOK_MAX_SUBSCRIPTIONS TOK_INTEGER {
	  conf_parser_storageConf->max_subscriptions=$2;
	}
	| TOK_WORKDIR TOK_STRING {
	  conf_main_workdir=$2;
	}
	| TOK_QUERYFILEDIR TOK_STRING {
	  conf_main_queryfiledir=strdup($2);
	  free($2);
	}
	| TOK_INDEXDIR TOK_STRING {
	  conf_main_indexdir=strdup($2);
	  free($2);
	}
	| TOK_CLASSDIR_FORMAT TOK_STRING {
		conf_main_classdir_format=strdup($2);
		free($2);
	}
	| TOK_FILENAME_FORMAT TOK_STRING {
		conf_main_filename_format=strdup($2);
		free($2);
	}
        | TOK_PROFILEPATH TOK_STRING {
          conf_main_profilepath=strdup($2);
          free($2);
        }
	| TOK_BRO_CONNECT_STR TOK_STRING {
	  conf_main_bro_connect_str=strdup($2);
	  free($2);
	}
	| TOK_FILTER TOK_STRING {
	  if (conf_parser_storageConf->filter.empty()) 
	      conf_parser_storageConf->filter.assign($2);
	  free($2);
	}
	| TOK_DEVICE TOK_STRING {
	  if (conf_parser_storageConf->device.empty()) 
	      conf_parser_storageConf->device.assign($2);
	  free($2);
	}
	| TOK_LOG_INTERVAL TOK_INTEGER {
	  conf_main_log_interval=$2;
	}
	| TOK_LOG_LEVEL TOK_INTEGER {
	  conf_main_log_level=$2;
	}
	| TOK_READ_TRACEFILE TOK_STRING {
	  if (conf_parser_storageConf->readtracefile.empty()) 
	      conf_parser_storageConf->readtracefile.assign($2);
	  free($2);
	}
	| TOK_CONSOLE TOK_INTEGER {
	  conf_main_console=$2;
	}
	| TOK_DAEMON TOK_INTEGER {
	  conf_main_daemon=$2;
	}
	| TOK_RMTCONSOLE TOK_INTEGER {
		conf_main_rmtconsole = $2;
	}
	| TOK_RMTCONSOLE_PORT TOK_INTEGER {
		conf_main_rmtconsole_port = $2;
	}
	| TOK_RMTCONSOLE_LISTEN_ADDR TOK_IPADDRESS {
		conf_main_rmtconsole_listen_addr = $2;
	}
	| TOK_TWEAK_CAPTURE_THREAD TOK_SCOPE {
		conf_main_tweak_capture_thread = TM_TWEAK_CAPTURE_THREAD_SCOPE;
	}
	| TOK_TWEAK_CAPTURE_THREAD TOK_PRIORITY {
		conf_main_tweak_capture_thread = TM_TWEAK_CAPTURE_THREAD_PRIO;
	}
	| TOK_TWEAK_CAPTURE_THREAD TOK_NO {
		conf_main_tweak_capture_thread = TM_TWEAK_CAPTURE_THREAD_NONE;
    }
	| TOK_BRO_LISTEN TOK_INTEGER {
		conf_main_bro_listen = $2;
	}
	| TOK_BRO_LISTEN_PORT TOK_INTEGER {
		conf_main_bro_listen_port = $2;
	}
	| TOK_BRO_LISTEN_ADDR TOK_IPADDRESS {
		conf_main_bro_listen_addr = $2;
	}
	| TOK_INDEX TOK_STRING TOK_DISK {
		conf_add_index($2, true);
	}
	| TOK_INDEX TOK_STRING {
		conf_add_index($2, false);
	}
	;
	 
%%
     
int conferror(const char *msg) {
  fprintf(stderr, "parser error in %s line %d: %s",
	  conf_parse_filename, conf_parse_lineno, msg);
  conf_parse_errors++;
  return 0;
}

int parse_config(const char* filename, StorageConfig *s) {
  // set variable conf_parser_fifos global to conf_parser.cc
  conf_parser_storageConf=s;
  extern FILE *confin;
  if (! (confin=fopen(filename, "r")) ) {
    fprintf(stderr, "error opening config file %s\n", filename);
    return(1);
  }
  conf_parse_filename=filename;
  conf_parse_lineno=1;
  confparse();
  fclose(confin);
  return conf_parse_errors;
}

bool diskIndexesExist() {
	std::list<IndexType*>::iterator i;
	for (i = conf_parser_storageConf->indexes->begin(); 
			 i != conf_parser_storageConf->indexes->end();
	     ++i) {
		if ((*i)->hasDiskIndex()) {
			return true;
		}
	}
	return false;
}

void conf_add_index(const char* name, bool do_disk_index) {
	if (conf_parser_storageConf->indexes->getIndexByName(name)) {
		char msg[2048];
		snprintf(msg, sizeof(msg), "Index %s already configured\n", name);
		conferror(msg);
		return;
	}
        /*
        uint64_t primes[] = {53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, /
                             98317, 196613, 393241, 786433, 1572869, 3145739, 6291469, /
                             12582917, 25165843, 50331653, 100663319, 201326611, 402653189, /
                             805306457, 1610612741, 3221225479, 6442450967, 12884901947};
        */
	/* TODO: We really should do index configuration with a regitry that knows 
	   of all potential IndexTypes .... */
	if (ConnectionIF4::getIndexNameStatic() == name) {
		//IndexType *idx = new Index<ConnectionIF4>(30, int(250000), do_disk_index, NULL);
        IndexType *idx = new Index<ConnectionIF4>(30, 15, do_disk_index, NULL);
		conf_parser_storageConf->indexes->addIndex(idx);
	}
	else if (ConnectionIF3::getIndexNameStatic() == name) {
		//IndexType *idx = new Index<ConnectionIF3>(30, int(250000), do_disk_index, NULL);
        IndexType *idx = new Index<ConnectionIF3>(30, 15, do_disk_index, NULL);
		conf_parser_storageConf->indexes->addIndex(idx);
	}

	else if (ConnectionIF2::getIndexNameStatic() == name) {
		//IndexType *idx = new Index<ConnectionIF2>(30, int(250000), do_disk_index, NULL);
        IndexType *idx = new Index<ConnectionIF2>(30, 15, do_disk_index, NULL);
		conf_parser_storageConf->indexes->addIndex(idx);
	}
	else if (IPAddress::getIndexNameStatic() == name) {
		//IndexType *idx = new Index<IPAddress>(30, int(250000), do_disk_index, NULL);
        IndexType *idx = new Index<IPAddress>(30, 15, do_disk_index, NULL);
		conf_parser_storageConf->indexes->addIndex(idx);
	}
	else {
		char msg[2048];
		snprintf(msg, sizeof(msg), "Don't know about index %s\n", name);
		conferror(msg);
	}
}
