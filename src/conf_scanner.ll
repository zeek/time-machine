%option prefix="conf"

%option noyywrap
%option nounput

%{

  #include <string.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include "Fifo.hh"
  #include "conf_parser.h"
  void conferror(const char*);
  extern int conf_parse_lineno;


%}

ID      [a-zA-Z_]+[0-9]*
INT     [0-9]+
DBL     [0-9]*\.[0-9]*
IP  [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+
HEX     [0-9a-fA-F]+
IP6 ("["({HEX}:){7}{HEX}"]")|("["0x{HEX}({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*({INT}"."){3}{INT}"]")
WHITE   [ \t]+
COMMENT \#.*
NEWLINE \n

%x comment

%%
"{"		 return LBRACE;
"}"		 return RBRACE;
"("		 return LPAREN;
")"		 return RPAREN;
"["		 return LBRACK;
"]"		 return RBRACK;
";"		 return SEMICOLON;
"class"		 return TOK_CLASS;
"classdir"	 return TOK_CLASSDIR;
"mem"		 return TOK_MEM;
"disk"		 return TOK_DISK;
"filesize"	 return TOK_FILESIZE;
"unlimited"   return TOK_UNLIMITED;
"K"|"k"		 return TOK_K;
"M"|"m"		 return TOK_M;
"G"|"g"		 return TOK_G;
"cutoff"	 return TOK_CUTOFF;
"filter"	 return TOK_FILTER;
"precedence"	 return TOK_PRECEDENCE;
"dyn_timeout"	return TOK_DYN_TIMEOUT;
"main"		 return TOK_MAIN;
"log_interval"	 return TOK_LOG_INTERVAL;
"log_level"  return TOK_LOG_LEVEL;
"device"	 return TOK_DEVICE;
"read_tracefile" return TOK_READ_TRACEFILE;
"no"		 return TOK_NO;
"workdir"	 return TOK_WORKDIR;
"queryfiledir"	 return TOK_QUERYFILEDIR;
"indexdir"	 return TOK_INDEXDIR;
"profilepath"    return TOK_PROFILEPATH;
"index"      return TOK_INDEX;
"logfile"	 return TOK_LOGFILE;
"bro_connect_str" return TOK_BRO_CONNECT_STR;
"pkts_to_disk"	 return TOK_PKTS_TO_DISK;
"console"	 return TOK_CONSOLE;
"daemon"	 return TOK_DAEMON;
"max_index_entries" return TOK_MAX_INDEX_ENTRIES;
"conn_timeout"   return TOK_CONN_TIMEOUT;
"tweak_capture_thread" return TOK_TWEAK_CAPTURE_THREAD;
"scope"		return TOK_SCOPE;
"priority"		return TOK_PRIORITY;
"filename_format" return TOK_FILENAME_FORMAT;
"classdir_format" return TOK_CLASSDIR_FORMAT;

"rmtconsole_listen_addr"	return TOK_RMTCONSOLE_LISTEN_ADDR;
"rmtconsole_port"	return TOK_RMTCONSOLE_PORT;
"rmtconsole"	return TOK_RMTCONSOLE;
"bro_listen_addr"	return TOK_BRO_LISTEN_ADDR;
"bro_console_port"	return TOK_BRO_LISTEN_PORT;
"bro_listen"	return TOK_BRO_LISTEN;


"bro_listen_port" return TOK_BRO_LISTEN_PORT;


{ID}		 { conflval.s=strdup(yytext); return TOK_ID; }
{INT}		 { conflval.i64=atol(yytext); return TOK_INTEGER; }
{DBL}		 { conflval.d=strtod(yytext, NULL); return TOK_DOUBLE; }
{IP}		{
				if (!inet_aton(yytext, &(conflval.ipaddr)))
					conferror("Invald IP address");
				return TOK_IPADDRESS;
			}
\".*\"	 { conflval.s=strdup(yytext+1);
		   conflval.s[strlen(conflval.s)-1]=0;
           /*free(conflval.s)*/
		   return TOK_STRING;
		 } 
{WHITE}
{COMMENT}
"/*"		 BEGIN(comment);
<comment>[^*\n]*        /* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*   /* eat up '*'s not followed by '/'s */
<comment>\n             ++conf_parse_lineno;
<comment>"*"+"/"        BEGIN(INITIAL);
{NEWLINE}	 { conf_parse_lineno++; }
.		 conferror("Illegal character in configuration file");

%%

