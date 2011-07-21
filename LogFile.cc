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

// $Id: LogFile.cc 169 2007-01-23 05:47:37Z gregor $
//
#include <stdarg.h>
#include <stdio.h>

#include <fstream>
#include <time.h>
#include <sys/time.h>

#include "LogFile.hh"
#include "types.h"

#define MAX_MSG_LEN 1024

LogFile::LogFile(const std::string& filename):
filename(filename) {
	fs=new std::ofstream(filename.c_str(), std::ios::app);
	fs->setf(std::ios::fixed);
	//log("logfile", "logfile opened");
}

LogFile::~LogFile() {
	//log("logfile", "closing logfile");
	delete fs;
}


void LogFile::log(const std::string& ident, const std::string& message)
{
	log(ident.c_str(), message.c_str());
}


void LogFile::log(const char* ident, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	/*
	const time_t now=time(NULL);
	char t[80];
	strftime(t, 80, "%Y-%m-%d %H:%M:%S", localtime(&now));
	*/
	struct timeval now;
	gettimeofday(&now, NULL);
	char msg[MAX_MSG_LEN];
	vsnprintf(msg, MAX_MSG_LEN, fmt, ap);
	*fs << to_tm_time(&now) << " "
	<< ident << ": " << msg << std::endl;
	if (fs->fail()) {
		fprintf(stderr, "failure writing to log file %s\n", filename.c_str());
	}
	va_end(ap);
}

void LogFile::logPlain(const std::string& msg) {
	*fs << msg << std::endl;
	if (fs->fail()) {
		fprintf(stderr, "failure writing to log file %s\n", filename.c_str());
	}
}

void LogFile::logPlain(const char *msg) {
	*fs << msg << std::endl;
	if (fs->fail()) {
		fprintf(stderr, "failure writing to log file %s\n", filename.c_str());
	}
}

