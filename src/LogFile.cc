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

        /*
        #ifdef __APPLE__
        struct tvalspec tmptv;
        clock_get_time(CLOCK_MONOTONIC_COARSE, &tmptv)i;
        *fs << valspec_to_tm(&tmptv) << " "
        << ident << ": " << msg << std::endl;
        #endif
        #ifdef linux
        struct timespec tmptv;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &tmptv);
        *fs << spec_to_tm(&tmptv) << " "
        << ident << ": " << msg << std::endl;
        #endif
        #ifdef __FreeBSD__
        struct timespec tmptv;
        clock_gettime(CLOCK_MONOTONIC_FAST, &tmptv);
        *fs << spec_to_tm(&tmptv) << " "
        << ident << ": " << msg << std::endl;
        #endif
        */

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

