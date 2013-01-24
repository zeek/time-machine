#ifndef LOGFILE_HH
#define LOGFILE_HH

#include <fstream>
#include <string>


class LogFile {
public:
	LogFile(const std::string& filename);
	~LogFile();
	void log(const std::string& ident, const std::string& message);
	void log(const char* ident, const char* fmt, ...);
	void logPlain(const std::string& msg);
	void logPlain(const char *msg);
protected:
	const std::string& filename;
	std::ofstream* fs;
};

#endif
