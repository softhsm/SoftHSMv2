/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 log.cpp

 Implements logging functions. This file is based on the concepts from
 SoftHSM v1 but extends the logging functions with support for a variable
 argument list as defined in stdarg (3) and logging to file.
 *****************************************************************************/

#include "config.h"
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <sstream>
#include <vector>
#include <time.h>
#include "log.h"
#include "MutexFactory.h"

int softLogLevel = LOG_DEBUG;
static FILE* logFile = nullptr;
static Mutex* logMutex = nullptr;

bool setLogLevel(const std::string &loglevel)
{
	if (loglevel == "ERROR")
	{
		softLogLevel = LOG_ERR;
	}
	else if (loglevel == "WARNING")
	{
		softLogLevel = LOG_WARNING;
	}
	else if (loglevel == "INFO")
	{
		softLogLevel = LOG_INFO;
	}
	else if (loglevel == "DEBUG")
	{
		softLogLevel = LOG_DEBUG;
	}
	else
	{
		ERROR_MSG("Unknown value (%s) for log.level in configuration", loglevel.c_str());
		return false;
	}

	return true;
}

bool setLogFile(const std::string &logFilePath)
{
	// Quick return without creating mutex for default configuration
	if (logFilePath.empty() && logFile == nullptr)
	{
		return true;
	}

	if (logMutex == nullptr)
	{
		// Create mutex for later access
		logMutex = MutexFactory::i()->getMutex();
	}

	if (logFile != nullptr)
	{
		fclose(logFile);
		logFile = nullptr;
	}

	if (logFilePath.empty())
	{
		return true;
	}

	// This function needs to be called in init so it does not need locking
	logFile = fopen(logFilePath.c_str(), "a");
	if (logFile == nullptr)
	{
		syslog(LOG_ERR, "Failed to open log file: %s, using syslog only", logFilePath.c_str());
		return false;
	}

	return true;
}

void closeLogFile()
{
	if (logFile != nullptr)
	{
		fclose(logFile);
		logFile = nullptr;
	}

	if (logMutex != nullptr)
	{
		MutexFactory::i()->recycleMutex(logMutex);
		logMutex = nullptr;
	}
}

static const char* getLevelString(int loglevel)
{
	switch(loglevel)
	{
		case LOG_ERR: return "ERROR";
		case LOG_WARNING: return "WARNING";
		case LOG_INFO: return "INFO";
		case LOG_DEBUG: return "DEBUG";
		default: return "UNKNOWN";
	}
}

static void writeLogToFile(const int loglevel, const char* prependText, const char* msgText)
{
	MutexLocker lock(logMutex);

	time_t now = time(nullptr);
	struct tm timeinfo;
	char timeStr[64];

#ifdef _WIN32
	localtime_s(&timeinfo, &now);
#else
	localtime_r(&now, &timeinfo);
#endif
	strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);

	fprintf(logFile, "%s %s: %s%s\n", timeStr, getLevelString(loglevel), prependText, msgText);
	fflush(logFile);
}

void softHSMLog(const int loglevel, const char* functionName, const char* fileName, const int lineNo, const char* format, ...)
{
	if (loglevel > softLogLevel) return;

	std::stringstream prepend;

#ifdef SOFTHSM_LOG_FILE_AND_LINE
	prepend << fileName << "(" << lineNo << ")";
#ifndef SOFTHSM_LOG_FUNCTION_NAME
	(void) functionName;
	prepend << ":";
#endif // !SOFTHSM_LOG_FUNCTION_NAME
	prepend << " ";
#endif // SOFTHSM_LOG_FILE_AND_LINE

#ifdef SOFTHSM_LOG_FUNCTION_NAME
	prepend << functionName << ": ";
#endif // SOFTHSM_LOG_FUNCTION_NAME

	// Print the format to a log message
	std::vector<char> logMessage;
	va_list args;

	logMessage.resize(4096);

	va_start(args, format);
	vsnprintf(&logMessage[0], 4096, format, args);
	va_end(args);

	const char* msgText = &logMessage[0];
	std::string prependStr = prepend.str();
	const char* prependText = prependStr.c_str();

	// Log to file if configured, otherwise use syslog
	if (logFile != nullptr)
	{
		writeLogToFile(loglevel, prependText, msgText);
	}
	else
	{
		syslog(loglevel, "%s%s", prependText, msgText);
	}

#ifdef DEBUG_LOG_STDERR
	fprintf(stderr, "%s%s\n", prependText, msgText);
	fflush(stderr);
#endif
}
