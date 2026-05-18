#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <vector>
#include "log.h"

#ifdef _WIN32

static HANDLE hEventLog = NULL;

/*
 * Close the Handle to the application Event Log
 */
void
closelog() {
	DeregisterEventSource(hEventLog);
}

/*
 * Initialize event logging
 */
void
openlog(const char *ident, int , int ) {
	/* Get a handle to the Application event log */
	hEventLog = RegisterEventSourceA(NULL, ident);
}

/*
 * Log to the NT Event Log
 */
void
syslog(int priority, const char *message, ...) {
	va_list ap;
	std::vector<char> logMessage;
	logMessage.resize(MAX_LOG_MESSAGE_SIZE);
	LPCSTR str[1];

	va_start(ap, message);
	vsnprintf(&logMessage[0], MAX_LOG_MESSAGE_SIZE, message, ap);
	va_end(ap);

	str[0] = &logMessage[0];

	/* Make sure that the channel is open to write the event */
	if (hEventLog == NULL) {
		openlog("SoftHSM", 0, 0);
	}
	if (hEventLog != NULL) {
		switch (priority) {
		case LOG_INFO:
		case LOG_NOTICE:
		case LOG_DEBUG:
			ReportEventA(hEventLog, EVENTLOG_INFORMATION_TYPE, 0,
				     0x40000003, NULL, 1, 0, str, NULL);
			break;
		case LOG_WARNING:
			ReportEventA(hEventLog, EVENTLOG_WARNING_TYPE, 0,
				     0x80000002, NULL, 1, 0, str, NULL);
			break;
		default:
			ReportEventA(hEventLog, EVENTLOG_ERROR_TYPE, 0,
				     0xc0000001, NULL, 1, 0, str, NULL);
			break;
		}
	}
}

#endif
