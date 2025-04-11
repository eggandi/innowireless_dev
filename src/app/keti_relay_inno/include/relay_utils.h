#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>  // stat(), mkdir() (Linux/macOS)
#include <sys/types.h> // stat(), mkdir()
#include <ifaddrs.h>
#include <arpa/inet.h>

#ifndef _D_HEADER_RELAY_INNO_UTILS
#define _D_HEADER_RELAY_INNO_UTILS


#endif //?_D_HEADER_RELAY_INNO_UTILS

#define _D_DEBUG_LOG 
	#ifdef _D_DEBUG_LOG
		#define _DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
	#else
		#define _DEBUG_PRINT(fmt, ...) 
#endif // _D_DEBUG_LOG

