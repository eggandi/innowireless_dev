#include <stdio.h>     // 사용된 함수: printf, fprintf, perror, snprintf
#include <stdlib.h>    // 사용된 함수: malloc, free, exit, strdup
#include <stdint.h>    // 사용된 타입: uint8_t, uint16_t 등
#include <string.h>    // 사용된 함수: memset, memcpy, strlen, strdup
#include <sys/stat.h>  // stat(), mkdir() (Linux/macOS)
#include <sys/types.h> // stat(), mkdir()
#include <unistd.h>    // 사용된 함수: access, mkdir
#include <stdbool.h>   // 사용된 타입: bool, true, false
#include <fcntl.h>     // 사용된 함수: open, O_RDWR, O_NOCTTY, O_SYNC
#include <inttypes.h>  // 사용된 매크로: PRIu64
#include <assert.h>
#include <dirent.h>


#ifndef _D_HEADER_RELAY_INNO_V2X_DOT2
#define _D_HEADER_RELAY_INNO_V2X_DOT2
#include "relay_main.h"
#include "relay_utils.h"

#include "relay_v2x.h"


#endif //?_D_HEADER_RELAY_INNO_V2X_DOT2

extern int RELAY_INNO_V2X_Dot2_Security_Init();
