#include <stdio.h>     // 사용된 함수: printf, fprintf, perror, snprintf
#include <stdlib.h>    // 사용된 함수: malloc, free, exit, strdup
#include <stdint.h>    // 사용된 타입: uint8_t, uint16_t 등
#include <string.h>    // 사용된 함수: memset, memcpy, strlen, strdup
#include <sys/stat.h>  // stat(), mkdir() (Linux/macOS)
#include <sys/types.h> // stat(), mkdir()
#include <unistd.h>    // 사용된 함수: access, mkdir
#include <stdbool.h>   // 사용된 타입: bool, true, false
#include <fcntl.h>     // 사용된 함수: open, O_RDWR, O_NOCTTY, O_SYNC

#ifndef _D_HEADER_RELAY_INNO_V2X_TX_J2735
#define _D_HEADER_RELAY_INNO_V2X_TX_J2735
// RELAY_INNO 소스 헤더 파일
#include "relay_main.h"
#include "relay_utils.h"

#include "relay_v2x.h"

#endif //?_D_HEADER_RELAY_INNO_V2X_TX_J2735
API int RELAY_INNO_V2X_Tx_J2735_BSM();
