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

#ifndef _D_HEADER_RELAY_INNO_V2X_J2735_BSM
#define _D_HEADER_RELAY_INNO_V2X_J2735_BSM	
#include "relay_main.h"
#include "relay_utils.h"

#include "relay_v2x.h"

#define RELAY_INNO_TEMPORARY_ID_LEN (4)
#define RELAY_INNO_INCREASE_BSM_MSG_CNT(cnt) (((cnt) + 1) % 128)

#endif //?_D_HEADER_RELAY_INNO_V2X_J2735_BSM

API uint8_t *REPLAY_INNO_J2736_Construct_BSM(size_t *bsm_size);
API int RELAY_INNO_J2735_Fill_BSM(struct j2735BasicSafetyMessage *bsm);
API void RELAY_INNO_BSM_Gnss_Info_Ptr_Instrall(struct j2735BSMcoreData **core_ptr);
API int RELAY_INNO_BSM_Fill_VarLengthNumber(int psid, dot3VarLengthNumber *to);
