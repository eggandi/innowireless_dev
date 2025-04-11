#include <stdio.h>     // 사용된 함수: printf, fprintf, perror, snprintf
#include <stdlib.h>    // 사용된 함수: malloc, free, exit, strdup
#include <stdint.h>    // 사용된 타입: uint8_t, uint16_t 등
#include <string.h>    // 사용된 함수: memset, memcpy, strlen, strdup
#include <sys/stat.h>  // stat(), mkdir() (Linux/macOS)
#include <sys/types.h> // stat(), mkdir()
#include <unistd.h>    // 사용된 함수: access, mkdir
#include <stdbool.h>   // 사용된 타입: bool, true, false
#include <fcntl.h>     // 사용된 함수: open, O_RDWR, O_NOCTTY, O_SYNC

#ifndef _D_HEADER_RELAY_INNO_V2X_TX_WSM
#define _D_HEADER_RELAY_INNO_V2X_TX_WSM
#include "relay_main.h"
#include "relay_utils.h"

#include "relay_v2x.h"
enum relay_inno_wsm_ext_type_e{
	RELAY_INNO_WSM_EXT_ID_TX_POWER = 0,
	RELAY_INNO_WSM_EXT_ID_CHANNEL,
	RELAY_INNO_WSM_EXT_ID_DATERATE,
};

struct realy_inno_wsm_header_ext_data_t
{
	int tx_power;
	unsigned int tx_channel_num;
	unsigned int tx_datarate;
};

struct relay_inno_msdu_t
{
	bool isused;
	bool isfilled;
	uint8_t *msdu;
	asn1_ssize_t msdu_size;
	struct LTEV2XHALMSDUTxParams tx_params;
};

#endif //?_D_HEADER_RELAY_INNO_V2X_TX_WSM

#define RELAY_INNO_Fill_TxPrams(str) _D_F_RELAY_INNO_Fill_TxPrams(str, 0xFFFFFFFF)

API asn1_ssize_t RELAY_INNO_WSM_Fill_MSDU(const dot3ShortMsgNpdu *wsm, const dot3ShortMsgData *wsm_body, uint8_t **msdu_in);
API void RELAY_INNO_WSM_Fill_Header(dot3ShortMsgNpdu **wsm_in, struct realy_inno_wsm_header_ext_data_t *ext_data);
API void RELAY_INNO_WSM_Free_Header(dot3ShortMsgNpdu *wsm);
API int RELAY_INNO_MSDU_Transmit(const uint8_t *mpdu, asn1_ssize_t msdu_size, struct LTEV2XHALMSDUTxParams *tx_params);