/** 
 * @file
 * @brief 함수 프로토타입 정의
 * @date 2022-09-17
 * @author gyun
 */


#ifndef V2X_SW_BSMD_FUNCS_H
#define V2X_SW_BSMD_FUNCS_H


// 시스템 헤더 파일
#include <stddef.h>

// 라이브러리 헤더 파일
#if defined(_BSMD_DSRC_)
#include "wlanaccess/wlanaccess.h"
#elif defined(_BSMD_LTE_V2X_)
#include "ltev2x-hal/ltev2x-hal.h"
#endif

// 어플리케이션 헤더 파일
#include "bsmd-types.h"

// bsmd-bsm.c
int BSMD_StartBSMTransmit(void);
void BSMD_BSMTransmitCallback(const uint8_t *bsm, size_t bsm_size, bool event, bool cert_sign, bool id_change, uint8_t *addr);

// bsmd-input-params.c
int BSMD_ParseInputParameters(int argc, char *argv[]);

// bsmd-log.c
void BSMD_PrintLog(const char *func, const char *format, ...);
void BSMD_PrintPacketDump(BSMDLogLevel log_level, const uint8_t *pkt, size_t pkt_size);

// bsmd-poweroff.c
void BSMD_InitPowerOffFunction(void);
bool BSMD_DetectPowerOff(void);

// bsmd-security.c
int BSMD_InitSecurity(void);
void BSMD_ProcessSPDUCallback(Dot2ResultCode result, void *priv);

#if defined(_BSMD_DSRC_)
// dsrc/bsmd-dsrc.c
void BSMD_DSRC_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, WalPriority priority);
void BSMD_DSRC_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *mpdu_rx_params);
#elif defined(_BSMD_LTE_V2X_)
// lte-v2x/bsmd-lte-v2x.c
void BSMD_LTE_V2X_InitTerminateHandler(void);
int BSMD_LTE_V2X_RegisterTransmitFlow(void);
void BSMD_LTE_V2X_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, LTEV2XHALPriority priority);
void BSMD_LTE_V2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_param);
#endif


#endif //V2X_SW_BSMD_FUNCS_H
