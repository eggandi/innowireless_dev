/** 
 * @file
 * @brief j29451 라이브러리 내부에서 사용되는 함수들을 정의한 헤더 파일
 * @date 2020-10-03
 * @author gyun
 */


#ifndef V2X_SW_J29451_INTERNAL_FUNCS_H
#define V2X_SW_J29451_INTERNAL_FUNCS_H


// 시스템 헤더 파일
#include <math.h>

// 라이브러리 내부 헤더 파일
#include "j29451-internal-defines.h"
#include "j29451-internal-types.h"
#include "j29451-mib.h"


// bsm/j29451-bsm.c
void INTERNAL j29451_InitBSMData(struct J29451BSMData *bsm_data, uint8_t *addr);
void INTERNAL j29451_ReleaseBSMData(struct J29451BSMData *bsm_data);
void INTERNAL j29451_UpdateBSMIDChangeInitialPoint(uint64_t current_msec, struct J29451GNSSData *gnss);
bool INTERNAL j29451_CheckBSMIDChange(uint64_t current_msec, struct J29451GNSSData *gnss);
void INTERNAL j29451_GenerateAndStoreNextRandomPool(struct J29451BSMData *bsm_data);

// bsm/j29451-bsm-construct.c
uint8_t INTERNAL *j29451_ConstructBSM(struct J29451GNSSData *gnss, struct J29451VehicleInfo *vehicle, size_t *bsm_size);

// bsm/j29451-bsm-tx.c
void INTERNAL j29451_InitBSMTx(struct J29451BSMTx *bsm_tx);
void INTERNAL j29451_ReleaseBSMTransmit(struct J29451BSMTx *bsm_tx);;
int INTERNAL j29451_StartBSMTransmit(struct J29451BSMTx *bsm_tx, J29451BSMTxInterval tx_interval);
void INTERNAL j29451_StopBSMTransmit(struct J29451BSMTx *bsm_tx);

// obu/j29451-obu.c
int INTERNAL j29451_InitOBUInfo(struct J29451OBUInfo *obu);
void INTERNAL j29451_ReleaseOBUInfo(struct J29451OBUInfo *obu);

// obu/j29451-obu-gnsss.c
int INTERNAL j29451_InitGNSSInfo(struct J29451GNSSInfo *obu);
void INTERNAL j29451_ReleaseGNSSInfo(struct J29451GNSSInfo *obu);
void INTERNAL j29451_InitGNSSData(struct J29451GNSSData *gnss);
int INTERNAL j29451_GetCurrentGNSSData(struct J29451GNSSData *gnss);
void INTERNAL j29451_UpdateGNSSHeadingLatch(J29451Speed speed, J29451Heading heading);
#ifdef _TARGET_STD_VER_2020_
void INTERNAL j29451_RestoreGNSSHeadingLatch(J29451Speed speed, J29451Heading heading);
#endif

// obu/j29451-obu-gnss-filter.c
void INTERNAL j29451_InitBWLowPassFilter(struct J29451BWLowPassFilter *filter, float sampling_freq, float cutoff_freq);
float INTERNAL j29451_BWLowPassFilter(struct J29451BWLowPassFilter *filter, float input);

// vehicle/j29451-vehicle.c
void INTERNAL j29451_InitVehicleInfo(struct J29451VehicleInfo *vehicle);
void INTERNAL j29451_ReleaseVehicleInfo(struct J29451VehicleInfo *vehicle);
int INTERNAL j29451_GetCurrentVehicleInfo(struct J29451VehicleInfo *vehicle);

// j29451.c
int INTERNAL j29451_Init(struct J29451MIB *mib, uint8_t *addr);
void INTERNAL j29451_Release(struct J29451MIB *mib);
void INTERNAL j29451_GetRandomOcts(uint8_t *r, size_t size);

// j29451-log.c
void INTERNAL j29451_PrintLog(const char *func, const char *format, ...);

#endif //V2X_SW_J29451_INTERNAL_FUNCS_H
