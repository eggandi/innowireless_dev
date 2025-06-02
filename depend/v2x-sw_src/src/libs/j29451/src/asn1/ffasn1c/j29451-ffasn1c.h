/** 
 * @file
 * @brief
 * @date 2021-02-22
 * @author gyun
 */


#ifndef V2X_SW_J29451_FFASN1C_H
#define V2X_SW_J29451_FFASN1C_H


// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"

// j29451-ffasn1c-encode.c
uint8_t INTERNAL *
j29451_ffasn1c_ConstructBSM(struct J29451GNSSData *gnss, struct J29451VehicleInfo *vehicle, size_t *bsm_size);

#endif //V2X_SW_J29451_FFASN1C_H
