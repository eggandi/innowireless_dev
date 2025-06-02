/** 
 * @file
 * @brief
 * @date 2020-07-17
 * @author gyun
 */


#ifndef V2X_SW_DOT3_INTERNAL_TYPES_H
#define V2X_SW_DOT3_INTERNAL_TYPES_H


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3-defines.h"


/**
 * @brief 802.11 MAC 헤더 형식
 */
struct Dot11MACHdr
{
  uint16_t fc; ///< Frame control
  uint16_t dur; ///< Duration/AID
  uint8_t addr1[MAC_ALEN]; ///< ADDR1
  uint8_t addr2[MAC_ALEN]; ///< ADDR2
  uint8_t addr3[MAC_ALEN]; ///< ADDR3
  uint16_t sc; ///< Sequence control
  uint16_t qc; ///< QoS control : QoS Data 프레임에만 존재한다.
} __attribute__ ((packed));


/**
 * @brief LLC 헤더 형식
 */
struct LLCHdr
{
  uint16_t type; ///< EtherType
} __attribute__ ((packed));


#endif //V2X_SW_DOT3_INTERNAL_TYPES_H
