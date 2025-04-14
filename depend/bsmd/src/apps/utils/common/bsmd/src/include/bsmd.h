/**
 * @file
 * @brief bsmd 메인 헤더
 * @date 2022-09-17
 * @author gyun
 */



#ifndef V2X_SW_BSMD_H
#define V2X_SW_BSMD_H


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 헤더파일
#include "v2x-sw.h"

// 어플리케이션 헤더 파일
#include "bsmd-defines.h"
#include "bsmd-types.h"
#include "bsmd-funcs.h"


/**
 * @brief bsmd 동작 유형
 */
enum eBSMDOperation
{
  kBSMDOperation_TxOnly, ///< 송신만 수행
  kBSMDOperation_TxRx, ///< 송수신 모두 수행 (수신은 BSM 디코딩 후 로그 출력까지만 수행)
};
typedef unsigned int BSMDOperation; ///< @ref eBSMDOperation


/**
 * @brief MIB
 */
struct BSMD_MIB
{
  /// bsmd 동작 유형
  BSMDOperation op;

  /// LTE-V2X 통신 디바이스 이름
  char dev_name[MAXLINE];

  /// V2V 인터페이스 MAC 주소
  uint8_t v2v_if_mac_addr[MAC_ALEN];

  /// 로그 메시지 출력 레벨
  struct {
    BSMDLogLevel bsmd; ///< bsmd 어플리케이션 로그 메시지 출력 레벨
    /// V2X 라이브러리 로그 메시지 출력 레벨
    struct {
      unsigned int dot2;
      unsigned int dot3;
      unsigned int j29451;
      unsigned int wlanaccess;
      unsigned int ltev2x_hal;
    } lib;
  } log;

  bool power_off; ///< Power off 되었음을 나타내는 플래그
};


extern struct BSMD_MIB g_bsmd_mib;

#endif //V2X_SW_BSMD_H
