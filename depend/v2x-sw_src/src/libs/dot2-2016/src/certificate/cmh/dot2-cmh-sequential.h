/** 
  * @file 
  * @brief Sequential 인증서 CMH 관련 정의 (Application/Identification/Enrollment 인증서에 해당됨)
  * @date 2022-07-03 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_CMH_SEQUENTIAL_H
#define V2X_SW_DOT2_CMH_SEQUENTIAL_H


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 의존 헤더 파일
#include "openssl/ec.h"
#include "sudo_queue.h"
#if defined(_FFASN1C_)
#include "ffasn1-dot2-2021.h"
#elif defined(_OBJASN1C_)
#include "IEEE1609dot2ScmsProtocol.h"
#else
#error "3rd party asn.1 library is not defined"
#endif

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "certificate/cert-info/dot2-cert-info.h"
#include "certificate/cert-info/dot2-ee-cert-info.h"
#include "certificate/cert-info/dot2-scc-cert-info.h"


/**
 * @brief Sequential CMH 리스트 내 CMH 엔트리의 개수
 *
 * 최대값은 20년치(자체 정의한 값)를 저장할 수 있도록 다음과 같이 정의된다.
 *  * 인증서 당 유효기간: 7일
 *   - 현 버전 SCMS 규격에 정의된 Application 인증서의 유효기간: 7일, Identification 인증서: 1개월, Enrollment 인증서: ?년)
 *  * 최대값 = 52주 * 20년
 */
enum eDot2SequentialCMHEntryNum
{
  kDot2SequentialCMHEntryNum_Max = (52 * 20) ///< 최대개수
};
typedef unsigned int Dot2SequentialCMHEntryNum; ///< @ref eDot2SequentialCMHEntryNum


/**
 * @brief Sequential CMH 정보
 *
 * 나의 Sequential 인증서 관련 개인키 및 인증서정보가 저장된다.
 */
struct Dot2SequentialCMHInfo
{
  struct Dot2EECertContents cert_contents; ///< 인증서정보
  struct Dot2ECPrivateKey priv_key; ///< 개인키 바이트열 OK
  EC_KEY *eck_priv_key; ///< EC_KEY 형식 개인키 (동적 할당됨 -> EC_KEY_free()로 해제되어야 함)
};


/**
 * @brief Sequential CMH 엔트리
 *
 * 각 인증서별 CMH 정보는 본 엔트리 형식으로 리스트에 저장된다.
 * CMH 정보와 인증서데이터, 상위인증서정보에 대한 참조포인터를 포함한다.
 */
struct Dot2SequentialCMHEntry
{
  struct Dot2SequentialCMHInfo info; ///< CMH 정보
  uint8_t *cert; ///< 인증서 바이트열 (동적 할당됨 -> free()로 해제되어야 함)
  Dot2CertSize cert_size; ///< 인증서 바이트열 길이
  struct Dot2SHA256 cert_h; ///< 인증서 해시
  struct Dot2SCCCertInfoEntry *issuer; ///< 상위인증서정보엔트리 참조 (SCC 저장소에 저장되어 있는)
  bool revoked; ///< 폐기되었는지 여부
#if defined(_FFASN1C_)
  dot2Certificate *asn1_cert; ///< asn.1 디코딩된 인증서 정보 (동적 할당됨 -> asn1_free_value()로 해제되어야 함)
#elif defined(_OBJASN1C_)
  OSCTXT *ctxt; ///< 인증서 디코딩에 사용된 컨텍스트 (asn1_cert를 free()할 때 필요하다)
  dot2Certificate *asn1_cert; ///< asn.1 디코딩된 인증서 형식
#else
#error "3rd party asn.1 library is not defined"
#endif
  TAILQ_ENTRY(Dot2SequentialCMHEntry) entries; ///< 리스트 연결 변수
};
TAILQ_HEAD(Dot2SequentialCMHEntryHead, Dot2SequentialCMHEntry);


/**
 * @brief Sequential CMH 리스트 형식
 *
 * 각 인증서의 유효기간 시작시점 순으로 저장된다(유효기간 시작시점이 빠른 인증서의 CMH가 앞쪽에 저장된다).
 */
struct Dot2SequentialCMHList
{
  Dot2SequentialCMHEntryNum entry_num; ///< 본 리스트에 저장된 저장된 CMH 엔트리 개수
  Dot2SequentialCMHEntryNum max_entry_num; ///< 본 리스트에 저장된 저장 가능한 CHM 엔트리 최대 개수
  struct Dot2SequentialCMHEntry *active_cmh; ///< 본 리스트에 저장된 저장된 CMH들 중 현재 서명에 사용되고 있는 CMH에 대한 참조 포인터
  struct Dot2SequentialCMHEntryHead head; ///< 본 리스트에 저장된 CMH 엔트리들에 대한 접근정보
};



#endif //V2X_SW_DOT2_CMH_SEQUENTIAL_H
