/** 
  * @file 
  * @brief Rotate CMH 세트 관련 정의 (Pseudonym 인증서에 해당된다)
  * @date 2022-07-03 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_CMH_ROTATE_H
#define V2X_SW_DOT2_CMH_ROTATE_H


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


/**
 * @brief Rotate CMH 세트 리스트 내 세트 엔트리의 개수
 *
 * 최대값은 20년치(자체 정의한 값)를 저장할 수 있도록 다음과 같이 정의된다. \n
 *  * CMH 당 유효기간: 7일 (현 버전 SCMS 규격에 정의된 Pseudonym 인증서의 유효기간)
 *  * 최대값 = 52주 * 100년
 */
enum eDot2RotateCMHSetEntryNum
{
  kDot2RotateCMHSetEntryNum_Max = (52 * 100) ///< 52주/년 * 100년
};
typedef unsigned int Dot2RotateCMHSetEntryNum; ///< @ref eDot2RotateCMHSetEntryNum


/**
 * @brief Rotate CMH 세트 내 CMH 정보의 개수
 *
 * 현 버전의 SCMS 규격에 따르면, 동일 유효기간(1주)을 갖는 20개의 Pseudonym 인증서가 하나의 CMH 세트에 속한다.
 * Identification 인증서의 경우에는 동일 유효기간(1개월)을 갖는 1개의 인증서가 하나의 CMH 세트에 속한다.
 */
enum eDot2RotateCMHInfoNum
{
  kDot2RotateCMHInfoNum_IdCertDefault = 1, ///< 식별인증서 기본값
  kDot2RotateCMHInfoNum_PseudonymCertDefault = kDot2CertJvalue_Max + 1, ///< 익명인증서 기본값
  kDot2RotateCMHInfoNum_Max = kDot2RotateCMHInfoNum_PseudonymCertDefault
};
typedef unsigned int Dot2RotateCMHInfoNum; ///< @ref eDot2RotateCMHInfoNum


/**
 * @brief Rotate CMH 세트 내 속한 CMH들간의 공통정보
 *
 * 세트별로 하나씩 존재한다.
 */
struct Dot2RotateCMHSetCommonInfo
{
  uint32_t i; ///< iCert
  Dot2CertType type; ///< 인증서 유형
  struct Dot2CertIssuerIdentifier issuer; ///< 상위인증서 식별자 정보
  uint8_t craca_id[DOT2_CRACA_ID_LEN]; ///< cracaId
  Dot2CertCRLSeries crl_series; ///< CRL series
  Dot2Time64 valid_start; ///< 인증서 유효기간 시작 시점
  Dot2Time64 valid_end; ///< 인증서 유효기간 종료 시점
  struct Dot2CertValidRegion2 valid_region; ///< 인증서 유효지역
  Dot2CertPermissionNum psid_num; ///< 인증서 내 PSID(권한) 개수
  Dot2PSID psid[kDot2CertPermissionNum_Max]; ///< 인증서 내 PSID(들)
};


/**
 * @brief 동일 Rotate CMH 세트 내 속한 CMH들의 개별정보(서로 다른 정보)
 *
 * 세트 내 각 CMH 별로 하나씩 존재한다.
 */
struct Dot2RotateCMHIndividualInfo
{
  struct Dot2CertId id; ///< 인증서 ID
  struct Dot2ECPrivateKey priv_key; ///< 개인키 바이트열
  EC_KEY *eck_priv_key; ///< EC_KEY 형식 개인키
};


/**
 * @brief Rotate CMH 세트 내 속한 각 CMH들의 정보
 */
struct Dot2RotateCMHInfo
{
  struct Dot2RotateCMHIndividualInfo info; ///< 인증서 개별정보
  uint8_t *cert; ///< 인증서 바이트열
  Dot2CertSize cert_size; ///< 인증서 바이트열의 길이
  struct Dot2SHA256 cert_h; ///< 인증서 해시값
#if defined(_FFASN1C_)
  dot2Certificate *asn1_cert; ///< asn.1 디코딩된 인증서 정보 (SPDU에 서명자정보를 넣을 때 사용된다)
#elif defined(_OBJASN1C_)
  OSCTXT *ctxt; ///< 인증서 디코딩에 사용된 컨텍스트 (asn1_cert를 free()할 때 필요하다)
  dot2Certificate *asn1_cert; ///< asn.1 디코딩된 인증서 형식 (SPDU에 서명자정보를 넣을 때 사용된다)
#else
#error "3rd party asn.1 library is not defined"
#endif
};


/**
 * @brief Rotate CMH 세트 엔트리
 *
 * 동일한 유효기간으로 묶여 있는 인증서들에 관련된 CMH들의 모음
 * OBU의 Pseudonym 인증서가 이에 해당되며, 유효기간별로 20개의 인증서가 함께 사용된다.
 * OBU의 Identification 인증서가 이에 해당되며, 유효기간별로 1개의 인증서가 사용된다. (그래서 실제로는 인증서들이 Rotate되지 않는다)
 */
struct Dot2RotateCMHSetEntry
{
  struct Dot2RotateCMHSetCommonInfo common; ///< 세트 내 인증서들의 공통정보
  struct Dot2RotateCMHInfo cmh[kDot2RotateCMHInfoNum_PseudonymCertDefault]; ///< 세트 내 각 CMH(들)
  Dot2RotateCMHInfoNum info_num; ///< 본 세트 내에 저장된 CMH 정보의 개수
  Dot2RotateCMHInfoNum max_info_num; ///< 본 세트 내에 저장 가능한 CMH 정보의 최대 개수
  struct Dot2RotateCMHInfo *active_cmh; ///< 본 세트 내에 저장된 CMH들 중 현재 사용되는 CMH에 대한 참조 포인터
  struct Dot2SCCCertInfoEntry *issuer; ///< 상위인증서정보 참조
  TAILQ_ENTRY(Dot2RotateCMHSetEntry) entries; ///< 세트 엔트리간 연결정보
};
TAILQ_HEAD(Dot2RotateCMHSetEntryHead, Dot2RotateCMHSetEntry);


/**
 * @brief Rotate CMH 세트 리스트
 *
 * Rotate CMH 세트들이 저장되는 리스트
 * 각 인증서들의 유효기간 시작시점 순으로 저장된다(유효기간 시작시점이 빠른 인증서들에 관련된 CMH 세트가 앞쪽에 저장된다).
 */
struct Dot2RotateCMHSetList
{
  Dot2RotateCMHSetEntryNum entry_num; ///< 본 리스트에 저장된 CMH 세트 개수
  Dot2RotateCMHSetEntryNum max_entry_num; ///< 본 리스트에 저장 가능한 CMH 세트 최대 개수
  struct Dot2RotateCMHSetEntry *active_set; ///< 본 리스트에 저장된 CMH 세트들 중 현재 서명에 사용되고 있는 CMH 세트에 대한 참조 포인터
  struct Dot2RotateCMHSetEntryHead head; ///< 본 리스트에 저장된 CMH 세트들에 대한 접근정보
};


#endif //V2X_SW_DOT2_CMH_ROTATE_H
