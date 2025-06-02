/** 
  * @file 
  * @brief SCC 인증서정보 관련 정의
  * @date 2022-07-02 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_SCC_CERT_INFO_H
#define V2X_SW_DOT2_SCC_CERT_INFO_H


// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"
#include "openssl/ec.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-cert-info.h"


/**
 * @brief SCC 인증서 유형
 */
enum eDot2SCCCertType
{
  kDot2SCCCertType_Unknown = 0, ///< 유형을 알 수 없음
  kDot2SCCCertType_RCA = 0x810001,
  kDot2SCCCertType_ICA = 0x830001,
  kDot2SCCCertType_ECA = 0x840001,
  kDot2SCCCertType_PCA = 0x850001,
  kDot2SCCCertType_CRLG = 0x860001,
  kDot2SCCCertType_RA = 0x8B0001,
};
typedef unsigned int Dot2SCCCertType; ///< @ref eDot2SCCCertType


/**
 * @brief SCC인증서 컨텐츠 정보 형식
 *
 * SCC인증서 내에 포함된 정보들이 저장된다.
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라;
 *  - SCC인증서는 Explicit 인증서이다 -> 서명검증용공개키가 포함된다.
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1을 준수하는 인증서 내 정보 중,
 *  - appPermissions, certIssuePermissions, certReqPermissions는 저장되지 않는다 (현 시점 기준으로 해당 정보는 사용되지 않는다)
 */
struct Dot2SCCCertContents
{
  Dot2SCCCertType type; ///< SCC 인증서 유형
  struct Dot2CertCommonContents common; ///< 인증서 공통컨텐츠정보
  struct Dot2ECPublicKey verify_pub_key; ///< 서명검증용공개키 바이트열
  EC_KEY *eck_verify_pub_key; ///< EC_KEY 형식 서명검증용공개키 (동적 할당됨 -> EC_KEY_free()로 해제되어야 함)
  EC_KEY *eck_enc_pub_key; ///< EC_KEY 형식 암호화용공개키 (common.enc_pub_key_present=true일 경우 존재)
                           ///< (동적 할당됨 -> EC_KEY_free()로 해제되어야 함)
};


/**
 * @brief SCC인증서정보 엔트리
 */
struct Dot2SCCCertInfoEntry
{
  struct Dot2SCCCertContents contents; ///< 인증서컨텐츠 정보
  uint8_t *cert; ///< 인증서 바이트열
  size_t cert_size; ///< 인증서 바이트열 길이
  struct Dot2SHA256 cert_h; ///< 인증서 해시
  struct Dot2SCCCertInfoEntry *issuer; ///< 본 인증서를 발급한 상위인증서정보(ICA or RCA or ...) 참조포인터
  Dot2CertRevocationStatus revoke; ///< 인증서 폐기상태
  TAILQ_ENTRY(Dot2SCCCertInfoEntry) entries;
};
TAILQ_HEAD(Dot2SCCCertInfoEntryHead, Dot2SCCCertInfoEntry);


/**
 * @brief Service Certificate Chain에 속한 인증서정보가 저장되는 리스트 형식
 */
struct Dot2SCCCertInfoList
{
  Dot2CertInfoEntryNum entry_num; ///< 리스트에 저장된 SCC인증서정보 엔트리 개수
  Dot2CertInfoEntryNum max_entry_num; ///< 리스트에 저장될 수 있는 SCC인증서정보 엔트리 최대 개수
  struct Dot2SCCCertInfoEntryHead head;
};


/**
 * @brief SCC인증서정보 테이블 형식
 *
 * SCC인증서정보들이 저장된다.
 */
struct Dot2SCCCertInfoTable
{
  struct Dot2SCCCertInfoList scc; ///< Service Certifiate Chain에 속한 인증서정보 리스트
  struct Dot2SCCCertInfoEntry *ra; ///< RA인증서정보 참조 (scc 리스트 내에 저장된 RA 엔트리를 참조한다)
  struct Dot2SCCCertInfoEntry *pca; ///< PCA/ACA인증서정보 참조 (scc 리스트 내에 저장된 PCA/ACA 엔트리를 참조한다)
  // struct Dot2SCCCertInfoEntry *ma; ///< MA인증서정보(현재 사용되지 않음)
};


#endif //V2X_SW_DOT2_SCC_CERT_INFO_H
