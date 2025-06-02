/** 
  * @file 
  * @brief 타 장치(End-Entity) 인증서캐시 관련 기능 정의
  * @date 2022-07-03 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_EE_CERT_CACHE_H
#define V2X_SW_DOT2_EE_CERT_CACHE_H


// 시스템 헤더 파일
#include <stddef.h>
#include <stdint.h>

// 라이브러리 의존 헤더 파일
#include "openssl/ec.h"
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "dot2-ee-cert-info.h"


/// EE 인증서캐시 유효기간(마이크로초 단위)
#define DOT2_EE_CERT_CACHE_VALID_USEC (60 * 1000000ULL)


/**
 * @brief EE 인증서캐시 엔트리 개수
 */
enum eDot2EECertCacheEntryNum
{
  kDot2EECertCacheEntryNum_Max = 10000, ///< 엔트리 최대개수(임의로 정함)
};
typedef unsigned int Dot2EECertCacheEntryNum; ///< @ref eDot2EECertCacheEntryNum


/**
 * @brief 타 장치 End-entity 인증서정보 캐시 엔트리
 */
struct Dot2EECertCacheEntry
{
  struct Dot2EECertContents contents; ///< 인증서컨텐츠정보
  uint8_t *cert; ///< 인증서 바이트열
  Dot2CertSize cert_size; ///< 인증서 바이트열 길이
  struct Dot2SHA256 cert_h; ///< 인증서 해시
  struct Dot2SCCCertInfoEntry *issuer; ///< 본 인증서를 발급한 상위인증서정보(=ACA/PCA) 참조포인터
  Dot2Time64 expiry; ///< 인증서정보 엔트리 캐싱 만기시점 (이 시점이 지나면 삭제된다)
  bool revoked; ///< 인증서 폐기 여부
  TAILQ_ENTRY(Dot2EECertCacheEntry) entries;
};
TAILQ_HEAD(Dot2EECertCacheEntryHead, Dot2EECertCacheEntry);


/**
 * @brief 타 장치 End-Entity 인증서 중 HashedID1 값(=마지막 바이트)이 동일한 인증서정보끼리 저장되는 캐시 리스트
 */
struct Dot2EECertCacheH1List
{
  Dot2EECertCacheEntryNum entry_num; ///< 리스트 내 저장된 인증서캐시 엔트리 개수
  Dot2EECertCacheEntryNum max_entry_num; ///< 리스트 내 저장가능한 인증서캐시 엔트리 최대 개수
  struct Dot2EECertCacheEntryHead head; ///< 인증서정보 엔트리들에 대한 리스트
};


/**
 * @brief 타 장치들의 End-Entity 인증서정보들이 저장되는 캐시 테이블
 *
 * 타 장치들로부터 수신한 End-entity 인증서정보들이 캐싱된다.
 */
struct Dot2EECertCacheTable
{
#define EE_CERT_H1_CACHE_LIST_NUM (256)
  struct Dot2EECertCacheH1List list[EE_CERT_H1_CACHE_LIST_NUM]; ///< H1(인증서) 값 별 인증서정보 캐시 리스트
  Dot2EECertCacheEntryNum entry_num; ///< 테이블 내 저장된 인증서캐시 엔트리 개수
  Dot2EECertCacheEntryNum max_entry_num; ///< 테이블 내 저장가능한 인증서캐시 엔트리 최대 개수
};


#endif //V2X_SW_DOT2_EE_CERT_CACHE_H
