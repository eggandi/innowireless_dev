/** 
  * @file 
  * @brief 
  * @date 2022-08-06 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_CERT_INFO_INLINE_H
#define V2X_SW_DOT2_CERT_INFO_INLINE_H


// 라이브러리 의존 헤더 파일
#include "openssl/ec.h"

// 라이브러리 내부 헤더 파일
#include "dot2-ee-cert-cache.h"


/**
 * @brief 인증서 ID 정보를 제거한다.
 * @param[in] id 인증서 ID 정보
 */
static inline void dot2_ClearCertId(struct Dot2CertId *id)
{
  if ((id->type == kDot2CertIdType_Name) &&
      (id->u.name.name)) {
    free(id->u.name.name);
    id->u.name.name = NULL;
  }
}


/**
 * @brief 인증서공통컨텐츠정보를 제거한다.
 * @param[in] info 인증서공통컨텐츠정보
 */
static inline void dot2_ClearCertCommonContents(struct Dot2CertCommonContents *contents)
{
  dot2_ClearCertId(&(contents->id));
  memset(contents, 0, sizeof(struct Dot2CertCommonContents));
}


/**
 * @brief EE 인증서컨텐츠 정보를 해제한다.
 * @param contents
 */
static inline void dot2_ClearEECertContents(struct Dot2EECertContents *contents)
{
  dot2_ClearCertCommonContents(&(contents->common));
#ifdef _SIGN_VERIFY_OPENSSL_
  if (contents->eck_verify_pub_key) {
    EC_KEY_free(contents->eck_verify_pub_key);
  }
#endif
  memset(contents, 0, sizeof(struct Dot2EECertContents));
}


/**
 * @brief EE 인증서캐시 엔트리의 내용을 삭제한다.
 * @param[in] entry EE 인증서캐시 엔트리
 */
static inline void dot2_ClearEECertCacheEntry(struct Dot2EECertCacheEntry *entry)
{
  dot2_ClearEECertContents(&(entry->contents));
  if (entry->cert) {
    free(entry->cert);
    entry->cert = NULL;
  }
  entry->cert_size = 0;
  memset(entry->cert_h.octs, 0, DOT2_SHA_256_LEN);
  entry->issuer = NULL;
  entry->expiry = 0ULL;
  entry->revoked = false;
}


/**
 * @brief EE 인증서캐시 엔트리를 제거한다.
 * @param[in] entry EE 인증서캐시 엔트리
 */
static inline void dot2_FreeEECertCacheEntry(struct Dot2EECertCacheEntry *entry)
{
  if (entry) {
    dot2_ClearEECertCacheEntry(entry);
    free(entry);
  }
}


/**
 * @brief EE 인증서캐시 엔트리를 생성한다.
 * @param[in] cert 인증서캐시 엔트리에 저장될 인증서바이트열
 * @param[in] cert_size 인증서캐시 엔트리에 저장될 인증서바이트열 길이
 * @retval 인증서캐시 엔트리 포인터: 성공
 * @retval NULL: 실패
 */
static inline struct Dot2EECertCacheEntry * dot2_AllocateEECertCacheEntry(const uint8_t *cert, Dot2CertSize cert_size)
{
  struct Dot2EECertCacheEntry *entry = (struct Dot2EECertCacheEntry *)calloc(1, sizeof(struct Dot2EECertCacheEntry));
  if (entry) {
    if (cert) {
      entry->cert = (uint8_t *)malloc(cert_size);
      if (entry->cert) {
        memcpy(entry->cert, cert, cert_size);
        entry->cert_size = cert_size;
      } else {
        free(entry);
        return NULL;
      }
    }
  }
  return entry;
}


/**
 * @brief 특정 H8 값을 갖는 EE 인증서캐시정보를 찾는다.
 * @param[in] h8 찾고자 하는 인증서 H8
 * @retval 인증서캐시정보엔트리 포인터: 성공
 * @retval NULL: 실패
 */
static inline struct Dot2EECertCacheEntry * dot2_FindEECertCacheWithH8(const uint8_t *h8)
{
  uint8_t h1 = h8[7];
  struct Dot2EECertCacheH1List *list = &(g_dot2_mib.ee_cert_cache_table.list[h1]);
  struct Dot2EECertCacheEntry *entry;
  TAILQ_FOREACH(entry, &(list->head), entries) {
    if (memcmp(DOT2_GET_SHA256_H8(entry->cert_h.octs), h8, 8) == 0) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief 타 장치(EE) 인증서정보 캐시엔트리의 인증서폐기정보를 업데이트한다.
 * @param[in] entry 타 장치(EE) 인증서정보 캐시엔트리
 */
static inline void dot2_UpdateEECertCacheEntryRevocation(struct Dot2EECertCacheEntry *entry)
{
#ifdef _SUPPORT_SCMS_
  if (dot2_CheckCertRevocation(&(entry->contents.common.id), DOT2_GET_SHA256_H10(entry->cert_h.octs))) {
    entry->revoked = true;
  }
#else
  (void)entry;
#endif
}


#endif //V2X_SW_DOT2_CERT_INFO_INLINE_H
