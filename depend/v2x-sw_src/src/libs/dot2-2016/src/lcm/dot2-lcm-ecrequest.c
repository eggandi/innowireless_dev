/** 
  * @file 
  * @brief 등록인증서 발급요청문 관련 구현
  * @date 2022-05-01 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief 등록인증서 발급요청문을 생성한다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[out] res 등록인증서 발급요청문 생성 결과가 저장될 구조체 포인터
 */
void INTERNAL dot2_ConstructECRequest(
  struct Dot2ECRequestConstructParams *params,
  struct Dot2ECKeyPair *init_key_pair,
  struct Dot2ECRequestConstructResult *res)
{
  Log(kDot2LogLevel_Event, "Construct ECRequest\n");

  /*
   * 등록인증서 발급요청문을 생성한다.
   */
#if defined(_FFASN1C_)
  res->ec_req = dot2_ffasn1c_ConstructECRequest(params, init_key_pair, &(res->ret));
#elif defined(_OBJASN1C_)
  res->ec_req = dot2_objasn1c_ConstructECRequest(params, init_key_pair, &(res->ret));
#else
#error "3rd party asn.1 library is not defined"
#endif

  /*
   * 등록인증서 발급요청문의 생성이 성공하면, 임시개인키와 발급요청문 HashedId8 값을 함께 반환한다.
   */
  if (res->ec_req) {
    uint8_t h_ec_req[DOT2_SHA_256_LEN];
    SHA256(res->ec_req, res->ret, h_ec_req);
    memcpy(res->ec_req_h8, DOT2_GET_SHA256_H8(h_ec_req), 8);
    memcpy(res->init_priv_key.octs, init_key_pair->octs.priv_key.octs, DOT2_EC_256_KEY_LEN);
  }
}
