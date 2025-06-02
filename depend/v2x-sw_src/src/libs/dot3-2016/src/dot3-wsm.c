/**
 * @file
 * @brief WSM 생성 및 파싱하는 기능을 구현한 파일
 * @date 2019-06-27
 * @author gyun
 */

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#if defined(_OBJASN1C_)
#include "dot3-objasn1c.h"
#elif defined(_FFASN1C_)
#include "dot3-ffasn1c.h"
#endif


/**
 * @brief 전달된 송신파라미터들과 페이로드를 이용하여 UPER 인코딩된 WSM을 생성 후 반환한다.
 * @param[in] params WSM 헤더구성정보
 * @param[in] payload 상위계층 페이로드
 * @param[in] payload_size 상위계층 페이로드 길이
 * @param[out] wsm_size 생성된 WSM의 길이가 반환될 변수 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @retval 생성된 WSM: 성공
 * @retval NULL: 실패
 *
 * 빌드 옵션(CMakeLists.txt 참조)에 따른 3rd party ASN.1 라이브러리가 적용된다.
 */
uint8_t INTERNAL * dot3_ConstructWSM(
  struct Dot3WSMConstructParams *params,
  const uint8_t *payload,
  Dot3WSMPayloadSize payload_size,
  size_t *wsm_size,
  int *err)
{
#if defined(_OBJASN1C_)
  return dot3_objasn1c_EncodeWSM(params, payload, payload_size, wsm_size, err);
#elif defined(_FFASN1C_)
  return dot3_ffasn1c_EncodeWSM(params, payload, payload_size, wsm_size, err);
#else
#error "3rd party asn.1 library is not defined"
#endif
}


/**
 * @brief WSM을 UPER 디코딩한 후, WSMP 헤더정보를 반환한다.
 * @param[in] wsm 파싱할 WSM이 저장된 버퍼
 * @param[in] wsm_size wsm 버퍼에 담긴 WSM의 크기
 * @param[out] payload_size 반환되는 페이로드의 길이가 저장될 변수의 포인터
 * @param[out] params WSMP 헤더정보가 저장될 구조체의 포인터
 * @param[out] ret 처리결과코드(Dot3ResultCode)가 반환될 변수 포인터
 * @retval WSM body에 수납되어 있는 페이로드: 성공
 * @retval NULL: WSM body가 비어 있는 경우 또는 실패
 *
 * 빌드 옵션(CMakeLists.txt 참조)에 따른 ASN.1 라이브러리가 적용된다.
 */
uint8_t INTERNAL * dot3_ParseWSM(
  const uint8_t *wsm,
  Dot3WSMSize wsm_size,
  size_t *payload_size,
  struct Dot3WSMParseParams *params,
  int *ret)
{
#if defined(_OBJASN1C_)
  return dot3_objasn1c_DecodeWSM(wsm, wsm_size, payload_size, params, ret);
#elif defined(_FFASN1C_)
  return dot3_ffasn1c_DecodeWSM(wsm, wsm_size, payload_size, params, ret);
#else
#error "3rd party asn.1 library is not defined"
#endif
}
