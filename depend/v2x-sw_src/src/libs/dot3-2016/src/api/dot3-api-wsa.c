/**
 * @file
 * @brief WSA(WAVE Service Advertisement) 관련 API들을 구현한 파일
 * @date 2019-08-17
 * @author gyun
 */

// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief WSA 헤더구성정보 파라미터의 유효성을 검사한다.
 * @param[in] params WSA 헤더구성정보 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_CheckWSAConstructParams(const struct Dot3ConstructWSAParams *params)
{
  if (dot3_IsValidWSAIdentifier(params->hdr.wsa_id) == false) {
    Err("Fail to construct WSA - invalid wsa id %u\n", params->hdr.wsa_id);
    return -kDot3Result_InvalidWSAIdentifier;
  }
  if (dot3_IsValidWSAContentCount(params->hdr.content_count) == false) {
    Err("Fail to construct WSA - invalid content count %u\n", params->hdr.content_count);
    return -kDot3Result_InvalidWSAContentCount;
  }
  if ((params->hdr.extensions.repeat_rate == true) &&
      (dot3_IsValidWSARepeatRate(params->hdr.repeat_rate) == false)) {
    Err("Fail to construct WSA - invalid repeat rate %u\n", params->hdr.repeat_rate);
    return -kDot3Result_InvalidRepeatRate;
  }
  if (params->hdr.extensions.twod_location == true) {
    if (dot3_IsValidLatitude(params->hdr.twod_location.latitude) == false) {
      Err("Fail to construct WSA - invalid latitude %d\n", params->hdr.twod_location.latitude);
      return -kDot3Result_InvalidLatitude;
    }
    if (dot3_IsValidLongitude(params->hdr.twod_location.longitude) == false) {
      Err("Fail to construct WSA - invalid longitude %d\n", params->hdr.twod_location.longitude);
      return -kDot3Result_InvalidLongitude;
    }
  }
  if (params->hdr.extensions.threed_location == true) {
    if (dot3_IsValidLatitude(params->hdr.threed_location.latitude) == false) {
      Err("Fail to construct WSA - invalid latitude %d\n", params->hdr.threed_location.latitude);
      return -kDot3Result_InvalidLatitude;
    }
    if (dot3_IsValidLongitude(params->hdr.threed_location.longitude) == false) {
      Err("Fail to construct WSA - invalid longitude %d\n", params->hdr.threed_location.longitude);
      return -kDot3Result_InvalidLongitude;
    }
    if (dot3_IsValidElevation(params->hdr.threed_location.elevation) == false) {
      Err("Fail to construct WSA - invalid elevation %d\n", params->hdr.threed_location.elevation);
      return -kDot3Result_InvalidElevation;
    }
  }
  if ((params->hdr.extensions.advertiser_id == true) &&
      (dot3_IsValidWSAAdvertiserIDLen(params->hdr.advertiser_id.len) == false)) {
    Err("Fail to construct WSA - invalid advertiser id len %u\n", params->hdr.advertiser_id.len);
    return -kDot3Result_InvalidAdvertiserIDLen;
  }
  if (params->present.wra == true) {
    if (dot3_IsValidWRARouterLifetime(params->wra.router_lifetime) == false) {
      Err("Fail to construct WSA - invalid WRA router lifetime %u\n", params->wra.router_lifetime);
      return -kDot3Result_InvalidWRARouterLifetime;
    }
    if (dot3_IsValidIPv6PrefixLen(params->wra.ip_prefix_len) == false) {
      Err("Fail to construct WSA - invalid ipv6 prefix len %u\n", params->wra.ip_prefix_len);
      return -kDot3Result_InvalidIPv6PrefixLen;
    }
  }
  return kDot3Result_Success;
}


/**
 * @brief WSA 생성을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] params WSA 헤더 및 WRA 구성정보
 * @param[out] wsa_size 생성된 WSA의 길이가 반환될 변수의 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return 생성된 WSA
 * @retval NULL: 실패
 */
uint8_t OPEN_API * Dot3_ConstructWSA(const struct Dot3ConstructWSAParams *params, size_t *wsa_size, int *err)
{
  Log(kDot3LogLevel_Event, "Construct WSA\n");

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   *  - WSA 헤더구성정보 파라미터 유효성 체크
   */
  if (err == NULL) {
    Err("Fail to construct WSA - null err parameter\n");
    return NULL;
  }
  if ((params == NULL) || (wsa_size == NULL)) {
    Err("Fail to construct WSA - null parameters - params: %p, wsa_size: %p\n", params, wsa_size);
    *err = -kDot3Result_NullParameters;
    return NULL;
  }
  *err = dot3_CheckWSAConstructParams(params);
  if (*err < 0) {
    return NULL;
  }

  /*
   * WSA를 생성한다.
   */
  uint8_t *wsa = dot3_ConstructWSA(params, wsa_size, err);
  if (wsa == NULL) {
    return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to construct %u-bytes WSA\n", *wsa_size);
  return wsa;
}


/**
 * @brief WSA 파싱을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] wsa 파싱할 WSA가 담긴 버퍼
 * @param[in] wsa_size wsa 버퍼에 담긴 WSA의 길이
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_ParseWSA(const uint8_t *wsa, size_t wsa_size, struct Dot3ParseWSAParams *params)
{
  Log(kDot3LogLevel_Event, "Parse WSA\n");

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터 체크
   */
  if ((wsa == NULL) || (params == NULL)) {
    Err("Fail to parse WSA - null parameters - wsa: %p, params: %p\n", wsa, params);
    return -kDot3Result_NullParameters;
  }

  /*
   * WSA를 파싱한다.
   */
  memset(params, 0, sizeof(struct Dot3ParseWSAParams));
  return dot3_ParseWSA(wsa, wsa_size, params);
}


/**
 * @brief WSA 처리를 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] wsa 처리할 WSA가 담긴 버퍼
 * @param[in] wsa_size wsa 버퍼에 담긴 WSA의 길이
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA 유형
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat WSA 송신지 위도
 * @param[in] tx_lon WSA 송신지 경도
 * @param[in] tx_elev WSA 송신지 고도
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_ProcessWSA(
  const uint8_t *wsa,
  size_t wsa_size,
  const Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  struct Dot3ParseWSAParams *params)
{
  Log(kDot3LogLevel_Event, "Process WSA\n");

  /*
   * 파라미터 유효성을 체크한다.
   */
  if ((wsa == NULL) || (src_mac_addr == NULL) || (params == NULL)) {
    Err("Fail to process WSA - null parameters - wsa: %p, params: %p, src_mac_addr: %p\n", wsa, params, src_mac_addr);
    return -kDot3Result_NullParameters;
  }
  if (dot3_IsValidWSAType(wsa_type) == false) {
    Err("Fail to process WSA - invalid WSA type %u\n", wsa_type);
    return -kDot3Result_InvalidWSAType;
  }
  if (dot3_IsValidRCPI(rcpi) == false) {
    Err("Fail to process WSA - invalid RCPI %u\n", rcpi);
    return -kDot3Result_InvalidRCPI;
  }
  if ((tx_lat != kDot3Latitude_Unavailable) && (dot3_IsValidLatitude(tx_lat) == false)) {
    Err("Fail to process WSA - invalid tx latitude %u\n", tx_lat);
    return -kDot3Result_InvalidLatitude;
  }
  if ((tx_lon != kDot3Longitude_Unavailable) && (dot3_IsValidLongitude(tx_lon) == false)) {
    Err("Fail to process WSA - invalid tx longitude %u\n", tx_lon);
    return -kDot3Result_InvalidLongitude;
  }
  if ((tx_elev != kDot3Elevation_Unavailable) && (dot3_IsValidElevation(tx_elev) == false)) {
    Err("Fail to process WSA - invalid tx elevation %u\n", tx_elev);
    return -kDot3Result_InvalidElevation;
  }

  /*
   * WSA 정보를 파싱한다.
   */
  memset(params, 0, sizeof(struct Dot3ParseWSAParams));
  int ret = dot3_ParseWSA(wsa, wsa_size, params);
  if (ret < 0) {
    return ret;
  }

  /*
   * WSA를 처리한다.
   */
  return dot3_ProcessWSA(wsa, wsa_size, src_mac_addr, wsa_type, rcpi, tx_lat, tx_lon, tx_elev, params);
}
