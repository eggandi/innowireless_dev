/**
 * @file
 * @brief WSM(WAVE Short Message) 관련 API들을 구현한 파일
 * @date 2019-06-06
 * @author gyun
 */

// 시스템 헤더 파일
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief WSM 헤더구성정보 파라미터의 유효성을 체크한다.
 * @param params 유효성을 체크할 WSM 헤더구성정보 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_CheckWSMConstructParams(struct Dot3WSMConstructParams *params)
{
  if (dot3_IsValidPSID(params->psid) == false) {
    Err("Fail to construct WSM - invalid PSID %u\n", params->psid);
    return -kDot3Result_InvalidPSID;
  }
  if ((params->chan_num != kDot3ChannelNumber_NA) && // NA: 확장헤더 불포함을 지시하기 위한 값
      (dot3_IsValidChannelNumber(params->chan_num) == false)) {
    Err("Fail to construct WSM - invalid channel number %u\n", params->chan_num);
    return -kDot3Result_InvalidChannelNumber;
  }
  if ((params->datarate != kDot3DataRate_NA) && // NA: 확장헤더 불포함을 지시하기 위한 값
      (dot3_IsValidDataRate(params->datarate) == false)) {
    Err("Fail to construct WSM - invalid datarate %u\n", params->datarate);
    return -kDot3Result_InvalidDataRate;
  }
  if ((params->transmit_power != kDot3Power_NA) && // NA: 확장헤더 불포함을 지시하기 위한 값
      (dot3_IsValidPower(params->transmit_power) == false)) {
    Err("Fail to construct WSM - invalid transmit power %d\n", params->transmit_power);
    return -kDot3Result_InvalidPower;
  }
  return kDot3Result_Success;
}


/**
 * @brief 송신하고자 하는 WSM의 생성을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] params WSM 헤더구성정보
 * @param[in] payload WSM에 수납될 페이로드(예: Ieee1609Dot2Data)가 담긴 버퍼
 * @param[in] payload_size payload 버퍼에 담긴 페이로드의 길이
 * @param[out] wsm_size 생성된 WSM의 길이가 반환될 변수 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return 생성된 WSM
 * @retval NULL: 실패
 */
uint8_t OPEN_API * Dot3_ConstructWSM(
  struct Dot3WSMConstructParams *params,
  const uint8_t *payload,
  Dot3WSMPayloadSize payload_size,
  size_t *wsm_size,
  int *err)
{
  Log(kDot3LogLevel_Event, "Construct WSM - payload size is %u\n", payload_size);

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터 체크
   *  - 페이로드 길이 유효성 체크
   *  - WSM 헤더구성정보 파라미터 유효성 체크
   */
  if (err == NULL) {
    Err("Fail to construct WSM - null err parameter\n");
    return NULL;
  }
  if ((params == NULL) || (wsm_size == NULL)) {
    Err("Fail to construct WSM - null parameters - params: %p, wsm_size: %p\n", params, wsm_size);
    *err = -kDot3Result_NullParameters;
    return NULL;
  }
  if (dot3_IsValidWSMPayloadSize(payload_size) == false) {
    Err("Fail to construct WSM - invalid payload size %u\n", payload_size);
    *err = -kDot3Result_InvalidWSMPayloadSize;
    return NULL;
  }
  *err = dot3_CheckWSMConstructParams(params);
  if (*err < 0) {
    return NULL;
  }

  /*
   * WSM 패킷을 생성한다.
   */
  uint8_t *wsm = dot3_ConstructWSM(params, payload, payload_size, wsm_size, err);
  if (wsm == NULL) {
    return NULL;
  }

  /*
   * 생성된 WSM의 길이가 설정된 최대값보다 클 경우 에러를 반환한다.
   */
  if (*wsm_size > g_dot3_mib.wsm_max_len) {
    Err("Fail to construct WSM - too long WSM: %u > %u\n", *wsm_size, g_dot3_mib.wsm_max_len);
    *err = -kDot3Result_InvalidWSMSize;
    free(wsm);
    return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to construct %u-bytes WSM\n", *wsm_size);
  return wsm;
}


/**
 * @brief 송신하고자 하는 WSM MPDU의 생성을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] params WSM 헤더 및 MAC 헤더 구성정보
 * @param[in] payload WSM에 수납될 페이로드(예: Ieee1609Dot2Data)가 담긴 버퍼
 * @param[in] payload_size payload 버퍼에 담긴 페이로드의 길이
 * @param[out] mpdu_size 생성된 MPDU의 길이가 반환될 변수 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return 생성된 MPDU
 * @retval NULL: 실패
 */
uint8_t OPEN_API * Dot3_ConstructWSMMPDU(
  struct Dot3MACAndWSMConstructParams *params,
  const uint8_t *payload,
  Dot3WSMPayloadSize payload_size,
  size_t *mpdu_size,
  int *err)
{
  Log(kDot3LogLevel_Event, "Construct WSM MPDU - payload size is %u\n", payload_size);

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터 체크
   *  - 페이로드 길이 유효성 체크
   *  - WSM 헤더구성정보 파라미터 유효성 체크
   *  - MAC 헤더구성정보(우선순위) 유효성 체크
   */
  if (err == NULL) {
    Err("Fail to construct WSM MPDU - null err parameter\n");
    return NULL;
  }
  if ((params == NULL) || (mpdu_size == NULL)) {
    Err("Fail to construct WSM MPDU - null parameters - params: %p, wsm_size: %p\n", params, mpdu_size);
    *err = -kDot3Result_NullParameters;
    return NULL;
  }
  if (dot3_IsValidWSMPayloadSize(payload_size) == false) {
    Err("Fail to construct WSM MPDU - invalid payload size %u\n", payload_size);
    *err = -kDot3Result_InvalidWSMPayloadSize;
    return NULL;
  }
  *err = dot3_CheckWSMConstructParams(&(params->wsm));
  if (*err < 0) {
    return NULL;
  }
  if (dot3_IsValidPriority(params->mac.priority) == false) {
    Err("Fail to construct WSM MPDU - invalid priority %u\n", params->mac.priority);
    *err = -kDot3Result_InvalidPriority;
    return NULL;
  }

  /*
   * WSM을 생성한다.
   */
  size_t wsm_size;
  uint8_t *wsm = dot3_ConstructWSM(&(params->wsm), payload, payload_size, &wsm_size, err);
  if (wsm == NULL) {
    return NULL;
  }

  /*
   * 생성된 WSM의 길이가 설정된 최대값보다 클 경우 에러를 반환한다.
   */
  if (wsm_size > g_dot3_mib.wsm_max_len) {
    Err("Fail to construct WSM MPDU - too long WSM: %u > %u\n", wsm_size, g_dot3_mib.wsm_max_len);
    *err = -kDot3Result_InvalidWSMSize;
    free(wsm);
    return NULL;
  }

  /*
   * MPDU를 생성한다.
   */
  uint8_t *mpdu = dot3_ConstructMPDU(&(params->mac), wsm, wsm_size, mpdu_size, err);
  free(wsm);
  if (mpdu == NULL) {
    return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to construct %u-bytes WSM MPDU\n", *mpdu_size);
  return mpdu;
}


/**
 * @brief 수신된 WSM에 대한 파싱을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] wsm 파싱할 WSM이 담긴 버퍼
 * @param[in] wsm_size wsm 버퍼에 담긴 WSM의 길이
 * @param[out] params WSM 헤더정보가 반환될 구조체 포인터
 * @param[out] payload_size WSM body에 수납된 페이로드의 길이가 반환될 변수 포인터
 * @param[out] wsr_registered WSM에 수납된 PSID가 관심서비스의 PSID인지 여부가 저장될 변수 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return WSM body에 수납되어 있는 페이로드
 * @retval NULL: WSM body가 비어 있는 경우 또는 실패
 */
uint8_t OPEN_API * Dot3_ParseWSM(
  const uint8_t *wsm,
  Dot3WSMSize wsm_size,
  struct Dot3WSMParseParams *params,
  size_t *payload_size,
  bool *wsr_registered,
  int *err)
{
  Log(kDot3LogLevel_Event, "Parse %u-bytes WSM\n", wsm_size);

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터 체크
   *  - WSM 길이 체크
   */
  if (err == NULL) {
    Err("Fail to parse WSM - null err parameter\n");
    return NULL;
  }
  if ((wsm == NULL) || (params == NULL) || (payload_size == NULL) || (wsr_registered == NULL)) {
    Err("Fail to parse WSM - null parameters - wsm: %p, params: %p, payload_size: %p, wsr_registered: %p\n",
      wsm, params, payload_size, wsr_registered);
    *err = -kDot3Result_NullParameters;
    return NULL;
  }
  if (dot3_IsValidWSMSize(wsm_size) == false) {
    Err("Fail to parse WSM - invalid WSM size %u\n", wsm_size);
    *err = -kDot3Result_InvalidWSMSize;
    return NULL;
  }

  /*
   * WSM을 파싱한다 - 페이로드(WSM body) 및 WSMP 헤더정보가 반환된다.
   */
  memset(params, 0, sizeof(struct Dot3WSMParseParams));
  uint8_t *payload = dot3_ParseWSM(wsm, wsm_size, payload_size, params, err);
  if (*err < 0) {
    return NULL;
  }

  /*
   * 해당 PSID가 WSR 테이블에 등록되어 있는지 확인하여 반환한다.
   */
  struct Dot3WSRTable *wsr_table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(wsr_table->mtx));
  if (dot3_FindWSRWithPSID(wsr_table, params->psid) != NULL) {
    *wsr_registered = true;
  } else {
    *wsr_registered = false;
  }
  pthread_mutex_unlock(&(wsr_table->mtx));

  Log(kDot3LogLevel_Event, "Success to parse WSM - payload size is %u\n", *payload_size);
  *err = kDot3Result_Success;
  return payload;
}


/**
 * @brief 수신된 WSM MPDU에 대한 파싱을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] mpdu 파싱할 MPDU가 담긴 버퍼
 * @param[in] mpdu_size mpdu 버퍼에 담긴 WSM의 길이
 * @param[out] params WSM 헤더정보가 반환될 구조체 포인터
 * @param[out] payload_size 반환되는 페이로드의 길이가 저장될 변수 포인터
 * @param[out] wsr_registered WSM에 수납된 PSID가 관심서비스의 PSID인지 여부가 저장될 변수 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return WSM body에 수납되어 있는 페이로드
 * @retval NULL: WSM body가 비어 있는 경우 또는 실패
 */
uint8_t OPEN_API * Dot3_ParseWSMMPDU(
  const uint8_t *mpdu,
  Dot3MPDUSize mpdu_size,
  struct Dot3MACAndWSMParseParams *params,
  size_t *payload_size,
  bool *wsr_registered,
  int *err)
{
  Log(kDot3LogLevel_Event, "Parse %u-bytes WSM MPDU\n", mpdu_size);

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터 체크
   *  - WSM 길이 체크
   */
  if (err == NULL) {
    Err("Fail to parse WSM MPDU - null err parameter\n");
    return NULL;
  }
  if ((mpdu == NULL) || (params == NULL) || (payload_size == NULL) || (wsr_registered == NULL)) {
    Err("Fail to parse WSM MPDU - null parameters - mpdu: %p, params: %p, payload_size: %p, wsr_registered: %p\n",
        mpdu, params, payload_size, wsr_registered);
    *err = -kDot3Result_NullParameters;
    return NULL;
  }
  if (dot3_IsValidMPDUSize(mpdu_size) == false) {
    Err("Fail to parse WSM MPDU - invalid MPDU size %u\n", mpdu_size);
    *err = -kDot3Result_InvalidMPDUSize;
    return NULL;
  }

  memset(params, 0, sizeof(struct Dot3MACAndWSMParseParams));

  /*
   * MPDU를 파싱한다.
   */
  *err = dot3_ParseMPDU(mpdu, &(params->mac));
  if (*err < 0) {
    return NULL;
  }

  /*
   * WSM을 파싱한다 - 페이로드(WSM body) 및 WSMP 헤더정보가 반환된다.
   */
  size_t ll_hdr_len = sizeof(struct Dot11MACHdr) + sizeof(struct LLCHdr);
  uint8_t *payload = dot3_ParseWSM(mpdu + ll_hdr_len,
                                   (size_t)(mpdu_size - ll_hdr_len),
                                   payload_size,
                                   &(params->wsm),
                                   err);
  if (*err < 0) {
    return NULL;
  }

  /*
   * 해당 PSID가 WSR 테이블에 등록되어 있는지 확인하여 반환한다.
   */
  struct Dot3WSRTable *wsr_table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(wsr_table->mtx));
  if (dot3_FindWSRWithPSID(wsr_table, params->wsm.psid) != NULL) {
    *wsr_registered = true;
  } else {
    *wsr_registered = false;
  }
  pthread_mutex_unlock(&(wsr_table->mtx));

  Log(kDot3LogLevel_Event, "Success to parse WSM MPDU - payload size is %u\n", *payload_size);
  *err = kDot3Result_Success;
  return payload;
}


/**
 * @brief 생성 가능한 WSM(헤더 포함) 최대허용길이를 설정한다(상세 내용 API 매뉴얼 참조).
 * @param[in] max_len 생성 가능한 WSM의 최대길이(WSM 헤더 포함)
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_SetWSMMaxLength(Dot3WSMSize max_len)
{
  Log(kDot3LogLevel_Event, "Set WSM max length as %u\n", max_len);

  /*
   * 값의 유효성을 확인한다.
   */
  if (dot3_IsValidWSMSize(max_len) == false)  {
    Err("Fail to set WSM max length - invalid length %u\n", max_len);
    return -kDot3Result_InvalidWSMMaxLength;
  }

  g_dot3_mib.wsm_max_len = max_len;

  Log(kDot3LogLevel_Event, "Success to set WSM max length\n");
  return kDot3Result_Success;
}
