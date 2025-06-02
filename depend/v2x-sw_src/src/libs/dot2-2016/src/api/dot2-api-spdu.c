/** 
  * @file 
  * @brief 
  * @date 2021-08-02 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"
#include "v2x-sw.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "spdu/dot2-spdu-inline.h"


/**
 * @brief SPDU 생성 파라미터의 유효성을 체크한다.
 * @param[in] params 유효성을 체크할 SPDU 생성 파라미터
 * @param[in] payload SPDU에 수납될 페이로드 (NULL 가능)
 * @param[in] payload_size 페이로드의 길이 (0 가능)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckSPDUConstructParams(
  const struct Dot2SPDUConstructParams *params,
  const uint8_t *payload,
  Dot2SPDUSize payload_size)
{
  if (dot2_CheckSPDUConstructType(params->type) == false) {
    return -kDot2Result_SPDU_InvalidSPDUConstructType;
  }
  if (params->type != kDot2SPDUConstructType_Unsecured) {
    if (dot2_CheckPSID(params->signed_data.psid) == false) {
      return -kDot2Result_SPDU_InvalidPSID;
    }
    if (dot2_CheckSPDUConstructSignerIdType(params->signed_data.signer_id_type) == false) {
      return -kDot2Result_SPDU_InvalidSignerIdType;
    }
    if (dot2_CheckThreeDLocation(&(params->signed_data.gen_location)) == false) {
      return -kDot2Result_SPDU_InvalidPosition;
    }
  }
  if ((payload == NULL) &&
      (payload_size != 0)) {
    return -kDot2Result_SPDU_NullParameters;
  }
  if ((payload != NULL) &&
      (payload_size == 0)) {
    return -kDot2Result_SPDU_InvalidPayloadSize;
  }
  if (dot2_CheckSPDUPayloadSize(payload_size) == false) {
    return -kDot2Result_SPDU_InvalidPayloadSize;
  }
  return kDot2Result_Success;
}


/**
 * @brief SPDU(Secure Protocol Data Unit)의 생성을 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] params SPDU 생성을 위한 파라미터
 * @param[in] payload SPDU에 수납될 페이로드(예: WSA, BSM, ...). 페이로드가 없는 SPDU를 생성하고자 할 경우 NULL 전달 가능.
 * @param[in] payload_size 페이로드의 길이. 페이로드가 없는 SPDU를 생성하고자 할 경우 0 전달.
 * @return SPDU 생성 결과
 */
struct Dot2SPDUConstructResult OPEN_API
Dot2_ConstructSPDU(const struct Dot2SPDUConstructParams *params, const uint8_t *payload, Dot2SPDUSize payload_size)
{
  Log(kDot2LogLevel_Event, "Construct SPDU with %zu-bytes payload\n", payload_size);

  struct Dot2SPDUConstructResult res = DOT2_SPDU_CONSTRUCT_RESULT_INITIALIZER;

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    res.ret = -kDot2Result_SPDU_NullParameters;
    return res;
  }
  res.ret = dot2_CheckSPDUConstructParams(params, payload, payload_size);
  if (res.ret < 0) {
    return res;
  }

  /*
   * 어플리케이션이 SPDU 생성 시각을 전달하지 않았으면, 직접 계산한다.
   */
  Dot2Time64 gen_time = params->time ? params->time : dot2_GetCurrentTime64();

  /*
   * SPDU를 생성한다.
   */
  if (params->type == kDot2SPDUConstructType_Unsecured) {
    res.ret = dot2_ConstructUnsecuredSPDU(payload, payload_size, &(res.spdu));
  } else {
    res.ret = dot2_ConstructSignedSPDU(payload,
                                       payload_size,
                                       params->signed_data.psid,
                                       gen_time,
                                       params->signed_data.signer_id_type,
                                       &(params->signed_data.gen_location),
                                       params->signed_data.cmh_change,
                                       &(res.spdu),
                                       &(res.cmh_expiry));
  }
  return res;
}


/**
 * @brief SPDU 처리 파라미터의 유효성을 체크한다.
 * @param[in] spdu_size 처리할 SPDU의 길이
 * @param[in] params SPDU 처리를 위한 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckSPDUProcessParams(Dot2SPDUSize spdu_size, const struct Dot2SPDUProcessParams *params)
{
  if (dot2_CheckSPDUSize(spdu_size) == false) {
    return -kDot2Result_SPDU_InvalidSPDUSize;
  }
  if (dot2_CheckPSID(params->rx_psid) == false) {
    return -kDot2Result_SPDU_InvalidPSID;
  }
  if (dot2_CheckTwoDLocation(&(params->rx_pos)) == false) {
    return -kDot2Result_SPDU_InvalidPosition;
  }
  return kDot2Result_Success;
}



/**
 * @brief (수신된) SPDU(Secured Protocol Data Unit)의 처리를 요청한다(상세 내용 API 매뉴얼 참조).
 * @param[in] spdu 처리할 SPDU (인코딩된 Ieee1609Dot2Data) (NULL 불가)
 * @param[in] spdu_size 처리할 SPDU의 길이
 * @param[in] params SPDU 처리를 위한 파라미터
 * @param[in] parsed 패킷파싱데이터 (dot2 파싱정보가 저장된 후 콜백함수를 통해 어플리케이션으로 전달된다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int OPEN_API Dot2_ProcessSPDU(
  const uint8_t *spdu,
  Dot2SPDUSize spdu_size,
  struct Dot2SPDUProcessParams *params,
  struct V2XPacketParseData *parsed)
{
  Log(kDot2LogLevel_Event, "Process %zu-bytes SPDU\n", spdu_size);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if ((spdu == NULL) ||
      (params == NULL) ||
      (parsed == NULL)) {
    return -kDot2Result_SPDU_NullParameters;
  }
  int ret = dot2_CheckSPDUProcessParams(spdu_size, params);
  if (ret < 0) {
    return ret;
  }

  /*
   * 어플리케이션이 SPDU 수신시각을 전달하지 않았으면, 직접 계산한다.
   */
  if (params->rx_time == 0) {
    params->rx_time = dot2_GetCurrentTime64();
  }

  /*
   * SPDU를 처리한다.
   */
  return dot2_ProcessSPDU(spdu, spdu_size, params, parsed);
}


/**
 * @brief Dot2_ProcessSPDU() API 호출을 통해 요청했던 SPDU 처리 결과를 전달받을 콜백함수를 등록한다.
 *        (상세 내용 API 매뉴얼 참조)
 * @param[in] callback 콜백함수 포인터
 */
void OPEN_API Dot2_RegisterProcessSPDUCallback(ProcessSPDUCallback callback)
{
  g_dot2_mib.spdu_process.cb = callback;
}
