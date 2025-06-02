/**
 * @file
 * @brief TCI80211 메시지를 처리하는 기능을 구현한 파일
 * @date 2019-09-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 802.11 SetInitialState 메시지를 처리한다.
 * @param[in] data SetInitialState 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process80211SetInitialState(bool data)
{
  return TCIA2023_ProcessSetInitialState(data);
}


/**
 * @brief 802.11 SetWsmTxInfo 메시지를 처리한다.
 * @param[in] params SetWsmTxInfo 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process80211SetWsmTxInfo(const struct Cvcoctci2023SetWsmTxInfo *data)
{
  return TCIA2023_ProcessSetWsmTxInfo(data);
}


/**
 * @brief 802.11 StartWsmTx 메시지를 처리한다.
 * @param[in] data StartWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @param[in] pdu TS가 전송한 PDU
 * @param[in] pdu_size pdu의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process80211StartWsmTx(const struct Cvcoctci2023StartWsmTx *data, const uint8_t *pdu, size_t pdu_size)
{
#if 1
  /*
   * TODO::
   * 2022.10.11 현재 802.11 Keysight TS는 항상 17바이트 길이의 PDU를 전송하라고 명령을 주지만,
   * 시험 규격상, 400바이트가 사용되어야 한다 (17바이트로는 정확한 테스트 결과를 얻을 수 없다)
   * 따라서, 해당 장비가 교정되기 전까지는, 802.11 시험에서는 TS의 명령과 무관하게 무조건 400바이트 PDU를 전송하도록 한다.
   */
  uint8_t new_pdu[400];
  memcpy(new_pdu, pdu, pdu_size > sizeof(new_pdu) ? sizeof(new_pdu) : pdu_size);
  return TCIA2023_ProcessStartWsmTx(data, new_pdu, sizeof(new_pdu));
#else
  return TCIA2023_ProcessStartWsmTx(data, pdu, pdu_size);
#endif
}


/**
 * @brief 802.11 StopWsmTx 메시지를 처리한다.
 * @param[in] data StopWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process80211StopWsmTx(const struct Cvcoctci2023StopWsmTx *data)
{
  return TCIA2023_ProcessStopWsmTx(data);
}


/**
 * @brief 802.11 StartWsmRx 메시지를 처리한다.
 * @param[in] data StartWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSM 수신을 시작한다.
 */
static int TCIA2023_Process80211StartWsmRx(const struct Cvcoctci2023StartWsmRx *data)
{
  return TCIA2023_ProcessStartWsmRx(data);
}


/**
 * @brief 802.11 StopWsmRx 메시지를 처리한다.
 * @param[in] data StopWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process80211StopWsmRx(const struct Cvcoctci2023StopWsmRx *data)
{
  return TCIA2023_ProcessStopWsmRx(data);
}


/**
 * @brief 802.11 TCI Request 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @param[in] pdu TCI 메시지 내에 수납되어 있는 pdu (수납되어 있지 않은 경우 NULL)
 * @param[in] pdu_size pdu 의 크기
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_Process80211TCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size)
{
  Log(kTCIA3LogLevel_Event, "Process received TCI80211 message\n");

  int ret = kTCIA3ResponseMsgType_Response;
  switch (parse_params->u.request.req_type) {
    case kCvcoctci2023RequestType_SetInitialState:
      ret = TCIA2023_Process80211SetInitialState(parse_params->u.request.u.set_initial_state);
      break;
    case kCvcoctci2023RequestType_SetWsmTxInfo:
      ret = TCIA2023_Process80211SetWsmTxInfo(&(parse_params->u.request.u.set_wsm_tx_info));
      break;
    case kCvcoctci2023RequestType_StartWsmTx:
      ret = TCIA2023_Process80211StartWsmTx(&(parse_params->u.request.u.start_wsm_tx), pdu, pdu_size);
      break;
    case kCvcoctci2023RequestType_StopWsmTx:
      ret = TCIA2023_Process80211StopWsmTx(&(parse_params->u.request.u.stop_wsm_tx));
      break;
    case kCvcoctci2023RequestType_StartWsmRx:
      ret = TCIA2023_Process80211StartWsmRx(&(parse_params->u.request.u.start_wsm_rx));
      break;
    case kCvcoctci2023RequestType_StopWsmRx:
      ret = TCIA2023_Process80211StopWsmRx(&(parse_params->u.request.u.stop_wsm_rx));
      break;
    default:
      Err("Fail to process TCI80211 message - invalid request type %d\n", parse_params->u.request.req_type);
      ret = -1;
      break;
  }

  return ret;
}
