/**
 * @file
 * @brief TCI16094 메시지를 처리하는 기능을 구현한 파일
 * @date 2019-09-25
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
 * @brief 1609.4 SetInitialState 메시지를 처리한다.
 * @param[in] data SetInitialState 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094SetInitialState(bool data)
{
  return TCIA2023_ProcessSetInitialState(data);
}


/**
 * @brief 1609.4 SetWsmTxInfo 메시지를 처리한다.
 * @param[in] data SetWsmTxInfo 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094SetWsmTxInfo(const struct Cvcoctci2023SetWsmTxInfo *data)
{
  return TCIA2023_ProcessSetWsmTxInfo(data);
}


/**
 * @brief 1609.4 StartWsmTx 메시지를 처리한다.
 * @param[in] data StartWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @param[in] pdu TS 가 전송한 PDU
 * @param[in] pdu_size pdu 의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StartWsmTx(const struct Cvcoctci2023StartWsmTx *data, const uint8_t *pdu, size_t pdu_size)
{
  return TCIA2023_ProcessStartWsmTx(data, pdu, pdu_size);
}


/**
 * @brief 1609.4 StopWsmTx 메시지를 처리한다.
 * @param[in] params StopWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StopWsmTx(const struct Cvcoctci2023StopWsmTx *data)
{
  return TCIA2023_ProcessStopWsmTx(data);
}


/**
 * @brief 1609.4 StartWsmRx 메시지를 처리한다.
 * @param[in] data StartWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StartWsmRx(const struct Cvcoctci2023StartWsmRx *data)
{
  return TCIA2023_ProcessStartWsmRx(data);

}


/**
 * @brief 1609.4 StopWsmRx 메시지를 처리한다.
 * @param[in] params StopWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StopWsmRx(const struct Cvcoctci2023StopWsmRx *data)
{
  return TCIA2023_ProcessStopWsmRx(data);
}


/**
 * @brief 1609.4 AddTxProfile 메시지를 처리한다.
 * @param[in] params AddTxProfile 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094AddTxProfile(const struct Cvcoctci2023AddTxProfile *data)
{
  Log(kTCIA3LogLevel_Event, "Process 16094 AddTxProfile\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintAddTxProfile(data);
  }

#if defined(_TCIA2023_DSRC_)
  int ret;

  /*
   * 채널에 접속한다.
   */
  Dot3TimeSlot timeslot = data->timeslot - 1;
  if (timeslot == kDot3TimeSlot_0) {
    ret = TCIA2023_DSRC_AccessChannel(data->radio.radio, data->chan_id, kDot3ChannelNumber_CCH);
  } else if (timeslot == kDot3TimeSlot_1) {
    ret = TCIA2023_DSRC_AccessChannel(data->radio.radio, kDot3ChannelNumber_CCH, data->chan_id);
  } else {
    Err("Fail to process 16094 AddTxProfile - invalid timeslot %d\n", data->timeslot);
    return -1;
  }
  if (ret < 0) {
    return -1;
  }
  g_tcia_mib.wsm_trx_info[timeslot].chan_num = data->chan_id;

  /*
   * Tx Profile을 등록한다.
   */
  struct WalTxProfile tx_profile;
  tx_profile.chan_num = data->chan_id;
  tx_profile.datarate = data->datarate;
  tx_profile.power = data->transmit_power_level;
  tx_profile.priority = 0;
  ret = WAL_RegisterTxProfile(data->radio.radio, &tx_profile);
  if (ret < 0) {
    Err("Fail to process 16094 AddTxProfile - WAL_RegisterTxProfile() failed - %d\n", ret);
    return -1;
  }
#endif

  Log(kTCIA3LogLevel_Event, "Success to process 16094 AddTxProfile\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.4 DelTxProfile 메시지를 처리한다.
 * @param[in] params DelTxProfile 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094DelTxProfile(const struct Cvcoctci2023DelTxProfile *data)
{
  Log(kTCIA3LogLevel_Event, "Process 16094 DelTxProfile\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintDelTxProfile(data);
  }

#if defined(_TCIA2023_DSRC_)
  /*
   * Tx Profile을 제거한다.
   */
  int ret = WAL_DeleteTxProfile(data->radio.radio);
  if (ret < 0) {
    Err("Fail to process 16094 DelTxProfile - WAL_DeleteTxProfile() failed: %d\n", ret);
  } else {
    Log(kTCIA3LogLevel_Event, "Success to process 16094 DelTxProfile\n");
  }
#endif
  
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.4 StartIPv6Tx 메시지를 처리한다.
 * @param[in] params StartIPv6Tx 파싱정보가 저장된 정보구조체 포인터
 * @param[in] payload TS 가 전송한 payload
 * @param[in] payload_size payload_size 의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int
TCIA2023_Process16094StartIPv6Tx(const struct Cvcoctci2023StartIPv6Tx *data, const uint8_t *payload, size_t payload_size)
{
  Log(kTCIA3LogLevel_Event, "Process 16094 StartIPv6Tx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintIPv6TxRecord(data);
  }

  /*
   * IP 전송 동작을 시작한다.
   */
  int ret = TCIA2023_StartIPv6TxOperation(data, payload, payload_size);
  if (ret < 0) {
    Err("Fail to process 16094 StartIPV6Tx\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16094 StartIPv6Tx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.4 StopIPv6Tx 메시지를 처리한다.
 * @param[in] params StopIPv6Tx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StopIPv6Tx(const struct Cvcoctci2023StopIPv6Tx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 16094 StopIPv6Tx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintIPv6TxRecord(data);
  }

  /*
   * IP 전송 동작을 중지한다.
   */
  int ret = TCIA2023_StopIPv6TxOperation(data);
  if (ret < 0) {
    Err("Fail to process 16094 StopIPV6Tx\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16094 StopIPv6Tx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.4 StartIPv6Rx 메시지를 처리한다.
 * @param[in] params StartIPv6Rx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StartIPv6Rx(const struct Cvcoctci2023StartIPv6Rx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 16094 StartIPv6Rx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintIPv6RxRecord(data);
  }

  /*
   * IP 전송 동작을 시작한다.
   */
  int ret = TCIA2023_StartIPv6RxOperation(data);
  if (ret < 0) {
    Err("Fail to process 16094 StartIPv6Rx\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16094 StartIPv6Rx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.4 StopIPv6Rx 메시지를 처리한다.
 * @param[in] params StopIPv6Rx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16094StopIPv6Rx(const struct Cvcoctci2023StopIPv6Rx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 16094 StopIPv6Rx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintIPv6RxRecord(data);
  }

  /*
   * IP 전송 동작을 중지한다.
   */
  int ret = TCIA2023_StopIPv6RxOperation(data);
  if (ret < 0) {
    Err("Fail to process 16094 StopIPv6Rx\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16094 StopIPv6Rx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.4 TCI Request 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @param[in] pdu TCI 메시지 내에 수납되어 있는 pdu (수납되어 있지 않은 경우 NULL)
 * @param[in] pdu_size pdu 의 크기
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_Process16094TCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size)
{
  Log(kTCIA3LogLevel_Event, "Process received TCI16094 message\n");

  int ret = kTCIA3ResponseMsgType_Response;
  switch (parse_params->u.request.req_type)
  {
    case kCvcoctci2023RequestType_SetInitialState:
      ret = TCIA2023_Process16094SetInitialState(parse_params->u.request.u.set_initial_state);
      break;

    case kCvcoctci2023RequestType_SetWsmTxInfo:
      ret = TCIA2023_Process16094SetWsmTxInfo(&(parse_params->u.request.u.set_wsm_tx_info));
      break;

    case kCvcoctci2023RequestType_StartWsmTx:
      ret = TCIA2023_Process16094StartWsmTx(&(parse_params->u.request.u.start_wsm_tx), pdu, pdu_size);
      break;

    case kCvcoctci2023RequestType_StopWsmTx:
      ret = TCIA2023_Process16094StopWsmTx(&(parse_params->u.request.u.stop_wsm_tx));
      break;

    case kCvcoctci2023RequestType_StartWsmRx:
      ret = TCIA2023_Process16094StartWsmRx(&(parse_params->u.request.u.start_wsm_rx));
      break;

    case kCvcoctci2023RequestType_StopWsmRx:
      ret = TCIA2023_Process16094StopWsmRx(&(parse_params->u.request.u.stop_wsm_rx));
      break;

    case kCvcoctci2023RequestType_AddTxProfile:
      ret = TCIA2023_Process16094AddTxProfile(&(parse_params->u.request.u.add_txprofile));
      break;

    case kCvcoctci2023RequestType_DelTxProfile:
      ret = TCIA2023_Process16094DelTxProfile(&(parse_params->u.request.u.del_txprofile));
      break;

    case kCvcoctci2023RequestType_StartIPv6Tx:
      ret = TCIA2023_Process16094StartIPv6Tx(&(parse_params->u.request.u.start_ipv6_tx), pdu, pdu_size);
      break;

    case kCvcoctci2023RequestType_StopIPv6Tx:
      ret = TCIA2023_Process16094StopIPv6Tx(&(parse_params->u.request.u.stop_ipv6_tx));
      break;

    case kCvcoctci2023RequestType_StartIPv6Rx:
      ret = TCIA2023_Process16094StartIPv6Rx(&(parse_params->u.request.u.start_ipv6_rx));
      break;

    case kCvcoctci2023RequestType_StopIPv6Rx:
      ret = TCIA2023_Process16094StopIPv6Rx(&(parse_params->u.request.u.stop_ipv6_rx));
      break;

    default:
      Err("Fail to process TCI16094 message - invalid request type %d\n", parse_params->u.request.req_type);
      ret = -1;
      break;
  }

  return ret;
}

