/**
 * @file
 * @brief TCI 메시지를 처리하는 기능을 구현 파일
 * @date 2019-09-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>
#include <time.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#include "j29451/j29451.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 수신된 TCI 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @param[in] pdu TCI 메시지 내에 수납되어 있는 pdu (수납되어 있지 않은 경우 NULL)
 * @param[in] pdu_size pdu 의 크기
 * @param[out] radio_idx Request 메시지가 GetIPv6InterfaceInfo일 경우, 요청된 인터페이스 식별번호가 저장될 변수 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessTCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size, Cvcoctci2023Radio *radio_idx)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Process received TCI message - pdu_size : %u\n", pdu_size);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, pdu, pdu_size);

  /*
   * TCI 프레임 유형 별로 처리한다.
   */
  int ret;
  switch (parse_params->frame_type) {
    case kCvcoctci2023FrameType_16093Dsrc:
      ret = TCIA2023_Process16093DSRCTCIMessage(parse_params, pdu, pdu_size, radio_idx);
      break;
    case kCvcoctci2023FrameType_16093Cv2x:
      ret = TCIA2023_Process16093PC5TCIMessage(parse_params, pdu, pdu_size, radio_idx);
      break;
    case kCvcoctci2023FrameType_80211:
      ret = TCIA2023_Process80211TCIMessage(parse_params, pdu, pdu_size);
      break;
    case kCvcoctci2023FrameType_16094:
      ret = TCIA2023_Process16094TCIMessage(parse_params, pdu, pdu_size);
      break;
    case kCvcoctci2023FrameType_29451:
      ret = TCIA2023_Process29451TCIMessage(parse_params);
      break;
    case kCvcoctci2023FrameType_31611:
      ret = TCIA2023_Process31611TCIMessage(parse_params);
      break;
    case kCvcoctci2023FrameType_SutControl:
      ret = TCIA2023_ProcessSutControlTCIMessage(parse_params);
      break;
    default:
      Err("Fail to process TCI message - invalid frame type %d\n", parse_params->frame_type);
      return -1;
  }

  return ret;
}


/**
 * @brief SetInitialState 메시지를 처리한다.
 * @param[in] data SetInitialState 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetInitialState(bool data)
{
  Log(kTCIA3LogLevel_Event, "Process SetInitialState\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetInitialState(data);
  }

  /*
  * SetInitialState TCI 메시지를 수신하면 시간 동기화 어플리케이션을 재실행한다.
  */
//  system("systemctl restart chronyd");
  system("systemctl restart chrony");
//  system("systemctl restart ntpd");

  /*
   * DUT 를 초기 상태로 설정한다.
   */
  TCIA2023_InitDUTState();

#if defined(_LTEV2X_HAL_)
  // 송신 플로우 정보를 초기화한다.
  TCIA2023_InitTxFlowInfo();
#endif

  g_tcia_mib.user_gnss_data.use = false;

  Log(kTCIA3LogLevel_Event, "Success to process 16093 SetInitialState\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief EnableGpsInput 메시지를 처리한다.
 * @param[in] data EnableGpsInput 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessEnableGpsInput(bool data)
{
  int ret;

  Log(kTCIA3LogLevel_Event, "Process EnableGpsInput\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintEnableGpsInput(data);
  }

  if (data == false) {
    J29451_EnableUserGNSSData();
    g_tcia_mib.user_gnss_data.use = true;

    // latitude, longitude, elevation 기본값 설정
    ret = J29451_SetUserGNSSLatitude(DEFAULT_INIT_LAT);
    if (ret < 0) {
      Err("Fail to set user gnss latitude - J29451_SetUserGNSSLatitude() failed: %d\n", ret);
      return -1;
    }

    ret = J29451_SetUserGNSSLongitude(DEFAULT_INIT_LON);
    if (ret < 0) {
      Err("Fail to set user gnss longitude - J29451_SetUserGNSSLongitude() failed: %d\n", ret);
      return -1;
    }

    ret = J29451_SetUserGNSSElevation(DEFAULT_INIT_ELEV);
    if (ret < 0) {
      Err("Fail to set user gnss elevation - J29451_SetUserGNSSElevation() failed: %d\n", ret);
      return -1;
    }

    ret = J29451_SetUserGNSSSpeed(kJ29451Speed_Min);
    if (ret < 0) {
      Err("Fail to set user gnss speed - J29451_SetUserGNSSSpeed() failed: %d\n", ret);
      return -1;
    }

    ret = J29451_SetUserGNSSHeading(kJ29451Heading_Min);
    if (ret < 0) {
      Err("Fail to set user gnss heading - J29451_SetUserGNSSHeading() failed: %d\n", ret);
      return -1;
    }

    ret = J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Min, kJ29451SemiMinorAxisAccuracy_Min, kJ29451SemiMajorAxisOrientation_Min);
    if (ret < 0) {
      Err("Fail to set user gnss position accuracy - J29451_SetUserGNSSPositionalAccuracy() failed: %d\n", ret);
      return -1;
    }

    J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Min, kJ29451Acceleration_Min, kJ29451VerticalAcceleration_Min, kJ29451YawRate_Min);

    g_tcia_mib.user_gnss_data.lat = DEFAULT_INIT_LAT;
    g_tcia_mib.user_gnss_data.lon = DEFAULT_INIT_LON;
    g_tcia_mib.user_gnss_data.elev = DEFAULT_INIT_ELEV;
    g_tcia_mib.user_gnss_data.heading = kJ29451Heading_Min;
    g_tcia_mib.user_gnss_data.speed = kJ29451Speed_Min;
    g_tcia_mib.user_gnss_data.pos_accuracy.semi_major = kJ29451SemiMajorAxisAccuracy_Min;
    g_tcia_mib.user_gnss_data.pos_accuracy.semi_minor = kJ29451SemiMinorAxisAccuracy_Min;
    g_tcia_mib.user_gnss_data.pos_accuracy.orientation = kJ29451SemiMajorAxisOrientation_Min;
    g_tcia_mib.user_gnss_data.acceleration_set.lat = kJ29451Acceleration_Min;
    g_tcia_mib.user_gnss_data.acceleration_set.lon = kJ29451Acceleration_Min;
    g_tcia_mib.user_gnss_data.acceleration_set.vert = kJ29451VerticalAcceleration_Min;
    g_tcia_mib.user_gnss_data.acceleration_set.yaw = kJ29451YawRate_Min;
  }
  else {
    J29451_DisableUserGNSSData();
    g_tcia_mib.user_gnss_data.use = false;
  }

  Log(kTCIA3LogLevel_Event, "Success to process EnableGpsInput\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetLatitude 메시지를 처리한다.
 * @param[in] data SetLatitude 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetLatitude(Cvcoctci2023SetLatitude data)
{
  Log(kTCIA3LogLevel_Event, "Process SetLatitude\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetLatitude(data);
  }

  // 위도값을 설정한다.
  int ret = J29451_SetUserGNSSLatitude(data);
  if (ret < 0) {
    Err("Fail to process SetLatitude - J29451_SetUserGNSSLatitude() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.user_gnss_data.lat = data;

  Log(kTCIA3LogLevel_Event, "Success to process SetLatitude\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetLongitude 메시지를 처리한다.
 * @param[in] data SetLongitude 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetLongitude(Cvcoctci2023SetLongitude data)
{
  Log(kTCIA3LogLevel_Event, "Process SetLongitude\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetLongitude(data);
  }

  // 경도 값을 설정한다.
  int ret = J29451_SetUserGNSSLongitude(data);
  if (ret < 0) {
    Err("Fail to process SetLongitude - J29451_SetUserGNSSLongitude() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.user_gnss_data.lon = data;

  Log(kTCIA3LogLevel_Event, "Success to process SetLongitude\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetElevation 메시지를 처리한다.
 * @param[in] data SetElevation 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetElevation(Cvcoctci2023SetElevation data)
{
  Log(kTCIA3LogLevel_Event, "Process SetElevation\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetElevation(data);
  }

  // 고도 값을 설정한다.
  int ret = J29451_SetUserGNSSElevation(data);
  if (ret < 0) {
    Err("Fail to process SetElevation - J29451_SetUserGNSSElevation() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.user_gnss_data.elev = data;

  Log(kTCIA3LogLevel_Event, "Success to process SetElevation\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetPositionalAccuracy 메시지를 처리한다.
 * @param[in] data SetPositionalAccuracy 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetPositionalAccuracy(const struct Cvcoctci2023SetPositionalAccuracy *data)
{
  Log(kTCIA3LogLevel_Event, "Process SetPositionalAccuracy\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetPositionalAccuracy(data);
  }

  // 좌표 정확도 값을 설정한다.
  int ret = J29451_SetUserGNSSPositionalAccuracy(data->semi_major_axis_accuracy, data->semi_minor_axis_accuracy, data->semi_major_axis_orientation);
  if (ret < 0) {
    Err("Fail to process SetPositionalAccuracy - J29451_SetUserGNSSPositionalAccuracy() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.user_gnss_data.pos_accuracy.semi_major = data->semi_major_axis_accuracy;
  g_tcia_mib.user_gnss_data.pos_accuracy.semi_minor = data->semi_minor_axis_accuracy;
  g_tcia_mib.user_gnss_data.pos_accuracy.orientation = data->semi_major_axis_orientation;

  Log(kTCIA3LogLevel_Event, "Success to process SetPositionalAccuracy\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetSpeed 메시지를 처리한다.
 * @param[in] data SetPositionalAccuracy 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetSpeed(Cvcoctci2023SetSpeed data)
{
  Log(kTCIA3LogLevel_Event, "Process SetSpeed\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetSpeed(data);
  }

  // 속도 값을 설정한다.
  int ret = J29451_SetUserGNSSSpeed(data);
  if (ret < 0) {
    Err("Fail to process SetSpeed - J29451_SetUserGNSSSpeed() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.user_gnss_data.speed = data;

  Log(kTCIA3LogLevel_Event, "Success to process SetSpeed\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetHeading 메시지를 처리한다.
 * @param[in] data SetHeading 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetHeading(Cvcoctci2023SetHeading data)
{
  Log(kTCIA3LogLevel_Event, "Process SetHeading\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetHeading(data);
  }

  // 헤딩 값을 설정한다.
  int ret = J29451_SetUserGNSSHeading(data);
  if (ret < 0) {
    Err("Fail to process SetHeading - J29451_SetUserGNSSHeading() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.user_gnss_data.heading = data;

  Log(kTCIA3LogLevel_Event, "Success to process SetHeading\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetAccelerationSet4Way 메시지를 처리한다.
 * @param[in] data SetAccelerationSet4Way 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetAccelerationSet4Way(const struct Cvcoctci2023SetAccelerationSet4Way *data)
{
  Log(kTCIA3LogLevel_Event, "Process SetAccelerationSet4Way\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetAccelerationSet4Way(data);
  }

  // AccelerationSet4Way 값을 설정한다.
  J29451_SetUserGNSSAccelerationSet4Way(data->longitude, data->latitude, data->vertical, data->yaw_rate);

  g_tcia_mib.user_gnss_data.acceleration_set.lon = data->longitude;
  g_tcia_mib.user_gnss_data.acceleration_set.lat = data->latitude;
  g_tcia_mib.user_gnss_data.acceleration_set.vert = data->vertical;
  g_tcia_mib.user_gnss_data.acceleration_set.yaw = data->yaw_rate;

  Log(kTCIA3LogLevel_Event, "Success to process SetAccelerationSet4Way\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SetGpsTime 메시지를 처리한다.
 * @param[in] data SetGpsTime 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetGpsTime(Cvcoctci2023SetGpsTime data)
{
  Log(kTCIA3LogLevel_Event, "Process SutControl SetGpsTime\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetGpsTime(data);
  }

  /*
   * SetGpsTime TCI 메시지를 수신하면 실행 중인 시간동기화 어플리케이션을 종료한다.
   */
//  system("systemctl stop chronyd");
  system("systemctl stop chrony");
//  system("systemctl stop ntpd");

  // 시간을 강제로 변경한다.
  struct timespec ts;
  ts.tv_sec = (time_t) (data / 1000);
  ts.tv_nsec = (long) ((data % 1000) * 1000000);
  clock_settime(CLOCK_REALTIME, &ts);

  /*
   * j29451 라이브러리의 Path 정보를 초기화한다.
   *  - 본 명령에 의해 시간이 변경되면, Path 정보 생성 메커니즘이 오동작하므로 Path 정보를 초기화해 준다.
   *  - 본 명령이 발생할 경우는, DUT의 동작이 시간 상 연속성을 가지지 않는 경우이므로,
   *    과거 정보와 연속성을 갖는 Path 정보는 초기화하여 새롭게 생성되도록 한다.
   */
  J29451_InitPathInfo();

  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    struct tm tm_now;
    localtime_r((time_t *) &ts.tv_sec, &tm_now);
    Log(kTCIA3LogLevel_Event, "Set system time - %04u-%02u-%02u %02u:%02u:%02u.%06ld\n",
        tm_now.tm_year + 1900,
        tm_now.tm_mon + 1, tm_now.tm_mday, tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);
  }

  Log(kTCIA3LogLevel_Event, "Success to process SutControl SetGpsTime\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * flowIdentifier is added(OPTIONAL)
 * transmitPowerLevel, userPriority, channelIdentifier, dataRate and timeslot changed to OPTIONAL
 * 
 * @brief SetWsmTxInfo 메시지를 처리한다.
 * @param[in] data SetWsmTxInfo 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSetWsmTxInfo(const struct Cvcoctci2023SetWsmTxInfo *data)
{
  Log(kTCIA3LogLevel_Event, "Process SetWsmTxInfo\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetWsmTxInfo(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio) (g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process SetWsmTxInfo - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * 시간슬롯 값 유효성 체크
   */
#if defined(_TCIA2023_DSRC_)
  Cvcoctci2023TimeSlot timeslot = data->timeslot;
  if ((timeslot < kCvcoctci2023TimeSlot_Min) || (timeslot > kCvcoctci2023TimeSlot_Max)) {
    Err("Fail to process SetWsmTxInfo - invalid timeslot %d\n", timeslot);
    return -1;
  }
  Dot3TimeSlot local_timeslot = timeslot - 1; // V2X 스택에서의 TimeSlot 은 0부터 시작하고, TCI 에서는 1부터 시작한다.
#endif
#if defined(_TCIA2023_LTE_V2X_)
  Dot3TimeSlot local_timeslot = 0; // LTE-V2X는 0으로 고정한다.
#endif

  /*
   * 시간슬롯별 WSM 송신정보를 업데이트한다.
   */
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[local_timeslot]);
  wsm_tx_info->if_idx = data->radio.radio;
  wsm_tx_info->psid = data->psid;
  wsm_tx_info->sec_info.content_type = data->security.content_type;
  wsm_tx_info->sec_info.signer_id_type = data->security.signer_id_type;
#if defined(_TCIA2023_LTE_V2X_)
  if (data->info_elements_included.chan_num) {
    wsm_tx_info->chan_num_ext = true;
  }
  if (data->info_elements_included.datarate) {
    wsm_tx_info->datarate_ext = true;
  }
  if (data->info_elements_included.transmit_power_used) {
    wsm_tx_info->txpower_ext = true;
  }

  if (data->options.chan_id == true) {
    wsm_tx_info->chan_num = data->chan_id;
  }
  if (data->options.datarate == true) {
    wsm_tx_info->datarate = data->datarate;
  }
  if (data->options.transmit_power_level == true) {
    wsm_tx_info->tx_power = data->transmit_power_level;
  }

  if (data->options.flow_id) {
    wsm_tx_info->flow_id = data->flow_id;
  }
  if (data->options.repeat_rate) {
    wsm_tx_info->repeat_rate = data->repeat_rate;
  } else {
    wsm_tx_info->repeat_rate = kCvcoctci2023RepeatRate_NA;
  }
  if (data->options.dst_mac_addr == true) {
    memcpy(wsm_tx_info->dst_mac_addr, data->dst_mac_addr, MAC_ALEN);
  } else {
    memset(wsm_tx_info->dst_mac_addr, 0xff, MAC_ALEN);
  }
#endif
#if defined(_TCIA2023_DSRC_)
  if (data->options.chan_id) {
    wsm_tx_info->chan_num = data->chan_id;
  }
  else {
    wsm_tx_info->chan_num = kCvcoctci2023ChannelNumber_NA;
  }
  if (data->options.timeslot) {
    wsm_tx_info->timeslot = local_timeslot;
  }
  else {
    wsm_tx_info->timeslot = kCvcoctci2023TimeSlot_NA;
  }
  if (data->options.datarate) { 
    wsm_tx_info->datarate = data->datarate;
  }
  else {
    wsm_tx_info->datarate = kCvcoctci2023DataRate_NA;
  }
  if (data->options.transmit_power_level) {
    wsm_tx_info->tx_power = data->transmit_power_level;
  }
  else {
    wsm_tx_info->tx_power = kCvcoctci2023TxPower_NA;
  }
  if (data->options.user_priority) {
    wsm_tx_info->priority = data->user_priority;
  }
  else {
    wsm_tx_info->priority = kCvcoctci2023UserPriority_NA;
  }

  if (data->options.dst_mac_addr == true) {
    memcpy(wsm_tx_info->dst_mac_addr, data->dst_mac_addr, MAC_ALEN);
  } else {
    memset(wsm_tx_info->dst_mac_addr, 0xff, MAC_ALEN);
  }
  if (data->options.repeat_rate) {
    wsm_tx_info->repeat_rate = data->repeat_rate;
  }
  else {
    wsm_tx_info->repeat_rate = kCvcoctci2023RepeatRate_NA;
  }
  if (data->info_elements_included.chan_num) {
    wsm_tx_info->chan_num_ext = true;
  }
  if (data->info_elements_included.datarate) {
    wsm_tx_info->datarate_ext = true;
  }
  if (data->info_elements_included.transmit_power_used) {
    wsm_tx_info->txpower_ext = true;
  }
  if (data->options.flow_id) {
    wsm_tx_info->flow_id = data->flow_id;
  }
  else {
    wsm_tx_info->flow_id = kCvcoctci2023FlowIdentifier_NA;
  }
#endif

  Log(kTCIA3LogLevel_Event, "Success to process SetWsmTxInfo for timeslot %d\n", local_timeslot);
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief StartWsmTx 메시지를 처리한다.
 * @param[in] data StartWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @param[in] pdu TS 가 전송한 PDU
 * @param[in] pdu_size pdu 의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessStartWsmTx(const struct Cvcoctci2023StartWsmTx *data, const uint8_t *pdu, size_t pdu_size)
{
  int ret;
  Log(kTCIA3LogLevel_Event, "Process StartWsmTx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStartWsmTx(data, pdu, pdu_size);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio) (g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process StartWsmTx - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * PSID에 해당되는 시간슬롯 확인
   */
  Cvcoctci2023TimeSlot timeslot;
  if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[0].psid)) {
    timeslot = kCvcoctci2023TimeSlot_AltSlot0;
  } else if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[1].psid)) {
    timeslot = kCvcoctci2023TimeSlot_AltSlot1;
  } else if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[2].psid)) {
    timeslot = kCvcoctci2023TimeSlot_Continuous;
  } else {
    Err("Fail to process StartWsmTx - cannot find timeslot for psid %d\n", data->psid);
    return -1;
  }
  Dot3TimeSlot local_timeslot = timeslot - 1; // 스택에서의 TimeSlot 은 0부터 시작하고, TCI 에서는 1부터 시작한다.

  /*
   * 이미 전송 중이면 실패를 반환한다.
   */
  if (g_tcia_mib.wsm_trx_info[local_timeslot].txing) {
    Err("Fail to process StartWsmTx - already WSM sending on timeslot %d\n", local_timeslot);
    return -1;
  }

  /*
   * WSM 전송 파라미터 정보를 업데이트한다.
   */
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[local_timeslot]);
  wsm_tx_info->if_idx = data->radio.radio;

  /**
   * Update TCIv3 by young@KETI
   * repeat_rate change to OPTIONAL
   * */
  if (true == data->options.repeat_rate) {
    wsm_tx_info->repeat_rate = data->repeat_rate;
  } else {
    wsm_tx_info->repeat_rate = kCvcoctci2023RepeatRate_NA;
  }

  wsm_tx_info->psid = data->psid;
  if (pdu && (pdu_size > 0)) {
    memcpy(wsm_tx_info->pdu, pdu, pdu_size);
    wsm_tx_info->pdu_size = pdu_size;
  } else {
    wsm_tx_info->pdu_size = 0;
  }

#if defined(_TCIA2023_DSRC_)
  /*
   * 채널에 접속한다.
   *  - Continuous 에 대한 StartWsmTx 이면, g_mib.wsm_tx_info[2]에 지정된 채널로 Continuous 접속한다.
   *  - TimeSlot0 또는 TimeSlot1 에 대한 StartWsmTx 이면, g_mib.wsm_tx_info[0]과 [1]에 지정된 채널로 Alternating 접속한다.
   */
  int ts0_chan_num = g_tcia_mib.wsm_trx_info[0].chan_num;
  int ts1_chan_num = g_tcia_mib.wsm_trx_info[1].chan_num;
  if (local_timeslot == kDot3TimeSlot_Continuous) {
    ts0_chan_num = ts1_chan_num = g_tcia_mib.wsm_trx_info[2].chan_num;
    if (ts0_chan_num == kDot3ChannelNumber_NA) { // SetWsmTxInfo에 의해 설정되어 있어야 한다.
      Err("Fail to process StartWsmTx - continuous channel(%d) is not set\n", ts0_chan_num);
      return -1;
    }
  } else {
    if ((ts0_chan_num == kDot3ChannelNumber_NA) || (ts1_chan_num == kDot3ChannelNumber_NA)) {
      Err("Fail to process StartWsmTx - ts0_chan_num(%d) or ts1_chan_num(%d) is not set\n", // SetWsmTxInfo에 의해 설정되어 있어야 한다.
          ts0_chan_num, ts1_chan_num);
      return -1;
    }
  }
  ret = TCIA2023_DSRC_AccessChannel(wsm_tx_info->if_idx, ts0_chan_num, ts1_chan_num);
  if (ret < 0) {
    return ret;
  }
#endif

  /*
   * WSM 전송을 시작한다.
   */
  ret = TCIA2023_StartWSMTransmit(local_timeslot);
  if (ret < 0) {
    return ret;
  }

  Log(kTCIA3LogLevel_Event, "Success to process StartWsmTx on timeslot %d\n", local_timeslot);
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief Pc5StartWsmTx 메시지를 처리한다.
 * @param[in] data Pc5StartWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @param[in] pdu TS 가 전송한 PDU
 * @param[in] pdu_size pdu 의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessPc5StartWsmTx(const struct Cvcoctci2023Pc5StartWsmTx *data, const uint8_t *pdu, size_t pdu_size)
{
  int ret;
  Log(kTCIA3LogLevel_Event, "Process Pc5StartWsmTx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintPc5StartWsmTx(data, pdu, pdu_size);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio) (g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process StartWsmTx - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  Dot3TimeSlot local_timeslot = 0; // LTE-V2X에서는 timeslot을 0으로 한다.

  /*
   * 0이 이미 사용 중이라면 1로 설정하여 전송한다.
   */
  if (g_tcia_mib.wsm_trx_info[local_timeslot].txing) {
    Err("Fail to process StartWsmTx - already WSM sending on timeslot %d\n", local_timeslot);
    local_timeslot = 1;

    /*
     * 1번도 사용 중이라면 실패를 반환한다.
     */
    if (g_tcia_mib.wsm_trx_info[local_timeslot].txing) {
      Err("Fail to process StartWsmTx - already WSM sending on timeslot %d\n", local_timeslot);
      return -1;
    }
  }



  /*
   * WSM 전송 파라미터 정보를 업데이트한다.
   */
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[local_timeslot]);
  wsm_tx_info->if_idx = data->radio.radio;
  wsm_tx_info->packet_count = data->packet_count;
  wsm_tx_info->repeat_rate = data->repeat_interval;
  wsm_tx_info->psid = data->psid;
  wsm_tx_info->flow_id = data->flow_id;

  if (pdu && (pdu_size > 0)) {
    memcpy(wsm_tx_info->pdu, pdu, pdu_size);
    wsm_tx_info->pdu_size = pdu_size;
  } else {
    wsm_tx_info->pdu_size = 0;
  }

  /*
   * WSM 전송을 시작한다.
   */
  ret = TCIA2023_StartWSMTransmit(local_timeslot);
  if (ret < 0) {
    return ret;
  }

  Log(kTCIA3LogLevel_Event, "Success to process StartWsmTx on timeslot %d\n", local_timeslot);
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief StopWsmTx 메시지를 처리한다.
 * @param[in] params StopWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessStopWsmTx(const struct Cvcoctci2023StopWsmTx *data)
{
  Log(kTCIA3LogLevel_Event, "Process StopWsmTx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStopWsmTx(data);
  }

  /*
   * PSID 에 해당되는 시간슬롯 확인
   */
  Cvcoctci2023TimeSlot timeslot;
  if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[0].psid)) {
    timeslot = kCvcoctci2023TimeSlot_AltSlot0;
  } else if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[1].psid)) {
    timeslot = kCvcoctci2023TimeSlot_AltSlot1;
  } else if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[2].psid)) {
    timeslot = kCvcoctci2023TimeSlot_Continuous;
  } else {
    Err("Fail to process StartWsmTx - cannot find timeslot for psid %d\n", data->psid);
    return -1;
  }
  Dot3TimeSlot local_timeslot = timeslot - 1; // 스택에서의 TimeSlot 은 0부터 시작하고, TCI 에서는 1부터 시작한다.

  /*
   * WSM 전송을 중지한다.
   */
  TCIA2023_StopWSMTransmit(local_timeslot);

  Log(kTCIA3LogLevel_Event, "Success to process StopWsmTx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief StartWsmRx 메시지를 처리한다.
 * @param[in] data StartWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessStartWsmRx(const struct Cvcoctci2023StartWsmRx *data)
{
  Log(kTCIA3LogLevel_Event, "Process StartWsmRx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStartWsmRx(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio) (g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process StartWsmRx - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * 시간슬롯 값 유효성 체크
   */
#if defined(_TCIA2023_DSRC_)
  Cvcoctci2023TimeSlot timeslot = data->timeslot;
  if ((timeslot < kCvcoctci2023TimeSlot_Min) || (timeslot > kCvcoctci2023TimeSlot_Max)) {
    Err("Fail to process StartWsmRx - invalid timeslot %d\n", timeslot);
    return -1;
  }
  Dot3TimeSlot local_timeslot = timeslot - 1; // 스택에서의 TimeSlot 은 0부터 시작하고, TCI 에서는 1부터 시작한다.
#elif defined(_TCIA2023_LTE_V2X_)
  Dot3TimeSlot local_timeslot = kDot3TimeSlot_Continuous;
#endif

  /*
   * 시간슬롯별 WSM 수신 파라미터 정보를 업데이트한다.
   */
  struct TCIA3WSMTrxInfo *wsm_rx_info = &(g_tcia_mib.wsm_trx_info[local_timeslot]);
  if (data->options.psid) {
    wsm_rx_info->psid = data->psid;
  } else {
    wsm_rx_info->psid = kCvcoctci2023Psid_NA;
  }
  wsm_rx_info->if_idx = data->radio.radio;

  /**
   * Update TCIv3 bay young@KETI
   * chan_id(chan_num) and timeslot changed to OPTIONAL
   * dst_mac_addr, pdu_filter and ssp is added
   * */
  if (data->options.chan_id) {
    wsm_rx_info->chan_num = data->chan_id;
  } else {
    wsm_rx_info->chan_num = kCvcoctci2023ChannelNumber_NA;
  }

#if defined(_TCIA2023_DSRC_)
  if (data->options.timeslot) {
    wsm_rx_info->timeslot = local_timeslot;
  } else {
    wsm_rx_info->timeslot = kCvcoctci2023TimeSlot_NA;
  }
#elif defined(_TCIA2023_LTE_V2X_)
  wsm_rx_info->timeslot = local_timeslot;
#endif

  memcpy(&(wsm_rx_info->event_handling), &(data->event_handling), sizeof(struct Cvcoctci2023EventHandling));
  // BSM 수신하면, 서명검증결과를 TS로 indication 해야 한다. (스파이런트 TS가 그걸 원한다)
  // 그런데 스파이런트 장비에서는 BSM 수신 테스트 시에, event_params_choice 값을 ServiceAvailable 로 전송하며,
  // 그 결과 Indication 시에 ServiceParameters 로 Indication 된다.
  // 그래서, event_flag 가 verification_completed_with_result 인 경우에는 event_params_choice 를 Security 로 맞춰준다.
  if (wsm_rx_info->event_handling.event_flag.verification_completed_with_result == true) {
    wsm_rx_info->event_handling.event_params_choice = kCvcoctci2023EventParamsType_Security;
  }
  if (data->options.dst_mac_addr) {
    memcpy(wsm_rx_info->dst_mac_addr, data->dst_mac_addr, MAC_ALEN);
  } else {
    memset(wsm_rx_info->dst_mac_addr, 0xff, MAC_ALEN);
  }
  if (data->options.pdu_filter) {
    wsm_rx_info->pdu_filter_size = data->pdu_filter.len;
    memcpy(wsm_rx_info->pdu_filter, data->pdu_filter.buf, wsm_rx_info->pdu_filter_size);
  } else {
    wsm_rx_info->pdu_filter_size = 0;
  }
  if (data->options.ssp) {
    wsm_rx_info->ssp_size = data->ssp.len;
    memcpy(wsm_rx_info->ssp, data->ssp.buf, wsm_rx_info->ssp_size);
  } else {
    wsm_rx_info->ssp_size = 0;
  }


#if defined(_TCIA2023_DSRC_)
  /*
   * 채널에 접속한다.
   */
  Dot3ChannelNumber ts0_chan_num = g_tcia_mib.wsm_trx_info[0].chan_num;
  Dot3ChannelNumber ts1_chan_num = g_tcia_mib.wsm_trx_info[1].chan_num;
  if (local_timeslot == kDot3TimeSlot_Continuous) {
    ts0_chan_num = ts1_chan_num = g_tcia_mib.wsm_trx_info[2].chan_num;
    if (ts0_chan_num == kDot3ChannelNumber_NA) {
      Err("Fail to process 16093 StartWsmRx - continuous channel(%d) is not set\n", ts0_chan_num);
      return -1;
    }
  } else {
    // Alternating 접속의 경우, 반대편 TimeSlot의 채널이 설정되어 있지 않으면, 본 TimeSlot과 동일한 채널로 설정하여,
    // 일단 Continuous 접속이 수행되도록 한다.
    // 반대편 TimeSlot의 채널이 설정되어 있으면, 정상적으로 alternating 접속이 수행된다.
    if (ts0_chan_num == kDot3ChannelNumber_NA) {
      ts0_chan_num = ts1_chan_num;
    } else if (ts1_chan_num == kDot3ChannelNumber_NA) {
      ts1_chan_num = ts0_chan_num;
    }
  }
  int ret = TCIA2023_DSRC_AccessChannel(wsm_rx_info->if_idx, ts0_chan_num, ts1_chan_num);
  if (ret < 0) {
    return -1;
  }
#endif

  /*
   * WSM 수신을 시작한다.
   */
  TCIA2023_StartWSMReceive(local_timeslot);

  Log(kTCIA3LogLevel_Event, "Success to process StartWsmRx on timeslot %d\n", local_timeslot);
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief StopWsmRx 메시지를 처리한다.
 * @param[in] data StopWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessStopWsmRx(const struct Cvcoctci2023StopWsmRx *data)
{
  Log(kTCIA3LogLevel_Event, "Process StopWsmRx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStopWsmRx(data);
  }

  /*
   * PSID 에 해당되는 시간슬롯 확인
   */
  Cvcoctci2023TimeSlot timeslot;
  if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[0].psid)) {
    timeslot = kCvcoctci2023TimeSlot_AltSlot0;
  } else if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[1].psid)) {
    timeslot = kCvcoctci2023TimeSlot_AltSlot1;
  } else if (data->psid == (Cvcoctci2023Psid) (g_tcia_mib.wsm_trx_info[2].psid)) {
    timeslot = kCvcoctci2023TimeSlot_Continuous;
  } else {
    timeslot = kCvcoctci2023TimeSlot_Continuous;
//    Err("Fail to process StopWsmRx - cannot find timeslot(%d,%d,%d) for psid %d\n", g_tcia_mib.wsm_trx_info[0].psid, g_tcia_mib.wsm_trx_info[1].psid, g_tcia_mib.wsm_trx_info[2].psid, data->psid);
//    return -1;
  }
  Dot3TimeSlot local_timeslot = timeslot - 1; // 스택에서의 TimeSlot 은 0부터 시작하고, TCI 에서는 1부터 시작한다.

  TCIA2023_StopWSMReceive(local_timeslot);

  Log(kTCIA3LogLevel_Event, "Success to process StopWsmRx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Add SendUeConfigXML
 * 
 * @brief SendUeConfigXML 메시지를 처리한다.
 * @param[in] data SendUeConfigXML 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 * */
int TCIA2023_ProcessSendUeConfigXML(const struct Cvcoctci2023SendUeConfigXML *data)
{
  Log(kTCIA3LogLevel_Event, "Process SendUeConfigXML\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSendUeConfigXML(data);
  }

  /* 구현 */

  Log(kTCIA3LogLevel_Event, "Success to process SendUeConfigXML\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Add SetUeConfig
 * 
 * @brief SetUeConfig 메시지를 처리한다.
 * @param[in] data SetUeConfig 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 * */
int TCIA2023_ProcessSetUeConfig(const struct Cvcoctci2023SetUeConfig *data)
{
  Log(kTCIA3LogLevel_Event, "Process SetUeConfig\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetUeConfig(data);
  }

  /* 구현 */

  Log(kTCIA3LogLevel_Event, "Success to process SetUeConfig\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Add SetFlowConfig
 * 
 * @brief SetFlowConfig 메시지를 처리한다.
 * @param[in] data SetFlowConfigs 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 * */
int TCIA2023_ProcessSetFlowConfigs(const struct Cvcoctci2023SetFlowConfigs *data)
{
  Log(kTCIA3LogLevel_Event, "Process SetFlowConfig\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetFlowConfigs(data);
  }

  int ret;

  /* 구현 */
#if defined(_LTEV2X_HAL_)
  int periodicity[12] = {
          20,
          50,
          100,
          200,
          300,
          400,
          500,
          600,
          700,
          800,
          900,
          1000};

  // 비어있는 SPS가 있는지 확인
  int empty_index = -1;
  if (data->flow_config[0].flow_type == kCvcoctci2023FlowType_sps) {
    struct LTEV2XHALTxFlowParams temp;
    for (unsigned int i = 0; i < kLTEV2XHALTxFLowIndex_Max; i++) {
      memset(&temp, 0x00, sizeof(struct LTEV2XHALTxFlowParams));
      ret = LTEV2XHAL_RetrieveTransmitFlow(0, &temp);
      if (ret < 0) {
        Err("Fail to retrieve transmit flow - LTEV2XHAL_RetrieveTransmitFlow() failed: %d\n", ret);
        return -1;
      }

      if (temp.interval == kLTEV2XHALTxFLowInterval_None && temp.size == kLTEV2XHALMSDUSize_None && temp.priority == kLTEV2XHALPriority_None) {
        empty_index = (int) i;
        break;
      }
      else if (temp.index == data->flow_config[0].flow_id) {
        empty_index = (int) data->flow_config[0].flow_id;
        break;
      }
    }
  }
  else {
    empty_index = kLTEV2XHALTxFLowIndex_Default;
  }
  if (empty_index < 0) {
    Err("Fail to set transmit flow - transmit flow is full\n");
    return -1;
  }


  struct TCIA3FlowInfo *flow_info = &g_tcia_mib.flow_info[data->flow_config[0].flow_id];

  flow_info->index = empty_index;
  flow_info->type = (data->flow_config[0].flow_type == kCvcoctci2023FlowType_sps ? kLTEV2XHALTxFlowType_SPS : kLTEV2XHALTxFlowType_Ad_Hoc);
  flow_info->pppp = (data->flow_config[0].pppp > kLTEV2XHALPriority_Max ? kLTEV2XHALPriority_Max : data->flow_config[0].pppp - 1); // Pc5SL-Priority-r13은 범위가 1-8이기 때문에 범위를 벗어남
  flow_info->power = (data->flow_config[0].options.tx_power == true ? data->flow_config[0].tx_power : kDot3Power_TxDefault);
  flow_info->interval = (data->flow_config[0].options.periodicity == true ? periodicity[data->flow_config[0].periodicity] : kLTEV2XHALTxFLowInterval_None);
  flow_info->size = (data->flow_config[0].options.sps_reservation_size == true ? data->flow_config[0].sps_reservation_size : kLTEV2XHALMSDUSize_None);

  if (data->flow_config[0].options.periodicity == false || data->flow_config[0].options.sps_reservation_size == false) {
    Err("Fail to process SetFlowConfigs - periodicity or sps_reservation_size is empty\n");
    return kTCIA3ResponseMsgType_Response;
  }

  if (flow_info->type == kLTEV2XHALTxFlowType_SPS) {
    ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(flow_info->index, flow_info->pppp, flow_info->interval, flow_info->size);
    if (ret < 0) {
      Err("Fail to process SetFlowConfigs - TCIA2023_LTE_V2X_RegisterTransmitFlow() failed: %d\n", ret);
//      return -1;
    }
  }
#else
    struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[0]);
    wsm_tx_info->flow_id = data->flow_config[0].flow_id;
    wsm_tx_info->flow_type = data->flow_config[0].flow_type;
    wsm_tx_info->priority = data->flow_config[0].pppp - 1; // TCI는 1부터 시작한다.
    wsm_tx_info->tx_power = (data->flow_config[0].options.tx_power == true ? data->flow_config[0].tx_power : kDot3Power_TxDefault);
    wsm_tx_info->repeat_rate = (data->flow_config[0].options.periodicity == true ? data->flow_config[0].periodicity : 0);
#endif

  Log(kTCIA3LogLevel_Event, "Success to process SetFlowConfig\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Add SendATCommand
 * 
 * @brief SendATCommand 메시지를 처리한다.
 * @param[in] data SendATCommand 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 * */
int TCIA2023_ProcessSendATCommand(const struct Cvcoctci2023SendATCommand *data)
{
  Log(kTCIA3LogLevel_Event, "Process SendATCommand\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSendATcommand(data);
  }

  /* 구현 */

  Log(kTCIA3LogLevel_Event, "Success to process SendATCommand\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Add RequestSutStatus
 * 
 * @brief RequestSutStatus 메시지를 처리한다.
 * @param[in] data RequestSutStatus 파싱정보가 저장된 정보
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 * */
int TCIA2023_ProcessRequestSutStatus(const bool data)
{
  Log(kTCIA3LogLevel_Event, "Process RequestSutStatus\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintRequestSutStatus(data);
  }

  /* 구현 */

  Log(kTCIA3LogLevel_Event, "Success to process RequestSutStatus\n");
  return kTCIA3ResponseMsgType_Response;
}