/**
 * @file
 * @brief TCI31611 메시지를 처리하는 기능을 구현한 파일
 * @date 2019-09-28
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#include "j29451/j29451.h"
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 31611 SetInitialState 메시지를 처리한다.
 * @param[in] data SetInitialState 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetInitialState(bool data)
{
  /*
   * 메시지를 처리한다.
   */
  int ret = TCIA2023_ProcessSetInitialState(data);
  if (ret < 0) {
    return -1;
  }

  /*
   * BSM 송신을 시작한다.
   */
  if (g_tcia_mib.testing.auto_bsm_tx == true) {
    ret = TCIA2023_StartBSMTransmit();
    if (ret < 0) {
      return -1;
    }
  }

  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetInitialState\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 StartBmTx 메시지를 처리한다.
 * @param[in] data StartBmTx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * data->repeat_rate 주기로 반복적인 WSM 전송을 시작한다.
 */
static int TCIA2023_Process31611StartBsmTx(const struct Cvcoctci2023StartBsmTx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 StartBsmTx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStartBsmTx((struct Cvcoctci2023StartBsmTx *)data);
  }

  int ret;

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 31611 StartBmTx - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * 이미 전송 중이면 실패
   */
  if (g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous].txing) {
    Err("Fail to process 31611 StartBmTx - already BSM sending\n");
    return -1;
  }

  /*
   * WSM 전송 파라미터 정보를 업데이트한다.
   */
#if defined(_TCIA2023_DSRC_)
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous]);
#elif defined(_TCIA2023_LTE_V2X_)
 struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous]);
#endif
  wsm_tx_info->if_idx = data->radio.radio;
  wsm_tx_info->psid = data->psid;
  wsm_tx_info->chan_num = DEFAULT_BSM_CHANNEL;
  wsm_tx_info->timeslot = kDot3TimeSlot_0;
  wsm_tx_info->datarate = DEFAULT_DATARATE;
  wsm_tx_info->tx_power = DEFAULT_TX_POWER;
  wsm_tx_info->priority = kDot3Priority_Max;
  wsm_tx_info->repeat_rate = 50; // 기존 100msec 주기로 설정
  wsm_tx_info->pdu_size = 0;  // pdu_size 가 0 이면 BSM 을 생성해서 전송한다.

  unsigned int tx_interval = 5000 / wsm_tx_info->repeat_rate;

#if defined(_TCIA2023_DSRC_)
  /*
   * BSM 전송 채널에 접속한다.
   */
  ret = TCIA2023_DSRC_AccessChannel(wsm_tx_info->if_idx, wsm_tx_info->chan_num, wsm_tx_info->chan_num);
  if (ret < 0) {
    return ret;
  }
#elif defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
  struct TCIA3FlowInfo *flow_info = &(g_tcia_mib.flow_info[wsm_tx_info->flow_id]);
  if (flow_info->type == kLTEV2XHALTxFlowType_SPS) {
    ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(flow_info->index, flow_info->pppp, flow_info->interval, 0);
    if (ret < 0) {
      return -1;
    }
  }
#else
  /*
   * 전송 플로우를 등록한다.
   */
  ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(wsm_tx_info->psid, wsm_tx_info->tx_power, wsm_tx_info->priority, tx_interval);
  if (ret < 0) {
    return -1;
  }
#endif
#else
#error "Communication type is not defined"
#endif

  /*
   * BSM 필수정보를 설정한다.
   */
  ret = J29451_SetVehicleSize(DEFAULT_INIT_VEHICLE_WIDTH, DEFAULT_INIT_VEHICLE_LENGTH);
  if (ret < 0) {
    Err("Fail to start BSM transmit - J29451_SetVehicleSize() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Start BSM transmit\n");
  ret = J29451_StartBSMTransmit(tx_interval);
  if (ret < 0) {
    Err("Fail to proces 29451 StartBsmTx - J29451_StartBSMTransmit() failed\n");
    return ret;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 31611 StartBmTx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 StopBsmTx 메시지를 처리한다.
 * @param[in] params StopBsmTx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSM 전송 타이머 및 쓰레드를 종료한다.
 */
static int TCIA2023_Process31611StopBsmTx(const struct Cvcoctci2023StopBsmTx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 StopBsmTx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStopWsmTx((struct Cvcoctci2023StopWsmTx *)data);
  }

  Log(kTCIA3LogLevel_Event, "Stop BSM transmit\n");
  J29451_StopBSMTransmit();
  g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous].txing = false;

  Log(kTCIA3LogLevel_Event, "Success to process 31611 StopBsmTx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 StartBsmRx 메시지를 처리한다.
 * @param[in] data StartBsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSM 수신을 시작한다.
 */
static int TCIA2023_Process31611StartBsmRx(const struct Cvcoctci2023StartBsmRx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 StartBsmRx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStartWsmRx((struct Cvcoctci2023StartWsmRx *)data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 31611 StartBsmRx - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  Dot3TimeSlot timeslot = kDot3TimeSlot_Continuous;

  /*
   * 시간슬롯별 WSM 수신 파라미터 정보를 업데이트한다.
   */
  struct TCIA3WSMTrxInfo *wsm_rx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);
  if (data->options.psid) {
    wsm_rx_info->psid = data->psid;
  } else {
    wsm_rx_info->psid = kCvcoctci2023Psid_NA;
  }
  wsm_rx_info->if_idx = data->radio.radio;
  wsm_rx_info->chan_num = data->chan_id;
  wsm_rx_info->timeslot = timeslot;
  memcpy(&(wsm_rx_info->event_handling), &(data->event_handling), sizeof(struct Cvcoctci2023EventHandling));

#if defined(_TCIA2023_DSRC_)
  /*
   * 채널에 접속한다.
   */
  int ret = TCIA2023_DSRC_AccessChannel(wsm_rx_info->if_idx, wsm_rx_info->chan_num, wsm_rx_info->chan_num);
  if (ret < 0) {
    return -1;
  }
#endif

  /*
   * WSM 수신을 시작한다.
   */
  TCIA2023_StartWSMReceive(timeslot);

  Log(kTCIA3LogLevel_Event, "Success to process 31611 StartBsmRx on timeslot %d\n", timeslot);
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 StopBsmRx 메시지를 처리한다.
 * @param[in] params StopBsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSM 수신을 종료한다.
 */
static int TCIA2023_Process31611StopBsmRx(const struct Cvcoctci2023StopBsmRx *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 StopBsmRx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStopWsmRx((struct Cvcoctci2023StopWsmRx *)data);
  }

  TCIA2023_StopWSMReceive(kDot3TimeSlot_Continuous);

  Log(kTCIA3LogLevel_Event, "Success to process 31611 StopBsmRx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 SetVehicleEventFlags 메시지를 처리한다.
 * @param[in] data SetVehicleEventFlags 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetVehicleEventFlags(const struct Cvcoctci2023SetVehicleEventFlags *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 SetVehicleEventFlags\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetVehicleEventFlags(data);
  }

  /*
   * 이벤트 플래그를 설정한다.
   */
  struct J29451VehicleEventFlags flags;
  memset(&flags, 0, sizeof(flags));
  flags.hazard_lights = data->hazard_lights;
  flags.stop_line_violation = data->stop_line_violation;
  flags.abs_activated = data->abs_activated;
  flags.traction_control_loss = data->traction_control_loss;
  flags.stability_control_activated = data->stability_control_activated;
  flags.hazardous_materials = data->hazardous_materials;
  flags.hard_braking = data->hard_braking;
  flags.lights_changed = data->lights_changed;
  flags.wiper_changed = data->wipers_changed;
  flags.flat_tire = data->flat_tire;
  flags.disabled_vehicle = data->disabled_vehicle;
  flags.airbag_deployment = data->air_bag_deployment;
  J29451_SetVehicleEventFlags(&flags);

  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetVehicleEventFlags\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 SetTransmissionState 메시지를 처리한다.
 * @param[in] data SetExteriorLights 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetTransmissionState(Cvcoctci2023SetTransmissionState data)
{
  Log(kTCIA3LogLevel_Event, "Processing 31611 SetTransmissionState\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetTransmissionState(data);
  }

  /*
   * 트랜스미션 상태를 설정한다.
   */
  int ret = J29451_SetVehicleTransmissionState((J29451TransmissionState)data);
  if (ret < 0) {
    Err("Fail to process 31611 SetTransmissionState - J29451_SetVehicleTransmissionState() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetTransmissionState\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 SetSteeringWheelAngle 메시지를 처리한다.
 * @param[in] data SetSteeringWheelAngle 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetSteeringWheelAngle(Cvcoctci2023SetSteeringWheelAngle data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 SetSteeringWheelAngle\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetSteeringWheelAngle(data);
  }

  /*
   * 스티어링 휠 각도를 설정한다.
   */
  J29451_SetVehicleSteeringWheelAngle((J29451SteeringWheelAngle)data);

  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetSteeringWheelAngle\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 SetBrakeSystemStatus 메시지를 처리한다.
 * @param[in] data SetBrakeSystemStatus 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetBrakeSystemStatus(const struct Cvcoctci2023SetBrakeSystemStatus *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 SetBrakeSystemStatus\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetBrakeSystemStatus(data);
  }

  /*
   * 브레이크 시스템 상태를 설정한다.
   */
  int ret;
  struct J29451BrakeAppliedStatus applied;
  memset(&applied, 0, sizeof(applied));
  applied.unavailable = data->brake_applied_status.unavailable;
  applied.left_front = data->brake_applied_status.left_front;
  applied.left_rear = data->brake_applied_status.left_rear;
  applied.right_front = data->brake_applied_status.right_front;
  applied.right_rear = data->brake_applied_status.right_rear;
  J29451_SetVehicleBrakeAppliedStatus(&applied);
  ret = J29451_SetVehicleTractionControlStatus((J29451TractionControlStatus)(data->traction_control_status));
  if (ret < 0) {
    Err("Fail to process 31611 SetBrakeSystemStatus - J29451_SetVehicleTractionControlStatus() failed: %d\n", ret);
    return -1;
  }
  ret = J29451_SetVehicleAntiLockBrakeStatus((J29451AntiLockBrakeStatus)(data->anti_lock_brake_status));
  if (ret < 0) {
    Err("Fail to process 31611 SetBrakeSystemStatus - J29451_SetVehicleAntiLockBrakeStatus() failed: %d\n", ret);
    return -1;
  }
  ret = J29451_SetVehicleStabilityControlStatus((J29451StabilityControlStatus)(data->stability_control_status));
  if (ret < 0) {
    Err("Fail to process 31611 SetBrakeSystemStatus - J29451_SetVehicleStabilityControlStatus() failed: %d\n", ret);
    return -1;
  }
  ret = J29451_SetVehicleBrakeBoostApplied((J29451BrakeBoostApplied)(data->brake_boost_applied));
  if (ret < 0) {
    Err("Fail to process 31611 SetBrakeSystemStatus - J29451_SetVehicleBrakeBoostApplied() failed: %d\n", ret);
    return -1;
  }
  ret = J29451_SetVehicleAuxiliaryBrakeStatus((J29451AuxiliaryBrakeStatus)(data->auxiliary_brake_status));
  if (ret < 0) {
    Err("Fail to process 31611 SetBrakeSystemStatus - J29451_SetVehicleAuxiliaryBrakeStatus() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetBrakeSystemStatus\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 SetVehicleSize 메시지를 처리한다.
 * @param[in] data SetVehicleSize 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetVehicleSize(const struct Cvcoctci2023SetVehicleSize *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 SetVehicleSize\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetVehicleSize(data);
  }

  /*
   * 차량크기를 설정한다.
   */
  g_tcia_mib.vehicle_size.width = data->width;
  g_tcia_mib.vehicle_size.len = data->length;
  int ret = J29451_SetVehicleSize(data->width, data->length);
  if (ret < 0) {
    Err("Fail to process 31611 SetVehicleSize - J29451_SetVehicleSize() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetVehicleSize\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 31611 SetExteriorLights 메시지를 처리한다.
 * @param[in] data SetExteriorLights 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process31611SetExteriorLights(const struct Cvcoctci2023SetExteriorLights *data)
{
  Log(kTCIA3LogLevel_Event, "Process 31611 SetExteriorLights\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetExteriorLights(data);
  }

  /*
   * 외부등 상태를 설정한다.
   */
  struct J29451ExteriorLights lights;
  memset(&lights, 0, sizeof(lights));
  lights.low_beam_headlight_on = data->low_beam_headlight_on;
  lights.high_beam_headlight_on = data->high_beam_headlight_on;
  lights.left_turn_signal_on = data->left_turn_signal_on;
  lights.right_turn_signal_on = data->right_turn_signal_on;
  lights.hazard_signal_on = data->hazard_signal_on;
  lights.automatic_light_control_on = data->automatic_light_control_on;
  lights.daytime_running_lights_on = data->daytime_running_lights_on;
  lights.fog_light_on = data->fog_light_on;
  lights.parking_light_on = data->parking_light_on;
  J29451_SetVehicleExteriorLights(&lights);

  Log(kTCIA3LogLevel_Event, "Success to process 31611 SetExteriorLights\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Delete enableGpsINput, setLatitude, setLongitude, setElevation, setPositionnalAccuacy, setSpeed,
 * setHeading, setAccelerationSet4Way and setGpsTime
 * 
 * @brief 31611 TCI Request 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_Process31611TCIMessage(const struct Cvcoctci2023Params *parse_params)
{
  Log(kTCIA3LogLevel_Event, "Process received TCI31611 message\n");

  int ret = kTCIA3ResponseMsgType_Response;
  switch (parse_params->u.request.req_type)
  {
    case kCvcoctci2023RequestType_SetInitialState:
      ret = TCIA2023_Process31611SetInitialState(parse_params->u.request.u.set_initial_state);
      break;

    case kCvcoctci2023RequestType_StartBsmTx:
      ret = TCIA2023_Process31611StartBsmTx(&(parse_params->u.request.u.start_bsm_tx));
      break;

    case kCvcoctci2023RequestType_StopBsmTx:
      ret = TCIA2023_Process31611StopBsmTx(&(parse_params->u.request.u.stop_bsm_tx));
      break;

    case kCvcoctci2023RequestType_StartBsmRx:
      ret = TCIA2023_Process31611StartBsmRx(&(parse_params->u.request.u.start_bsm_rx));
      break;

    case kCvcoctci2023RequestType_StopBsmRx:
      ret = TCIA2023_Process31611StopBsmRx(&(parse_params->u.request.u.stop_bsm_rx));
      break;

    case kCvcoctci2023RequestType_SetVehicleEventFlags:
      ret = TCIA2023_Process31611SetVehicleEventFlags(&(parse_params->u.request.u.set_vehicle_event_flags));
      break;

    case kCvcoctci2023RequestType_SetTransmissionState:
      ret = TCIA2023_Process31611SetTransmissionState(parse_params->u.request.u.set_transmission_state);
      break;

    case kCvcoctci2023RequestType_SetSteeringWheelAngle:
      ret = TCIA2023_Process31611SetSteeringWheelAngle(parse_params->u.request.u.set_steering_wheel_angle);
      break;

    case kCvcoctci2023RequestType_SetBrakeSystemStatus:
      ret = TCIA2023_Process31611SetBrakeSystemStatus(&(parse_params->u.request.u.set_brake_system_status));
      break;

    case kCvcoctci2023RequestType_SetVehicleSize:
      ret = TCIA2023_Process31611SetVehicleSize(&(parse_params->u.request.u.set_vehicle_size));
      break;

    case kCvcoctci2023RequestType_SetExteriorLights:
      ret = TCIA2023_Process31611SetExteriorLights(&(parse_params->u.request.u.set_exterior_lights));
      break;

    default:
      Err("Fail to process TCI31611 message - invalid request type %d\n", parse_params->u.request.req_type);
      ret = -1;
      break;
  }

  return ret;
}
