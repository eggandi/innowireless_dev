/**
 * @file
 * @brief TCI29451 메시지를 처리하는 기능을 구현한 파일
 * @date 2019-09-28
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#include "j29451/j29451.h"
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief SutControl Restart 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_ProcessSutControlRestart(const struct Cvcoctci2023Params *parse_params)
{
  bool data = parse_params->u.request.u.restart;
  Log(kTCIA3LogLevel_Event, "Process SutControl Restart\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintRestart(data);
  }

  /*
   * BSM 전송을 중지한다.
   * 타이밍에 따라 BSM 콜백이 호출될 수도 있으므로, 일정 시간 지연 후 Path 정보를 백업한다.
   */
  J29451_StopBSMTransmit();
  usleep(200000);
  J29451_SavePathInfoBackupFile(DEFAULT_PH_HEADING_BACKUP_FILE);

  /*
   * DUT 를 초기 상태로 설정한다.
   */
  TCIA2023_InitDUTState();
  Log(kTCIA3LogLevel_Event, "Set DUT as initial state\n");

  // L2 ID를 획득하고 저장한다.
  srand(time(NULL));
  LTEV2XHALL2ID l2_id = (rand() % (UINT8_MAX + 1)) | ((rand() % (UINT8_MAX + 1)) << 8) | ((rand() % (UINT8_MAX + 1)) << 16);
  LTEV2XHAL_SetL2ID(l2_id);

  /*
   * 재부팅 -> j29451 라이브러리 재시작
   */
  Log(kTCIA3LogLevel_Event, "Restart j29451 library\n");
  J29451_Release();

  /*
   * Spirent TS의 재부팅대기시간 기본값인 30초보다 작게 설정한다.
   */
  if (g_tcia_mib.testing.auto_bsm_tx == true) {
    sleep(2);
  }

  uint8_t mac_addr[MAC_ALEN];
  int ret = J29451_Init(kJ29451LogLevel_Err, mac_addr);
  if (ret < 0) {
    Err("Fail to process SutControl Restart - J29451_Init() failed\n");
    return -1;
  }
  /*
   * TS로부터의 User gnss data를 사용하고 있던 상황이라면, 마지막 값을 복구한다.
   * BSM 전송 재시작 후, Insufficient GNSS data 에러를 방지하여 BSM이 정상 전송되도록 하기 위함이다.
   * 이 내용이 없으면, 특정 TP(BSM-MV-BV-01)는 실패한다.
   */
  if (g_tcia_mib.user_gnss_data.use) {
    Log(kTCIA3LogLevel_Event, "Use user gnss data\n");
    J29451_EnableUserGNSSData();
    J29451_SetUserGNSSLatitude(g_tcia_mib.user_gnss_data.lat);
    J29451_SetUserGNSSLongitude(g_tcia_mib.user_gnss_data.lon);
    J29451_SetUserGNSSElevation(g_tcia_mib.user_gnss_data.elev);
    J29451_SetUserGNSSSpeed(g_tcia_mib.user_gnss_data.speed);
    J29451_SetUserGNSSHeading(g_tcia_mib.user_gnss_data.heading);
    J29451_SetUserGNSSPositionalAccuracy(g_tcia_mib.user_gnss_data.pos_accuracy.semi_major,
                                         g_tcia_mib.user_gnss_data.pos_accuracy.semi_minor,
                                         g_tcia_mib.user_gnss_data.pos_accuracy.orientation);
    J29451_SetUserGNSSAccelerationSet4Way(g_tcia_mib.user_gnss_data.acceleration_set.lon,
                                          g_tcia_mib.user_gnss_data.acceleration_set.lat,
                                          g_tcia_mib.user_gnss_data.acceleration_set.vert,
                                          g_tcia_mib.user_gnss_data.acceleration_set.yaw);
  }
  J29451_RegisterBSMTransmitCallback(TCIA2023_BSMTransmitCallback);
  J29451_ActivateHardBrakingEventDecision(false);
  J29451_SetCertificationMode();
  J29451_LoadPathInfoBackupFile(DEFAULT_PH_HEADING_BACKUP_FILE); // 백업된 Path 정보 로딩
  Log(kTCIA3LogLevel_Event, "j29451 library restarted\n");

  /*
   * 새로운 랜덤 MAC 주소 저장
   */
  memcpy(g_tcia_mib.v2x_if.mac_addr[V2V_IF_IDX], mac_addr, MAC_ALEN);
  Log(kTCIA3LogLevel_Init, "if[0] MAC address is changed to random "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(mac_addr));

#if defined(_TCIA2023_LTE_V2X_)
  /*
   * 차량 크기 정보를 설정한다.
   */
  J29451_SetVehicleSize(g_tcia_mib.vehicle_size.width, g_tcia_mib.vehicle_size.len);
#endif

  /*
   * TS로 response를 송신한다.
   */
  TCIA2023_ConstructAndSendTCIResponse(parse_params->frame_type, parse_params->u.request.msg_id, 0);

  /*
   * BSM 전송을 시작한다.
   */
  if (g_tcia_mib.testing.auto_bsm_tx == true) {
    ret = TCIA2023_StartBSMTransmit();
    if (ret < 0) {
      return -1;
    }
  }

  return kTCIA3ResponseMsgType_ResponseSent;
}


/**
 * @brief SutControl RequestSutAvailability 메시지를 처리한다.
 * @param[in] data RequestSutAvailability 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_ProcessSutControlRequestSutAvailability(bool data)
{
  Log(kTCIA3LogLevel_Event, "Processing SutControl RequestSutAvailability\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintRequestSutAvailability(data);
  }
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief SutControl RequestSutInfo 메시지를 처리한다.
 * @param[in] data RequestSutInfo 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_ProcessSutControlRequestSutInfo(bool data)
{
  Log(kTCIA3LogLevel_Event, "Processing SutControl RequestSutInfo\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintRequestSutInfo(data);
  }
  return kTCIA3ResponseMsgType_ResponseSutInfo;
}


/**
 * @brief SutControl SetTestId 메시지를 처리한다.
 * @param[in] set_test_id SetTestId 메시지
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_ProcessSutControlSetTestId(const struct Cvcoctci2023SetTestId *set_test_id)
{
  Log(kTCIA3LogLevel_Event, "Processing SutControl SetTestId\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetTestId(set_test_id);
  }
  return kTCIA3ResponseMsgType_Response;
}


/**
 * Update TCIv3 by young@KETI
 * Add RequestSutStatus
 * 
 * @brief SutControl RequestSutStatus 메시지를 처리한다.
 * @param[in] data RequestSutStatus 파싱정보가 저장된 정보
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 * */
static int TCIA2023_ProcessSutConstrolRequestSutStatus(const bool data)
{
  return TCIA2023_ProcessRequestSutStatus(data);
}

/**
 * Update TCIv3 by young@KETI
 * Add RequestSutStatus
 * 
 * @brief SutControl TCI Request 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_ProcessSutControlTCIMessage(const struct Cvcoctci2023Params *parse_params)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Process received TCISutControl message\n");

  int ret = kTCIA3ResponseMsgType_Response;
  switch (parse_params->u.request.req_type)
  {
    case kCvcoctci2023RequestType_Shutdown:
      Err("Fail to process received TCISutControl message - Shutdown message is not supported\n");
      ret = -1;
      break;

    case kCvcoctci2023RequestType_Restart:
      ret = TCIA2023_ProcessSutControlRestart(parse_params);
      break;

    case kCvcoctci2023RequestType_RequestSutAvailability:
      ret = TCIA2023_ProcessSutControlRequestSutAvailability(parse_params->u.request.u.request_sut_availability);
      break;

    case kCvcoctci2023RequestType_RequestSutInfo:
      ret = TCIA2023_ProcessSutControlRequestSutInfo(parse_params->u.request.u.request_sut_info);
      break;

    case kCvcoctci2023RequestType_SetTestId:
      ret = TCIA2023_ProcessSutControlSetTestId(&(parse_params->u.request.u.set_test_id));
      break;

    case kCvcoctci2023RequestType_EnableGpsInput:
      ret = TCIA2023_ProcessEnableGpsInput(parse_params->u.request.u.enable_gps_input);
      break;

    case kCvcoctci2023RequestType_SetLatitude:
      ret = TCIA2023_ProcessSetLatitude(parse_params->u.request.u.set_latitude);
      break;

    case kCvcoctci2023RequestType_SetLongitude:
      ret = TCIA2023_ProcessSetLongitude(parse_params->u.request.u.set_longitude);
      break;

    case kCvcoctci2023RequestType_SetElevation:
      ret = TCIA2023_ProcessSetElevation(parse_params->u.request.u.set_elevation);
      break;

    case kCvcoctci2023RequestType_SetPositionalAccuracy:
      ret = TCIA2023_ProcessSetPositionalAccuracy(&(parse_params->u.request.u.set_pos_accuracy));
      break;

    case kCvcoctci2023RequestType_SetSpeed:
      ret = TCIA2023_ProcessSetSpeed(parse_params->u.request.u.set_speed);
      break;

    case kCvcoctci2023RequestType_SetHeading:
      ret = TCIA2023_ProcessSetHeading(parse_params->u.request.u.set_heading);
      break;

    case kCvcoctci2023RequestType_SetAccelerationSet4Way:
      ret = TCIA2023_ProcessSetAccelerationSet4Way(&(parse_params->u.request.u.set_accel_set));
      break;

    case kCvcoctci2023RequestType_SetGpsTime:
      ret = TCIA2023_ProcessSetGpsTime(parse_params->u.request.u.set_gps_time);
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add RequestSutStatus
     * */
    case kCvcoctci2023RequestType_RequestSutStatus:
      ret = TCIA2023_ProcessSutConstrolRequestSutStatus(parse_params->u.request.u.request_sut_status);
      break;

    default:
      Err("Fail to process TCISutControl message - invalid request type %d\n", parse_params->u.request.req_type);
      ret = -1;
      break;
  }

  return ret;
}
