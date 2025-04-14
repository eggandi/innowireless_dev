/**
 * @file
 * @brief BSM 전송 기능 구현
 * @date 2022-09-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "j29451/j29451.h"
#if defined(_BSMD_DSRC_)
#include "wlanaccess/wlanaccess.h"
#elif defined(_BSMD_LTE_V2X_)
#include "ltev2x-hal/ltev2x-hal.h"
#endif

// 어플리케이션 헤더 파일
#include "include/bsmd.h"


/**
 * @brief BSM 전송을 시작한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int BSMD_StartBSMTransmit(void)
{
  int ret;
  Log(kBSMDLogLevel_Event, "Start BSM transmit\n");

#ifdef _BSMD_DSRC_
  /*
   * V2V 채널에 접속한다.
   */
  ret = WAL_AccessChannel(V2V_IF_IDX, V2V_CHAN_NUM, V2V_CHAN_NUM);
  if (ret < 0) {
    Err("Fail to access channel - WAL_AccessChannel() failed: %d\n", ret);
    return -1;
  }
  Log(kBSMDLogLevel_Event, "Success to access channel (I/F: %u, Chan: %u)\n", V2V_IF_IDX, V2V_CHAN_NUM);
#elif defined(_BSMD_LTE_V2X_)
  /*
   * 전송 플로우를 등록한다.
   */
  ret = BSMD_LTE_V2X_RegisterTransmitFlow();
  if (ret < 0) {
    return -1;
  }
#else
#error "Communication type is not defined"
#endif

  /*
   * BSM 필수정보를 설정한다.
   */
  ret = J29451_SetVehicleSize(VEHICLE_WIDTH, VEHICLE_LENGTH);
  if (ret < 0) {
    Err("Fail to start BSM transmit - J29451_SetVehicleSize() failed: %d\n", ret);
    return -1;
  }

  /*
   * 29451 라이브러리에 BSM 전송 시작을 요청한다.
   */
  ret = J29451_StartBSMTransmit(BSM_TX_INTERVAL);
  if (ret < 0) {
    Err("Fail to start BSM transmit - J29451_StartBSMTransmit() failed: %d\n", ret);
    return -1;
  }
  Log(kBSMDLogLevel_Event, "Success to start BSM transmit\n");

  return 0;
}


/**
 * @brief j29451 라이브러리가 호출하는 BSM 송신 콜백함수
 * @param[in] bsm BSM 메시지 UPER 인코딩 바이트열
 * @param[in] bsm_size BSM 메시지의 길이
 * @param[in] event 이벤트 발생 여부
 * @param[in] cert_sign 인증서로 서명해야 하는지 여부
 * @param[in] id_change ID/인증서 변경 필요 여부
 * @param[in] addr 랜덤하게 생성된 MAC 주소. id_change=true일 경우 본 MAC 주소를 장치에 설정해야 한다.
 */
void
BSMD_BSMTransmitCallback(const uint8_t *bsm, size_t bsm_size, bool event, bool cert_sign, bool id_change, uint8_t *addr)
{
  Log(kBSMDLogLevel_DetailedEvent, "BSM tx callback - event: %u, cert_sign: %u, id_change: %u\n", event, cert_sign, id_change);

#ifdef _SUPPORT_POWER_OFF_DETECT_
  if (g_bsmd_mib.power_off == true) {
    Log(kBSMDLogLevel_Event, "Power off state - not send BSM\n");
    return;
  }
#endif

  /*
   * 필요 시 MAC 주소를 변경한다.
   */
  if (id_change == true) {
    Log(kBSMDLogLevel_Event, "BSM tx callback - id changed - new MAC addr: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(addr));
    memcpy(g_bsmd_mib.v2v_if_mac_addr, addr, MAC_ALEN);
  }

  /*
   * Signed SPDU를 생성한다.
   */
  Dot2SignerIdType signer_id;
  if (cert_sign == true) {
    Log(kBSMDLogLevel_Event, "BSM tx callback - Force to sign with certificate\n");
    signer_id = kDot2SignerId_Certificate;
  } else {
    signer_id = kDot2SignerId_Profile;
  }
  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Signed;
  params.signed_data.psid = BSM_PSID;
  params.signed_data.signer_id_type = signer_id;
  params.signed_data.cmh_change = id_change;
  res = Dot2_ConstructSPDU(&params, bsm, bsm_size);
  if (res.ret < 0) {
    Err("BSM tx callback - Dot2_ConstructSPDU() failed: %d\n", res.ret);
    return;
  }

#if defined(_BSMD_DSRC_)
  WalPriority prio = (event == true) ? BSM_EVENT_PRIORITY : BSM_DEFAULT_PRIORITY;
  BSMD_DSRC_TransmitWSM(res.spdu, (size_t)res.ret, prio);
#elif defined(_BSMD_LTE_V2X_)
  LTEV2XHALPriority prio = (event == true) ? BSM_EVENT_PRIORITY : BSM_DEFAULT_PRIORITY;
  BSMD_LTE_V2X_TransmitWSM(res.spdu, (size_t)res.ret, prio);
#else
#error "Communication type is not defined"
#endif
  free(res.spdu);

  // 현재 인증서가 이미 만기되었거나 다음번 BSM 서명 시에 만기될 경우에는, BSM ID 변경을 요청한다.
  // 다음번 BSM 콜백함수가 호출될 때, id_change=true, cert_sign=true 가 전달된다.
  if (res.cmh_expiry == true) {
    Log(kBSMDLogLevel_Event, "BSM tx callback - Certificate will be expired. Request to change BSM ID\n");
    J29451_RequestBSMIDChange();
  }

#ifdef _SUPPORT_POWER_OFF_DETECT_
  /*
   * Power off가 된 상태이면,
   * BSM 전송을 중지하고 Path 정보를 백업한다.
   */
  if (BSMD_DetectPowerOff() == true) {
    Log(kBSMDLogLevel_Event, "Power off detected - stop BSM transmit and backup path info\n");
    J29451_StopBSMTransmit();
    J29451_SavePathInfoBackupFile(PATH_INFO_BACKUP_FILE);
    system("sync"); // 낸드 플래시 싱크 명령 강제 입력 (=전원이 꺼지기 전에 낸드플래시에 즉각 저장되도록 한다)
    g_bsmd_mib.power_off = true;
  }
#endif

#ifdef _SUPPORT_USER_POWER_OFF_
  /*
   * Power off가 된 상태이면,
   * BSM 전송을 중지하고 Path 정보를 백업한다.
   */
  if (g_bsmd_mib.power_off == true) {
    Log(kBSMDLogLevel_Event, "Power off detected - stop BSM transmit and backup path info\n");
    J29451_StopBSMTransmit();
    J29451_SavePathInfoBackupFile(PATH_INFO_BACKUP_FILE);
  }
#endif
}
