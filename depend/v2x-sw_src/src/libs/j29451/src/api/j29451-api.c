/** 
 * @file
 * @brief j29451 라이브러리 API 구현 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#if defined(_FFASN1C_)
#include "ffasn1-j2735-2016.h"
#elif defined (_OBJASN1C_)
#else
#error "3rd party asn.1 library is not defined"
#endif

// 라이브러리 헤더 파일
#include "j29451/j29451-types.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"


/**
 * @brief j29451 라이브러리를 초기화한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] log_level 로그메시지 출력 레벨
 * @param[out] addr 랜덤하게 생성된 MAC주소가 저장될 버퍼
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_Init(J29451LogLevel log_level, uint8_t *addr)
{
  g_j29451_log = (log_level > kJ29451LogLevel_Max) ? kJ29451LogLevel_Max : log_level;
  Log(kJ29451LogLevel_Event, "Initialize j29451 library - log level: %u\n", log_level);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (addr == NULL) {
    Err("Fail to initialize j29451 library - null parameters\n");
    return -kJ29451Result_InvalidParameters;
  }

  return j29451_Init(&g_j29451_mib, addr);
}


/**
 * @brief j29451 라이브러리를 종료한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_Release(void)
{
  Log(kJ29451LogLevel_Event, "Release j29451 library\n");
  struct J29451MIB *mib = &g_j29451_mib;
  j29451_Release(mib);
}


/**
 * @brief BSM 송신 요청을 전달받을 콜백함수를 등록한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] callback 콜백함수 포인터
 */
void OPEN_API J29451_RegisterBSMTransmitCallback(ProcessBSMTransmitCallback callback)
{
  g_j29451_mib.bsm_tx_callback = callback;
}


/**
 * @brief 주기적인 BSM 송신의 시작을 요청한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] tx_interval 송신주기
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_StartBSMTransmit(J29451BSMTxInterval tx_interval)
{
  Log(kJ29451LogLevel_Event, "Start BSM transmit - interval: %umsec\n", tx_interval);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if ((tx_interval < kJ29451BSMTxInterval_Min) || (tx_interval > kJ29451BSMTxInterval_Max)) {
    Err("Fail to start BSM transmit - invalid interval: %umsec\n", tx_interval);
    return -kJ29451Result_InvalidParameters;
  }

  /*
   * BSM 전송을 시작한다.
   */
  return j29451_StartBSMTransmit(&(g_j29451_mib.bsm_tx), tx_interval);
}


/**
 * @brief BSM 송신의 중지를 요청한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_StopBSMTransmit(void)
{
  Log(kJ29451LogLevel_Event, "Stop BSM transmit\n");
  j29451_StopBSMTransmit(&(g_j29451_mib.bsm_tx));
}


/**
 * @brief ID 변경을 수행하도록 요청한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_RequestBSMIDChange(void)
{
  Log(kJ29451LogLevel_Event, "Request BSM ID change\n");
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.bsm_tx.id_change.change_req = true;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 가장 최근에 전송된 BSM에 수납된 Path 정보를 백업한다.
 * @param[in] file_path 정보가 저장될 파일 경로
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SavePathInfoBackupFile(const char *file_path)
{
  Log(kJ29451LogLevel_Event, "Save path info backup file\n");

  /*
   * 파라미터 유효성 체크
   */
  if (file_path == NULL) {
    Err("Fail to save path info backup file - null\n");
    return -kJ29451Result_InvalidParameters;
  }

  /*
   * Path history 관련 내부 정보와 heading 정보를 백업한다.
   */
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  j29451_SavePathInfoBackupFile(file_path);
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 백업파일로부터 Path 정보를 로딩한다.
 * @param[in] file_path 정보가 저장된 파일 경로
 */
void OPEN_API J29451_LoadPathInfoBackupFile(const char *file_path)
{
  Log(kJ29451LogLevel_Event, "Load path info backup file\n");

  /*
   * 파라미터 유효성 체크
   */
  if (file_path == NULL) {
    Err("Fail to load path info backup file - null\n");
    return;
  }

  pthread_mutex_lock(&(g_j29451_mib.mtx));
  j29451_LoadPathInfoBackupFile(file_path);
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief Hard braking 이벤트 발생여부 판정 기능을 활성화/비활성화한다.
 * @param[in] activate 활성화 시 true, 비활성화 시 false
 */
void OPEN_API J29451_ActivateHardBrakingEventDecision(bool activate)
{
  Log(kJ29451LogLevel_Event, "Activate hard braking event decision - %u\n", activate);

  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.obu.hard_braking_decision = activate;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief Path 정보(Path history, Path prediction)를 초기화한다.
 *
 * 본 API는 인증(표준적합성 시험)에서만 사용된다.
 *  - TS의 명령(SetGpsTime)에 의해 시간이 변경되면, Path 정보 생성 메커니즘이 오동작하므로 Path 정보를 초기화해 줄 필요가 있다.
 *  - 해당 명령이 발생할 경우는, DUT의 동작이 시간 상 연속성을 가지지 않는 경우이므로,
 *    과거 정보와 연속성을 갖는 Path 정보는 초기화하여 새롭게 생성되도록 한다.
 */
void OPEN_API J29451_InitPathInfo(void)
{
  Log(kJ29451LogLevel_Event, "Initialize path info\n");
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  j29451_ReleasePathInfo(&(g_j29451_mib.path));
  j29451_InitPathInfo(&(g_j29451_mib.path));
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 인증 모드로 설정한다.
 *
 * 인증을 위한 표준적합성시험(TCI 기반) 진행 시 호출한다.
 */
void OPEN_API J29451_SetCertificationMode(void)
{
  Log(kJ29451LogLevel_Event, "Set certification mode\n");
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.certification.activate = true;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


#if defined(_FFASN1C_)
/**
 * @brief 메시지 프레임을 디코딩한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] msg 디코딩할 메시지 프레임
 * @param[in] msg_size 메시지 프레임의 길이
 * @return 메시지 프레임 디코딩 정보 포인터
 * @retval NULL: 디코딩 실패
 */
j2735MessageFrame OPEN_API * J29451_DecodeMessageFrame(const uint8_t *msg, size_t msg_size)
{
  Log(kJ29451LogLevel_Event, "Decode %u-bytes message frame\n", msg_size);

  if (msg == NULL) {
    Err("Fail to decode message frame - null parameters\n");
    return NULL;
  }

  ASN1Error asn1_err;
  struct j2735MessageFrame *frame = NULL;
  if (asn1_uper_decode((void **)&frame, asn1_type_j2735MessageFrame, msg, msg_size, &asn1_err) < 0) {
    return NULL;
  }
  return frame;
}


/**
 * @brief 디코딩된 메시지 프레임 정보를 해제한다.
 * @param[in] msg 디코딩된 메시지 프레임 정보
 */
void OPEN_API J29451_FreeDecodedMessageFrame(j2735MessageFrame *msg)
{
  Log(kJ29451LogLevel_Event, "Free decoded message frame\n");
  if (msg) {
    asn1_free_value(asn1_type_j2735MessageFrame, msg);
  }
}
#endif
