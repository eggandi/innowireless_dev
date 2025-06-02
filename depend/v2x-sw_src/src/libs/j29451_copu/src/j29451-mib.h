/** 
 * @file
 * @brief j29451 라이브러리 MIB(Management Information Base)를 정의한 헤더 파일
 * @date 2020-10-03
 * @author gyun
 */


#ifndef V2X_SW_J29451_MIB_H
#define V2X_SW_J29451_MIB_H


// 시스템 헤더 파일
#include <pthread.h>
#include <time.h>

// 라이브러리 의존 헤더 파일
#include "gps.h"
#include "sudo_queue.h"
#ifdef _CRATON2_
#include <atlk/ehsm_service.h>
#endif

// 라이브러리 헤더 파일
#include "j29451/j29451-defines.h"
#include "j29451/j29451-types.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal-defines.h"
#include "j29451-internal-types.h"
#include "path-info//j29451-path-info.h"
#include "obu/j29451-obu-gnss-data.h"
#ifdef _UNIT_TEST_
#include "j29451-test.h"
#endif


/**
 * @brief BSM에서 사용되는 랜덤값 집합
 */
struct J29451BSMDataRandoms
{
  unsigned int msg_cnt; ///< BSM에 수납되는 msgCnt
  uint8_t temporary_id[J29451_TEMPORARY_ID_LEN]; ///< BSM에 수납되는 ID
  uint8_t addr[MAC_ALEN]; ///< MAC 주소
};


/**
 * @brief BSM 수납 정보
 */
struct J29451BSMData
{
  unsigned int msg_cnt; ///< 메시지 카운트 - 전송 시마다 1씩 증가하며, 0~127의 값을 가진다.
  uint8_t temporary_id[J29451_TEMPORARY_ID_LEN]; ///< Temporary ID - 랜덤하게 생성된다.
  struct J29451BSMDataRandoms randoms; ///< 랜덤값 집합
};


/**
 * @brief BSM 송신 관련 정보
 */
struct J29451BSMTx
{
  int timer_fd; ///< 송신 타이머
  pthread_t thread; ///< 송신 쓰레드
  bool thread_running; ///< 송신 쓰레드가 동작 중인지 여부 (쓰레드가 업데이트하고 API 컨텍스트가 읽는다)
  bool thread_exit; ///< 송신 쓰레드 종료 요청 플래그 (API 컨텍스트가 업데이트하고 쓰레드가 읽는다)
  J29451BSMTxInterval tx_interval; ///< 송신 주기
  struct {
    J29451IDChangeInterval interval; ///< ID 변경 주기
    J29451IDChangeDistance dist_threshold; ///< ID 변경 거리
    struct {
      double lat_deg; ///< (ID 변경 후) 최초 BSM 송신 시점의 위도 (도 단위)
      double lon_deg; ///< (ID 변경 후) 최초 BSM 송신 시점의 위도 (도 단위)
    } initial_pos;
    uint64_t initial_time; ///< (ID 변경 후) 최초 BSM 송신 시점(밀리초 단위)
    bool change_req; ///< ID 변경 요청을 받았는지 여부 (set될 경우, 직후 BSM 생성 시 ID를 변경한다)
  } id_change; ///< ID 변경 관련 관리 정보
  bool first_bsm_transmitted; ///< 첫번째 BSM이 전송되었는지 여부
};


/**
 * @brief lon/lat/vertical 가속도 값에 적용되는 butterworth low pass 필터 (per SAE J2945/1a-2020 p.77)
 *
 * 필터 구현 참조
 *  - https://github.com/adis300/filter-c
 *  - https://exstrom.com/journal/sigproc/dsigproc.html
 */
struct J29451BWLowPassFilter
{
  int n;
  float A[J29451_BW_FILTER_ORDER / 2];
  float d1[J29451_BW_FILTER_ORDER / 2];
  float d2[J29451_BW_FILTER_ORDER / 2];
  float w0[J29451_BW_FILTER_ORDER / 2];
  float w1[J29451_BW_FILTER_ORDER / 2];
  float w2[J29451_BW_FILTER_ORDER / 2];
};


/**
 * @brief GNSS 정보
 */
struct J29451GNSSInfo
{
  pthread_t thread; ///< GNSS 데이터 업데이트 쓰레드
  bool thread_running; ///< GNSS 데이터 업데이트 쓰레드가 동작 중인지 여부 (쓰레드가 업데이트하고 API 컨텍스트가 읽는다)
  bool thread_exit; ///< GNSS 데이터 업데이트 쓰레드 종료 요청 플래그 (API 컨텍스트가 업데이트하고 쓰레드가 읽는다)
  J29451GNSSDataSelectionMode gnss_data_sel_mode; ///< GNSS 데이터 선택 모드
  struct J29451GNSSDataBuf gnss_data_buf; ///<  GNSS 데이터 버퍼
  struct J29451GNSSDataUpdateStartOffset offset; ///< GNSS 데이터 업데이트시작 오프셋 정보

#ifdef _UNIT_TEST_
  struct J29451TestGPSData gps_data; ///< 단위테스트 시 사용되는 GNSS 입력 데이터 (테스트코드에 의해 채워진다)
#else
  struct gps_data_t gps_data; ///< GNSS 입력 데이터 (from gpsd)
#endif
  struct J29451GNSSData gnss_data; ///< GNSS 데이터
  bool user_gnss_enable; ///< 어플리케이션이 입력하는 GNSS 데이터 사용 여부. false일 경우에는 gpsd로부터 입력되는 데이터가 사용된다.

  struct {
    bool initialized; ///< latching 기능이 초기화되었는지 여부
    bool latched; ///< 헤딩값이 잠겨(latching) 있는지 여부
    J29451Speed prev_speed; ///< 직전 속도값
    J29451Heading prev_heading; ///< 직전 헤딩값
    J29451Heading heading; ///< 잠긴(latching된) 헤딩값
  } heading_latch; ///< 저속에서의 Heading latch 관련 정보

  struct {
    struct J29451BWLowPassFilter lon; ///< lon 가속도 필터
    struct J29451BWLowPassFilter lat; ///< lat 가속도 필터
    struct J29451BWLowPassFilter vert; ///< vertical 가속도 필터
    struct J29451BWLowPassFilter yaw; ///< yawrate 가속도 필터
  } accel_filter; ///< 가속도값에 적용되는 Butterworth 필터
};


/**
 * @brief OBU 정보
 */
struct J29451OBUInfo
{
  bool hard_braking_decision; ///< hard braking 이벤트발생여부 판정 기능 활성화/비활성화 여부 (기본값: true)
  struct J29451GNSSInfo gnss; ///< GNSS 정보
};


/**
 * @brief 차량 정보
 */
struct J29451VehicleInfo
{
  J29451TransmissionState transmission; ///< 기어 상태
  J29451Speed speed; ///< 속도
  J29451SteeringWheelAngle angle; ///< 스티어링 휠 각도
  struct {
    struct J29451BrakeAppliedStatus wheel_brakes;
    J29451TractionControlStatus traction;
    J29451AntiLockBrakeStatus abs;
    J29451StabilityControlStatus scs;
    J29451BrakeBoostApplied brake_boost;
    J29451AuxiliaryBrakeStatus aux_brakes;
  } brakes; ///< 브레이크 관련 정보
  struct {
    J29451VehicleWidth width;
    J29451VehicleLength length;
  } size; ///< 차량 크기 정보
  struct J29451ExteriorLights lights; ///< 외부등 상태 정보
  struct {
    bool set; ///< 이벤트 발생 여부
    struct J29451VehicleEventFlags event; ///< 이벤트별 발생 상태
  } event; ///< 이벤트 발생 정보
};


/**
 * @brief j29451 라이브러리 MIB
 */
struct J29451MIB
{
  pthread_mutex_t mtx; ///< MIB 접근 뮤텍스
  struct J29451BSMTx bsm_tx; ///< BSM 송신 정보
  struct J29451BSMData bsm_data; ///< BSM 수납 정보
  struct J29451OBUInfo obu; ///< OBU 정보
  struct J29451VehicleInfo vehicle; ///< 차량 정보
  struct J29451PathInfo path; ///< Path 정보
  /// BSM 송신 요청 콜백함수 포인터 - J29451_RegisterBSMTransmitCallback() API 호출을 통해 등록된다.
  /// j29451 라이브러리는 BSM 송신 시점마다 본 콜백함수를 호출하여 송신할 BSM을 어플리케이션으로 전달한다.
  ProcessBSMTransmitCallback bsm_tx_callback;

  /// 인증(표준적합성 시험) 시 사용되는 정보
  /// 인증(표준적합성 시험) 모드에서는 GNSS정보가 유효하지 않은 경우, 직전 GNSS 정보를 사용하여 무조건 BSM이 전송되도록 한다.
  /// 시험 진행 시 GPS 환경이 양호하지 않으면, 본 기능을 사용하지 않을 경우 BSM이 전송되지 않아 시험을 통과하지 못한다.
  struct {
    bool activate; ///< 인증(표준적합성 시험) 모드 활성화 상태
  } certification;
#ifdef _CRATON2_
  ehsm_service_t *ehm_service;
#endif
};


#endif //V2X_SW_J29451_MIB_H
