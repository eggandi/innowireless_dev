/** 
 * @file
 * @brief BSM 송신 관련 기능을 구현한 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <sys/queue.h>  
// 라이브러리 내부 헤더 파일
#define _D_CLEANUPHEAD
#include "j29451-internal.h"
#include "j29451-internal-inline.h"
#include "j29451-mib.h"


/**
 * @brief BSM 첫 송신 지연을 구한다.
 * @return 송신지연(밀리초 단위)
 */
static inline unsigned int j29451_GetBSMInitialTxDelay(void)
{
  uint8_t t[1];
  do {
    j29451_GetRandomOcts(t, 1);
  } while(t[0] >= 200U);
  return (unsigned int)t[0];
}


/**
 * @brief BSM 송신 관련 정보를 초기화한다.
 * @param[in] bsm_tx BSM 송신 관련 정보
 */
void INTERNAL j29451_InitBSMTx(struct J29451BSMTx *bsm_tx)
{
  Log(kJ29451LogLevel_Event, "Initialize BSM transmit\n");
  memset(bsm_tx, 0, sizeof(struct J29451BSMTx));
  bsm_tx->tx_interval = kJ29451BSMTxInterval_Default;
  bsm_tx->id_change.interval = kJ29451IDChangeInterval_Default;
  bsm_tx->id_change.dist_threshold = kJ29451IDChangeDistance_Default;
  bsm_tx->id_change.initial_pos.lat_deg = NAN;
  bsm_tx->id_change.initial_pos.lon_deg = NAN;
}


/**
 * @brief BSM 송신 동작을 해제하고 관련 정보를 초기화한다.
 * @param[in] bsm_tx BSM 송신 관련 정보
 */
void INTERNAL j29451_ReleaseBSMTransmit(struct J29451BSMTx *bsm_tx)
{
  j29451_StopBSMTransmit(bsm_tx);
  j29451_InitBSMTx(bsm_tx);
}


/**
 * @brief BSM을 준비(생성)한다.
 * @param[out] bsm_size 준비(생성)된 BSM의 길이가 저장될 변수
 * @param[out] event 이벤트발생 여부가 반환될 변수 포인터
 * @param[out] cert_sign 인증서서명여부가 반환될 변수 포인터
 * @param[out] id_change 식별자변경여부가 반환될 변수 포인터
 * @param[out] addr 새롭게 생성된 MAC주소가 반환될 버퍼 (id_change=true일 때만 반환됨)
 * @return 생성된 BSM 바이트열
 * @retval NULL 실패
 */
static uint8_t * j29451_PrepareBSM(size_t *bsm_size, bool *event, bool *cert_sign, bool *id_change, uint8_t *addr)
{
  uint8_t *bsm = NULL;
  *event = false;
  *cert_sign = false;
  *id_change = false;

  pthread_mutex_lock(&(g_j29451_mib.mtx));
  /*
   * GNSS 데이터 선택모드를 설정한다.
   */
  j29451_SetGNSSDataSelectionMode();

  /*
   * BSM을 생성하고 콜백함수로 전달할 파라미터 값을 결정한다.
   */
  struct J29451GNSSData gnss;
  struct J29451VehicleInfo vehicle;

  /*
   * 최신 GNSS 정보를 획득하여 Path 정보를 업데이트하고, 차량정보를 획득한다.
   * 충분한 정보가 획득된 상태에서만 BSM이 전송된다.
   */
  j29451_InitGNSSData(&gnss);
  if ((j29451_GetCurrentGNSSData(&gnss) == kJ29451Result_Success) &&
      (j29451_UpdatePathInfo(&gnss) == true) &&
      (j29451_GetCurrentVehicleInfo(&vehicle) == kJ29451Result_Success))
  {
    struct timespec ts;
#ifdef _UNIT_TEST_
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    uint64_t current_msec = ((uint64_t)ts.tv_sec * 1000) + ((uint64_t)ts.tv_nsec / 1000000);

#ifdef _TARGET_STD_VER_2016_
    // 백업 PH 정보는 사용되었음을 표시한다 -> 더이상 사용하지 않기 위해.
    g_j29451_mib.path.backup_ph_present = false;
#endif

    // 라이브러리 시작 후 첫 전송일 경우, 인증서로 서명하도록 한다.
    if (g_j29451_mib.bsm_tx.first_bsm_transmitted == false) {
      *cert_sign = true;
    }

    // ID 변경 필요 여부를 체크한다. ID 변경 시에는 인증서로 서명해야 한다.
    *id_change = j29451_CheckBSMIDChange(current_msec, &gnss);
    if (*id_change == true) {
      *cert_sign = true;
    }

    // Hard braking 이벤트 발생 여부를 확인한다.
    if (g_j29451_mib.obu.hard_braking_decision == true) {
      if (gnss.acceleration_set.lon_raw < J29451_HARD_BRAKIG_THRESHOLD) {
        Log(kJ29451LogLevel_Event, "Set hard braking event using internal decision\n");
        j29451_SetVehicleInfoHardBrakingEvent(&vehicle);
      } else {
        Log(kJ29451LogLevel_Event, "Clear hard braking event using internal decision\n");
        j29451_ClearVehicleInfoHardBrakingEvent(&vehicle);
      }
    }

    // 이벤트 발생 여부를 체크한다. 이벤트 발생 중에는 ID를 변경해서는 안되며, 인증서로 서명해야 한다.
    *event = vehicle.event.set;
    if (*event == true) {
      *id_change = false;
      *cert_sign = true;
    }

    // 어플리케이션으로부터 ID 변경하도록 요청 받았을 경우(예: 인증서 만기)에는 ID를 변경하고, 인증서로 서명하도록 한다.
    if (g_j29451_mib.bsm_tx.id_change.change_req == true) {
      *id_change = true;
      *cert_sign = true;
    }

    // 필요 시, ID를 변경하고 관련 정보를 업데이트한다.
    if (*id_change == true) {
      g_j29451_mib.bsm_data.msg_cnt = g_j29451_mib.bsm_data.randoms.msg_cnt;
      memcpy(g_j29451_mib.bsm_data.temporary_id, g_j29451_mib.bsm_data.randoms.temporary_id, J29451_TEMPORARY_ID_LEN);
      memcpy(addr, g_j29451_mib.bsm_data.randoms.addr, MAC_ALEN);
      j29451_UpdateBSMIDChangeInitialPoint(current_msec, &gnss);
    }

    // BSM을 생성한다.
    bsm = j29451_ConstructBSM(&gnss, &vehicle, bsm_size);
    if (bsm) {
      g_j29451_mib.bsm_tx.first_bsm_transmitted = true;
      g_j29451_mib.bsm_tx.id_change.change_req = false;
    }
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));

  /*
   * ID를 변경했을 경우, 다음번 ID 변경을 위한 랜덤값들을 미리 생성하여 저장해 둔다.
   */
  if (*id_change == true) {
    j29451_GenerateAndStoreNextRandomPool(&(g_j29451_mib.bsm_data));
  }

  return bsm;
}


/**
 * @brief BSM을 전송한다.
 * @param[in] bsm 전송할 BSM 바이트열
 * @param[in] bsm_size 전송할 BSM 바이트열의 길이
 * @param[in] event 이벤트 발생 여부
 * @param[in] cert_sign 인증서 서명 필요 여부
 * @param[in] id_change ID 변경 여부
 * @param[in] addr 새롭게 생성된 MAC 주소 (id_change=true인 경우에만 의미있음)
 */
static void
j29451_TransmitBSM(const uint8_t *bsm, size_t bsm_size, bool event, bool cert_sign, bool id_change, uint8_t *addr)
{
  /*
   * 어플리케이션에 전달한다.
   */
  ProcessBSMTransmitCallback callback = g_j29451_mib.bsm_tx_callback;
  if (callback) {
    callback(bsm, bsm_size, event, cert_sign, id_change, addr);
  }
}


/**
 * @brief BSM 전송 타이머를 생성한다.
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int j29451_CreateBSMTransmitTimer(void)
{
  struct J29451BSMTx *bsm_tx = &(g_j29451_mib.bsm_tx);

  /*
   * 타이머 시작시점과 주기를 결정한다.
   * 다음 초 시작시점 + 100msec + 랜덤 지연(0~199musec) 시점에 첫 타이머가 터지도록 한다.
   */
  struct timespec current;
  clock_gettime(CLOCK_MONOTONIC, &current);
  long interval = (long)bsm_tx->tx_interval * 1000000;
  long initial_delay = (long)j29451_GetBSMInitialTxDelay();
  long first_tx_delay = ((long)bsm_tx->tx_interval * 1000000) + (initial_delay * 1000000);
  struct itimerspec ts;
  ts.it_value.tv_sec = current.tv_sec + 1;
  ts.it_value.tv_nsec = first_tx_delay; // 통계적 결과에 따르면, 약 6msec 정도 빠르게 시작하면
  // 실제 BSM 송신 시점의 랜덤성이 대체로 만족된다. (시험 시 약 50% 만족)
  if (ts.it_value.tv_nsec >= 1000000000) { // tx_interval 값이 커서 tv_nsec 값이 1000000000(=1초)를 넘어가면 조정해 준다.
    // tx_interval 값이 기본값(100msec)인 경우에는 해당되지 않는다.
    ts.it_value.tv_sec++;
    ts.it_value.tv_nsec -= 1000000000;
  }
  ts.it_interval.tv_sec = (time_t)(interval / 1000000000);
  ts.it_interval.tv_nsec = interval % 1000000000;

  /*
   * 타이머를 생성한다.
   */
  bsm_tx->timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (bsm_tx->timer_fd < 0) {
    Err("Fail to create BSM transmit timer - timerfd_create() failed - %m\n");
    return -kJ29451Result_FailToCreateTimer;
  }

  /*
   * 타이머 주기를 설정한다.
   */
  int ret = timerfd_settime(bsm_tx->timer_fd, TFD_TIMER_ABSTIME, &ts, NULL);
  if (ret < 0) {
    Err("Fail to create BSM transmit timer - timerfd_settime() failed - %m\n");
    return -kJ29451Result_FailToCreateTimer;
  }

  Log(kJ29451LogLevel_Event, "Success to create BSM transmit timer\n");
  return kJ29451Result_Success;
}


/**
 * @brief BSM 송신 쓰레드 루틴
 * @param[in] arg 사용되지 않는다.
 */
static void * j29451_BSMTransmitThread(void *arg)
{
  (void)arg;
  struct J29451BSMTx *bsm_tx = &(g_j29451_mib.bsm_tx);
  bsm_tx->thread_running = true;
  Log(kJ29451LogLevel_Event, "Success to start BSM transmit thread\n");

  /*
   * 최적 GNSS 데이터 업데이트시작 오프셋 추정이 완료될 때까지 대기한다.
   * 대가 중, BSM 전송 중지 요청을 받으면 쓰레드를 종료한다.
   */
  while (1) {
    if ((bsm_tx->thread_exit) ||
        j29451_CheckOptimalGNSSDataUpdateStartOffsetEstimation()) {
      break;
    }
    sleep(1);
  }
  if (bsm_tx->thread_exit) {
    goto out;
  }

  /*
   * GNSS 데이터 선택모드 및 GNSS 데이터 버퍼 내 "처리" 관련 정보를 초기화한다.
   */
  j29451_InitGNSSDataSelectionMode();
  j29451_InitGNSSDataBufProcessInfo();

  /*
   * BSM 전송 타이머를 생성한다.
   */
  if (j29451_CreateBSMTransmitTimer() < 0) {
    goto out;
  }

  /*
   * 루프를 돌며 타이머 만기 이벤트를 처리한다.
   */
  uint64_t exp;
  uint8_t *bsm = NULL;
  size_t bsm_size = 0;
  bool event = false, cert_sign = false, id_change = false;
  uint8_t addr[MAC_ALEN];
  ssize_t s;
  while (1) {
    s = read(bsm_tx->timer_fd, &exp, sizeof(uint64_t));
    if (s == sizeof(uint64_t)) {
      if (bsm_tx->thread_exit) {
        break;
      }
      bsm = j29451_PrepareBSM(&bsm_size, &event, &cert_sign, &id_change, addr);
      if (bsm) {
        free(bsm);
      }else{
				printf("j29451_BSMTransmitThread: Failed to prepare BSM\n");
			}
			struct J29451GNSSDataBufEntry *e, *tmp;
			TAILQ_FOREACH_SAFE(e, &g_cleanup_head, entries, tmp) {
				TAILQ_REMOVE(&g_cleanup_head, e, entries);
				free(e);_DEBUG_LINE
			}
    }
  }

  Log(kJ29451LogLevel_Event, "BSM transmit thread exit\n");

out:
  bsm_tx->thread_running = false;
  return NULL;
}


/**
 * @brief BSM 송신 동작을 시작한다.
 * @param[in] bsm_tx BSM 송신 관련 정보
 * @param[in] tx_interval 송신주기
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int INTERNAL j29451_StartBSMTransmit(struct J29451BSMTx *bsm_tx, J29451BSMTxInterval tx_interval)
{
  Log(kJ29451LogLevel_Event, "Start BSM transmit\n");

  /*
   * 이미 전송 중이면 실패를 반환한다.
   */
  if (bsm_tx->thread_running == true) {
    Err("Fail to start BSM transmit - already transmitting\n");
    return -kJ29451Result_Busy;
  }
  bsm_tx->thread_exit = false;

  /*
   * 전송 주기를 저장한다.
   */
  bsm_tx->tx_interval = tx_interval;

  /*
   * BSM 송신 쓰레드를 생성한다.
   */
  int ret = -kJ29451Result_FailToCreateThread;
  if (pthread_create(&(bsm_tx->thread), NULL, j29451_BSMTransmitThread, NULL) == 0) {
    struct timespec req = {.tv_sec = 0, .tv_nsec = 10000000}, rem;
    while (bsm_tx->thread_running == false) {
      nanosleep(&req, &rem);
    }
    ret = kJ29451Result_Success;
  }
  return ret;
}


/**
 * @brief BSM 송신을 종료한다.
 * @param[in] bsm_tx BSM 송신 관련 정보
 *
 * @note 뮤텍스락 락 상태에서 호출 시 전송 쓰레드와의 데드락 상황에 빠질 수 있으므로, 언락 상태에서 호출되어야 한다.
 */
void INTERNAL j29451_StopBSMTransmit(struct J29451BSMTx *bsm_tx)
{
  Log(kJ29451LogLevel_Event, "Stop BSM transmit\n");

  /*
   * 전송 쓰레드를 종료시킨다.
   */
  if (bsm_tx->thread_running == true) {
    bsm_tx->thread_exit = true;
    pthread_join(bsm_tx->thread, NULL);
    if (bsm_tx->timer_fd) {
      close(bsm_tx->timer_fd);
    }
  }

  /*
   * ID 변경 파라미터를 초기화한다.
   */
  bsm_tx->id_change.initial_pos.lat_deg = NAN;
  bsm_tx->id_change.initial_pos.lon_deg = NAN;
  bsm_tx->id_change.initial_time = 0;
}
