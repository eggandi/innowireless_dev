/**
 * @file
 * @brief
 * @date 2020-07-31
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#include "dot3-mib.h"


/**
 * @brief UAS 정보가 만기되었는지 확인한다.
 * @param[in] entry UAS 정보 엔트리
 * @param[in] current_sec 현재시각(초값)
 * @retval true: 만기됨
 * @retval false: 만기되지 않음
 */
static inline bool dot3_UASExpired(struct Dot3UASTableEntry *entry, time_t current_sec)
{
  return (entry->expiry <= current_sec);
}


/**
 * @brief 관리타이머 만기시점에 UAS의 유효성을 업데이트한다.
 * @param[in] table UAS 테이블
 * @param[out] entry 업데이트할 UAS
 */
static inline void dot3_UpdateUASAvailableFromTimer(struct Dot3UASTable *table, struct Dot3UASTableEntry *entry)
{
  struct Dot3UAS *uas = &(entry->uas);

  /*
   * 유효성을 판단하기 위해 WSA 수신카운트를 사용하지 않는 경우, 유효성 판단을 수행하지 않는다.
   * 이 경우 유효성 판단은 WSA 수신시점에만 수행된다.
   */
  if (entry->check_rx_cnt == false) {
    return;
  }

  /*
   * 아직 체크 시점에 도달하지 못했으면 유효성 판단을 수행하지 않는다.
   *  - 100msec 단위 인터벌 발생 회수가 UAS의 WSA count threshold interval보다는 커야 유효성 판단이 가능하다.
   */
  entry->unit_interval_cnt += table->timer_interval;
  if (entry->unit_interval_cnt < uas->wsa_cnt_threshold_interval) {
    return;
  }

  double rx_cnt_in_unit_interval = entry->rx_cnt_in_mgmt_timer_interval / (double)(table->timer_interval);
  double target_rx_cnt_in_unit_interval = (double)(uas->wsa_cnt_threshold) / (double)(uas->wsa_cnt_threshold_interval);

  /*
   * 유효성을 판단하기 위해 RCPI 기준값을 사용하지 않는 경우, 수신카운트와 기준값을 비교하여 유효 여부를 판단한다.
   */
  if (uas->present.rcpi_threshold == false) {
    if (rx_cnt_in_unit_interval >= target_rx_cnt_in_unit_interval) {
      Log(kDot3LogLevel_Event, "UAS status -> available (no rcpi threshold and high rx count): %.2f >= %.2f\n",
          rx_cnt_in_unit_interval, target_rx_cnt_in_unit_interval);
      uas->available = true;
    } else {
      Log(kDot3LogLevel_Event, "UAS status -> unavailable (no rcpi threshold and low rx count): %.2f < %.2f\n",
          rx_cnt_in_unit_interval, target_rx_cnt_in_unit_interval);
      uas->available = false;
    }
  }

  /*
   * 유효성을 판단하기 위해 RCPI 기준값을 사용하는 경우, RCPI와 수신카운트 모두에 대해 유효 여부를 체크한다.
   */
  else {
    if ((uas->rcpi >= uas->rcpi_threshold) &&
        (rx_cnt_in_unit_interval >= target_rx_cnt_in_unit_interval)) {
      Log(kDot3LogLevel_Event, "UAS status -> available (high rcpi threshold and high rx count): %.2f >= %.2f\n",
          rx_cnt_in_unit_interval, target_rx_cnt_in_unit_interval);
      uas->available = true;
    } else {
      Log(kDot3LogLevel_Event, "UAS status -> unavailable (low rcpi threshold or low rx count): %.2f < %.2f\n",
          rx_cnt_in_unit_interval, target_rx_cnt_in_unit_interval);
      uas->available = false;
    }
  }

  /*
   * 체크할 값을 초기화한다.
   */
  entry->unit_interval_cnt = 0;
  entry->rx_cnt_in_mgmt_timer_interval = 0;
}


/**
 * @brief UAS 관리타이머 만기쓰레드 함수
 * @param[in] not_used 사용되지 않음
 *
 * 관리타이머 만기 시마다 호출되며, 다음 두 동작을 수행한다.
 *  - 만기된 UAS 엔트리를 삭제한다.
 *  - WSA count threshold에 따른 UAS의 유효성을 결정한다.
 */
static void dot3_UASManagementTimerThread(union sigval not_used)
{
  (void)not_used;
  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  struct Dot3UASTable *table = &(g_dot3_mib.user_info.uas_table);
  struct Dot3UASTableEntry *entry, *tmp;
  struct timespec ts;

  pthread_mutex_lock(&(uinfo->mtx));

  /*
   * UAS 테이블 내의 각 엔트리에 대해;
   *  - 만기시각이 지난 엔트리는 삭제한다.
   *  - WSA 수신회수와 threshold 값을 비교하여 정보의 유효성을 업데이트한다.
   */
  clock_gettime(CLOCK_REALTIME, &ts);
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp)
  {
    // 만기된 UAS는 제거한다.
    if (dot3_UASExpired(entry, ts.tv_sec) == true) {
      TAILQ_REMOVE(&(table->head), entry, entries);
      if (entry->wsa) {
        free(entry->wsa);
      }
      free(entry);
      table->num--;
      continue;
    }

    // UAS 정보의 유효성을 업데이트한다.
    dot3_UpdateUASAvailableFromTimer(table, entry);
  }

  pthread_mutex_unlock(&(uinfo->mtx));
}


/**
 * @brief UAS 관리타이머를 시작한다.
 * @param[in] table UAS 테이블
 * @param[in] interval 관리(타이머) 주기
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_StartUASManagementTimer(struct Dot3UASTable *table, Dot3UASManagementInterval interval)
{
  Log(kDot3LogLevel_Event, "Start UAS management timer\n");

  /*
   * 타이머 만기 시 타이머쓰레드(dot3_UASManagementTimerThread)가 생성되도록 설정한다.
   */
  struct sigevent se;
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = &(table->timer);
  se.sigev_notify_function = dot3_UASManagementTimerThread;
  se.sigev_notify_attributes = NULL;
  int ret = timer_create(CLOCK_MONOTONIC, &se, &(table->timer));
  if (ret == -1) {
    Err("Fail to Start UAS management timer - timer_create() failed: %m\n");
    return -kDot3Result_SystemCallFailed;
  }

  /*
   * 타이머 주기를 설정한다.
   */
  ret = dot3_SetUASManagementTimerInterval(table, interval);
  if (ret < 0) {
    timer_delete(table->timer);
    return -kDot3Result_SystemCallFailed;
  }

  Log(kDot3LogLevel_Event, "Success to start UAS management timer\n");
  return kDot3Result_Success;
}


/**
 * @brief UAS 관리 기능을 시작한다(대응 함수: dot3_StopUASManagementFunction()).
 * @param[in] table UAS 테이블
 * @param[in] interval 관리(타이머) 주기
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_StartUASManagementFunction(struct Dot3UASTable *table, Dot3UASManagementInterval interval)
{
  Log(kDot3LogLevel_Event, "Start UAS management function\n");

  /*
   * 관리 기능이 이미 동작 중이면 그냥 리턴한다.
   */
  if (table->mgmt_running == true) {
    Log(kDot3LogLevel_Event, "UAS management function is already running\n");
    return -kDot3Result_AlreadyRunning;
  }

  /*
   * 관리 타이머를 시작한다.
   */
  int ret = dot3_StartUASManagementTimer(table, interval);
  if (ret < 0) {
    return ret;
  }

  table->mgmt_running = true;
  Log(kDot3LogLevel_Event, "Success to initialize UAS management function\n");
  return kDot3Result_Success;
}


/**
 * @brief UAS 관리 기능을 중지한다(대응 함수: dot3_StartUASManagementFunction()).
 * @param[in] table UAS 테이블
 */
void INTERNAL dot3_StopUASManagementFunction(struct Dot3UASTable *table)
{
  Log(kDot3LogLevel_Event, "Stop UAS management function\n");

  /*
   * 관리 기능이 동작 중이 아니면 그냥 리턴한다.
   */
  if (table->mgmt_running == false) {
    Log(kDot3LogLevel_Event, "UAS management function is not running\n");
    return;
  }

  /*
   * 타이머를 해제한다.
   */
  timer_delete(table->timer);
  table->timer_interval = 0;

  table->mgmt_running = false;
}


/**
 * @brief UAS 관리 타이머의 주기를 (재)설정한다.
 * @param[in] table UAS 테이블
 * @param[in] interval 타이머 주기
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_SetUASManagementTimerInterval(struct Dot3UASTable *table, Dot3UASManagementInterval interval)
{
  Log(kDot3LogLevel_Event, "Set UAS management timer interval as %u * 100msec\n", interval);

  unsigned int msec = interval * 100;

  struct itimerspec ts;
  ts.it_value.tv_sec = (time_t)(msec / 1000);
  ts.it_value.tv_nsec = (long)((msec % 1000) * 1000000);
  ts.it_interval.tv_sec = (time_t)(msec / 1000);
  ts.it_interval.tv_nsec = (long)((msec % 1000) * 1000000);
  int ret = timer_settime(table->timer, 0, &ts, NULL);
  if (ret == -1) {
    Err("Fail to set UAS management timer interval - timer_settimer() failed: %m\n");
    return -kDot3Result_SystemCallFailed;
  }
  table->timer_interval = interval;

  Log(kDot3LogLevel_Event, "Success to set UAS management timer interval\n");
  return kDot3Result_Success;
}
