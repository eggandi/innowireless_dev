/**
 * @file
 * @brief GNSS 데이터 버퍼관련 기능 구현
 * @date 2023-04-03
 * @author gyun
 */


// 시스템 헤더파일
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 의존 헤더파일
#include <sudo_queue.h>

// 라이브러리 내부 헤더파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"

TAILQ_HEAD(CleanupHead, J29451GNSSDataBufEntry) cleanup_head = TAILQ_HEAD_INITIALIZER(cleanup_head);

static void enqueue_for_cleanup(struct J29451GNSSDataBufEntry *e)
{
  // 이 시점에 e->entries 리스트 포인터가 꼬이지 않도록 주의
	TAILQ_INSERT_TAIL(&cleanup_head, e, entries);_DEBUG_LINE
}

void j29451_PerformCleanup(void)
{
  struct J29451GNSSDataBufEntry *e, *tmp;_DEBUG_LINE
	struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
	printf("buf->entry_num: %d\n", buf->entry_num);_DEBUG_LINE
  TAILQ_FOREACH_SAFE(e, &cleanup_head, entries, tmp) {
		printf("e: %p, e->ref_count: %d, e->gen_msec: %"PRIu64"\n", e, e->ref_count, e->gen_msec);_DEBUG_LINE
		if(e->ref_count == 0){
			TAILQ_REMOVE(&cleanup_head, e, entries);_DEBUG_LINE
			e->gen_msec = 0;_DEBUG_LINE
			memset(&(e->gnss), 0, sizeof(struct J29451GNSSData));_DEBUG_LINE
			free(e);_DEBUG_LINE
			e = NULL;
		}
   
  }
}

void *j29451_PerformCleanup_Th(void *arg)
{
	arg = arg;_DEBUG_LINE
  while (1) 
	{
		sleep(1);_DEBUG_LINE
    j29451_PerformCleanup();_DEBUG_LINE
  }
}

/**
 * @brief GNSS 데이터 버퍼를 초기화한다.
 */
void INTERNAL j29451_InitGNSSDataBuf(void)
{
  memset(&(g_j29451_mib.obu.gnss.gnss_data_buf), 0, sizeof(struct J29451GNSSDataBuf));_DEBUG_LINE
  TAILQ_INIT(&(g_j29451_mib.obu.gnss.gnss_data_buf.head));_DEBUG_LINE
	pthread_t cleanup_thread;_DEBUG_LINE
	if (pthread_create(&cleanup_thread, NULL, j29451_PerformCleanup_Th, NULL) != 0) {
		Log(kJ29451LogLevel_Err, "Failed to create cleanup thread\n");_DEBUG_LINE
	} else {
		pthread_detach(cleanup_thread);_DEBUG_LINE
	}
	Log(kJ29451LogLevel_Event, "Initialized GNSS data buf\n");_DEBUG_LINE
}


/**
 * @brief GNSS 데이터 버퍼를 비운다.
 */
void INTERNAL j29451_FlushGNSSDataBuf(void)
{
  Log(kJ29451LogLevel_Event, "Flush GNSS data buf\n");_DEBUG_LINE
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
  struct J29451GNSSDataBufEntry *entry, *tmp;_DEBUG_LINE
  TAILQ_FOREACH_SAFE(entry, &(buf->head), entries, tmp) {
    TAILQ_REMOVE(&(buf->head), entry, entries);_DEBUG_LINE
		atomic_fetch_sub(&entry->ref_count, 1);_DEBUG_LINE
    enqueue_for_cleanup(entry);_DEBUG_LINE
  }
  buf->entry_num = 0;_DEBUG_LINE
  buf->proc.prev = NULL;_DEBUG_LINE
  buf->proc.recent = NULL;_DEBUG_LINE
}


/**
 * @brief GNSS 데이터 버퍼 엔트리를 버퍼에 추가한다.
 * @return 추가된 GNSS 데이터 버퍼 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_AddGNSSDataBufEntry(void)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
  struct J29451GNSSDataBufEntry *entry = calloc(1, sizeof(struct J29451GNSSDataBufEntry));_DEBUG_LINE
  if (entry) {
		entry->ref_count = 0;
		atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
    // 버퍼가 가득 차 있으면, 가장 오래된 엔트리를 제거한다.
    if (buf->entry_num == kJ29451GNSSDataBufEntryNum_Max) {
      /* 누수 지점 young@KETI */
      struct J29451GNSSDataBufEntry *first_entry = TAILQ_FIRST(&(buf->head));_DEBUG_LINE
      TAILQ_REMOVE(&(buf->head), first_entry, entries);_DEBUG_LINE
			atomic_fetch_sub(&first_entry->ref_count, 1);_DEBUG_LINE
      buf->entry_num--;_DEBUG_LINE
      enqueue_for_cleanup(first_entry);_DEBUG_LINE
    }
    entry->gen_msec = j29451_GetCurrentMsecMonotonic();_DEBUG_LINE
    TAILQ_INSERT_TAIL(&(buf->head), entry, entries);_DEBUG_LINE
    buf->entry_num++;_DEBUG_LINE
  }
  return entry;_DEBUG_LINE
}


/**
 * @brief 버퍼 내 특정 GNSS 데이터 버퍼 엔트리 뒤에 새로운 엔트리를 추가한다.
 * @parma[in] 대상 GNSS 데이터 버퍼 엔트리
 * @return 추가된 GNSS 데이터 버퍼 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_AddAfterGNSSDataBufEntry(struct J29451GNSSDataBufEntry *entry)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
  struct J29451GNSSDataBufEntry *next = calloc(1, sizeof(struct J29451GNSSDataBufEntry));_DEBUG_LINE
  if (next) {
		next->ref_count = 0;
		atomic_fetch_add(&next->ref_count, 1);_DEBUG_LINE
    // 버퍼가 가득 차 있으면, 가장 오래된 엔트리를 제거한다.
    if (buf->entry_num == kJ29451GNSSDataBufEntryNum_Max) {
			struct J29451GNSSDataBufEntry *first_entry = TAILQ_FIRST(&(buf->head));_DEBUG_LINE
      TAILQ_REMOVE(&(buf->head), first_entry, entries);_DEBUG_LINE
			atomic_fetch_sub(&first_entry->ref_count, 1);_DEBUG_LINE
      buf->entry_num--;_DEBUG_LINE
			enqueue_for_cleanup(first_entry);_DEBUG_LINE
    }
    next->gen_msec = j29451_GetCurrentMsecMonotonic();_DEBUG_LINE
    TAILQ_INSERT_AFTER(&(buf->head), entry, next, entries);_DEBUG_LINE
    buf->entry_num++;_DEBUG_LINE
  }
  return next;_DEBUG_LINE
}


/**
 * @brief GNSS 데이터 정보를 업데이트/저장할 GNSS 데이터 버퍼 엔트리를 반환한다.
 * @param[in] gps_data gpsd로부터 읽어들인 GPS 데이터
 * @return 버퍼 엔트리 포인터
 *
 * gpsdata의 epoch time 값이 동일하면, 최근에 업데이트하던 버퍼 엔트리를 반환한다.
 * gpsdata의 epoch time 값이 변경되었으면, 새로운 버퍼 엔트리를 반환한다.
 */
struct J29451GNSSDataBufEntry INTERNAL * j29451_GetGNSSDataBufEntryToUpdate(struct gps_data_t *gps_data)
{
  uint64_t epoch_msec = j29451_ConvertTimespecToMilliseconds(&(gps_data->fix.time));_DEBUG_LINE

  // 프로그램 실행 후 최초 호출이면(last entry=NULL), 새로운 엔트리를 생성하여 반환한다.
  // 새로운 epoch 구간의 정보이면 새로운 엔트리를 할당하여 반환하고 그렇지 않으면 최근에 업데이트하던 엔트리를 그대로 반환한다.
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
  struct J29451GNSSDataBufEntry *entry = TAILQ_LAST(&(buf->head), J29451GNSSDataBufEntryHead); // 버퍼 내 마지막 엔트리(=최근 엔트리)
  if (!entry) {
    entry = j29451_AddGNSSDataBufEntry();_DEBUG_LINE
  } else {
    if (epoch_msec > entry->gnss.time) {
      entry = j29451_AddGNSSDataBufEntry();_DEBUG_LINE
    }
  }
  return entry;_DEBUG_LINE
}


/**
 * @brief GNSS 데이터 버퍼에서 특정 엔트리를 제거한다.
 * @param[in] entry 제거할 엔트리
 */
static void j29451_RemoveGNSSDataBufEntry(struct J29451GNSSDataBufEntry *entry)
{
  TAILQ_REMOVE(&(g_j29451_mib.obu.gnss.gnss_data_buf.head), entry, entries);_DEBUG_LINE
	atomic_fetch_sub(&entry->ref_count, 1);_DEBUG_LINE
  enqueue_for_cleanup(entry);_DEBUG_LINE
  g_j29451_mib.obu.gnss.gnss_data_buf.entry_num--;_DEBUG_LINE
}


/**
 * @brief GNSS 데이터 버퍼 내에서 특정 엔트리보다 앞쪽에 저장된(=과거의) 엔트리들을 모두 제거한다.
 * @param[in] entry 기준 엔트리
 */
static void j29451_RemoveAllPrevGNSSDataBufEntry(struct J29451GNSSDataBufEntry *entry)
{
  struct J29451GNSSDataBufEntry *tmp1, *tmp2;_DEBUG_LINE
  TAILQ_FOREACH_SAFE(tmp1, &(g_j29451_mib.obu.gnss.gnss_data_buf.head), entries, tmp2) {
		atomic_fetch_add(&tmp1->ref_count, 1);_DEBUG_LINE
    if (tmp1 == entry) {
			atomic_fetch_sub(&tmp1->ref_count, 1);_DEBUG_LINE
      break;_DEBUG_LINE
    }
    j29451_RemoveGNSSDataBufEntry(tmp1);_DEBUG_LINE
		atomic_fetch_sub(&tmp1->ref_count, 1);_DEBUG_LINE
  }
}


/**
 * @brief 버퍼 내 특정 GNSS 데이터 엔트리를 복제해서 바로 뒤에 추가한다.
 * @param[in] from 복제할 GNSS 데이터 엔트리
 * @param[in] interval 복제된 엔트리와 기존 엔트리의 시간 간격 (밀리초 단위)
 * @return 생성/복제된 GNSS 데이터 엔트리
 */
static struct J29451GNSSDataBufEntry *
j29451_CloneAndAddGNSSDataBufEntry(struct J29451GNSSDataBufEntry *from, unsigned int interval)
{
  struct J29451GNSSDataBufEntry *to = j29451_AddAfterGNSSDataBufEntry(from);_DEBUG_LINE
  if (to) {
    memcpy(&(to->gnss), &(from->gnss), sizeof(struct J29451GNSSData));_DEBUG_LINE
		printf("to->ref_count: %d, from->ref_count: %d\n", to->ref_count, from->ref_count);_DEBUG_LINE
    to->gnss.time += (uint64_t)interval; // 복제된 엔트리의 epoch time을 강제로 증가시킨다.
    to->gnss.msec = j29451_ConvertMillisecondsToDSecond(to->gnss.time);_DEBUG_LINE
  }
  return to;_DEBUG_LINE
}


/**
 * @brief Recent 모드에서, GNSS 데이터 버퍼에서 처리할 엔트리를 반환한다.
 * @return 처리할 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_GetNextGNSSDataBufEntryInRecentMode(void)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
  struct J29451GNSSDataBufEntry *entry, *prev = buf->proc.recent;_DEBUG_LINE

  /*
   * 프로그램 실행 후 처음으로 엔트리를 처리하는 경우, 버퍼의 가장 마지막 엔트리를 선택한다.
  */
  if (!prev) {
    entry = TAILQ_LAST(&(buf->head), J29451GNSSDataBufEntryHead);_DEBUG_LINE
    if (entry) {
			atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (사용될 일 없는 오래된 엔트리 제거)
      prev = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);_DEBUG_LINE
      if (prev) {
				atomic_fetch_add(&prev->ref_count, 1);_DEBUG_LINE
        j29451_RemoveAllPrevGNSSDataBufEntry(prev);_DEBUG_LINE
				atomic_fetch_sub(&prev->ref_count, 1);_DEBUG_LINE
      } else {
        // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 GNSS 데이터가 항상 2개 이상(=prev가 존재) 있다고 간주한다.
        Err("[ABNORMAL] [First] No prev entry of recent entry(epoch: %"PRIu64") in gnss data buf\n", entry->gnss.time);_DEBUG_LINE
      }
      assert(prev);_DEBUG_LINE
    } else {
      // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 버퍼 내에 GNSS 데이터가 항상 있다고 간주한다.
      Err("[ABNORMAL] [First] No entry in gnss data buf\n");_DEBUG_LINE
    }
    assert(entry);_DEBUG_LINE
  }

  /*
   * 두번째 엔트리 처리부터는, 직전주기에 처리했던 recent 엔트리의 다음 엔트리를 선택한다.
   * GNSS 데이터 선택모드(Recent) 메커니즘이 정상동작한다면, 직전주기에 recent 엔트리를 처리한 후에 버퍼 내에 1개의 GNSS 데이터가 추가되어 있어야 한다.
   * 동작 중에 GNSS fix가 해제되는 경우, 직전주기에 처리했던 recent 엔트리 이후에 새로운 엔트리가 추가되어 있지 않을 수 있다.
   * 이 경우, 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다.
   */
  else {
		atomic_fetch_add(&prev->ref_count, 1);_DEBUG_LINE
    entry = TAILQ_NEXT(prev, entries);_DEBUG_LINE
    if (entry) {
			atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (더이상 사용될 일 없는 오래된 엔트리 제거)
      j29451_RemoveAllPrevGNSSDataBufEntry(prev);_DEBUG_LINE
			atomic_fetch_sub(&entry->ref_count, 1);_DEBUG_LINE

    } else {
      Err("Probably the GNSS signal is not fixed - No next entry of prev recent(epoch: %"PRIu64", total entry: %u)\n",
          prev->gnss.time, buf->entry_num);_DEBUG_LINE
      // 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다. (직전데이터 재활용, 시간값만 강제로 증가)
    }
		entry = j29451_CloneAndAddGNSSDataBufEntry(prev, g_j29451_mib.bsm_tx.tx_interval);_DEBUG_LINE
    assert(entry);_DEBUG_LINE
		atomic_fetch_sub(&prev->ref_count, 1);_DEBUG_LINE
  }

  buf->proc.prev = prev;_DEBUG_LINE
  buf->proc.recent = entry;_DEBUG_LINE
  return entry;_DEBUG_LINE
}


/**
 * @brief Safe 모드에서, GNSS 데이터 버퍼에서 처리할 엔트리를 반환한다.
 * @return 처리할 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_GetNextGNSSDataBufEntryInSafeMode(void)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);_DEBUG_LINE
  struct J29451GNSSDataBufEntry *entry, *prev = buf->proc.recent;_DEBUG_LINE
  /*
   * 프로그램 실행 후 처음으로 엔트리를 처리하는 경우, 버퍼의 가장 마지막 엔트리를 선택하되,
   * 마지막 엔트리의 생성시각이 현시점으로부터 epoch 반주기보다 과거의 정보가 아니면, 그 직전 엔트리를 선택한다.
   */
  if (!prev) {
    entry = TAILQ_LAST(&(buf->head), J29451GNSSDataBufEntryHead);_DEBUG_LINE
    if (entry) {
			atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
      // 마지막 엔트리의 생성시각이 현시점으로부터 epoch 반주기보다 과거의 정보가 아니면, 그 직전 엔트리를 선택한다.
      uint64_t current_msec = j29451_GetCurrentMsecMonotonic();_DEBUG_LINE
      if ((current_msec - entry->gen_msec) < (GNSS_EPOCH_INTERVAL_MSEC / 2)) {
        struct J29451GNSSDataBufEntry *entry_prev = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);_DEBUG_LINE
        if (!entry_prev) {
          // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 GNSS 데이터가 항상 2개 이상 있다고 간주한다.
          Err("[ABNORMAL] No previous entry of last entry in gnss data buf\n");_DEBUG_LINE
        }else{
					atomic_fetch_sub(&entry->ref_count, 1);_DEBUG_LINE
					atomic_fetch_add(&entry_prev->ref_count, 1);_DEBUG_LINE
					entry = entry_prev;_DEBUG_LINE
				}
        assert(entry);_DEBUG_LINE
      }
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (사용될 일 없는 오래된 엔트리 제거)
      prev = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);_DEBUG_LINE
      if (prev) {
				atomic_fetch_add(&prev->ref_count, 1);_DEBUG_LINE
        j29451_RemoveAllPrevGNSSDataBufEntry(prev);_DEBUG_LINE
				atomic_fetch_sub(&prev->ref_count, 1);_DEBUG_LINE
      } else {
        // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 GNSS 데이터가 항상 3개 이상 있다고 간주한다.
        Err("[ABNORMAL] [First] No prev entry of recent entry(epoch: %"PRIu64") in gnss data buf\n", entry->gnss.time);_DEBUG_LINE
      }
      assert(prev);_DEBUG_LINE
    } else {
      // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 버퍼 내에 GNSS 데이터가 항상 있다고 간주한다.
      Err("[ABNORMAL] [First] No entry in gnss data buf\n");_DEBUG_LINE
    }
    assert(entry);_DEBUG_LINE
  }

  /*
   * 두번째 엔트리 처리부터는, 직전주기에 처리했던 recent 엔트리의 다음 엔트리를 선택한다.
   * GNSS 데이터 선택모드(Safe) 메커니즘이 정상동작한다면, 직전주기에 recent 엔트리를 처리한 후에 1~2개의 GNSS 데이터가 추가되어 있어야 한다.
   * 동작 중에 GNSS fix가 해제되는 경우, 직전주기에 처리했던 recent 엔트리 이후에 새로운 엔트리가 추가되어 있지 않을 수 있다.
   * 이 경우, 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다.
   */
  else {
		atomic_fetch_add(&prev->ref_count, 1);_DEBUG_LINE
    entry = TAILQ_NEXT(prev, entries);_DEBUG_LINE
    if (entry) {
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (더이상 사용될 일 없는 오래된 엔트리 제거)
			atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
      j29451_RemoveAllPrevGNSSDataBufEntry(prev);_DEBUG_LINE
      // prev와 entry간 epoch time이 순차적으로 증가하지 않았으면, 두 엔트리 사이에 새로운 엔트리를 복제/추가하고 이를 사용한다. (직전데이터 재활용, 시간값만 강제로 증가)
      // 이는 GNSS fix가 해제된 상태에서 다시 fix 되었을 때, Safe 모드에서 발생할 수 있는 현상에 대처하기 위함이다)
      if (j29451_CheckGNSSDataBufEntryEpochTimeIncrease(entry) == false) {
        entry = j29451_CloneAndAddGNSSDataBufEntry(prev, g_j29451_mib.bsm_tx.tx_interval);_DEBUG_LINE
      }
    } else {
      Err("Probably the GNSS signal is not fixed - No next entry of prev recent(epoch: %"PRIu64", total entry: %u)\n",
          prev->gnss.time, buf->entry_num);_DEBUG_LINE
      // 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다. (직전데이터 재활용, 시간값만 강제로 증가)
      entry = j29451_CloneAndAddGNSSDataBufEntry(prev, g_j29451_mib.bsm_tx.tx_interval);_DEBUG_LINE
			atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
    }
    assert(entry);_DEBUG_LINE
		atomic_fetch_sub(&prev->ref_count, 1);_DEBUG_LINE
  }

  buf->proc.prev = prev;_DEBUG_LINE
  buf->proc.recent = entry;_DEBUG_LINE
  return entry;_DEBUG_LINE
}


/**
 * @brief 처리하고자 하는 GNSS 데이터 버퍼 엔트리를 반환한다.
 * @return GNSS 데이터 버퍼 엔트리
 */
struct J29451GNSSDataBufEntry INTERNAL * j29451_GetGNSSDataBufEntryToProcess(void)
{
  struct J29451GNSSDataBufEntry *entry;_DEBUG_LINE
	
  if (g_j29451_mib.obu.gnss.gnss_data_sel_mode == kJ29451GNSSDataSelectionMode_Recent) {
    entry = j29451_GetNextGNSSDataBufEntryInRecentMode();_DEBUG_LINE
		printf("entry: %p, entry->ref_count: %d\n", entry, entry->ref_count);_DEBUG_LINE
  } else {
    entry = j29451_GetNextGNSSDataBufEntryInSafeMode();_DEBUG_LINE
		printf("entry: %p, entry->ref_count: %d\n", entry, entry->ref_count);_DEBUG_LINE

  }
  if (entry) {
		atomic_fetch_add(&entry->ref_count, 1);_DEBUG_LINE
    j29451_CheckGNSSDataBufEntryEpochTimeIncrease(entry);_DEBUG_LINE
		atomic_fetch_sub(&entry->ref_count, 1);_DEBUG_LINE
	} 
  return entry;_DEBUG_LINE
}


/**
 * @brief GNSS 데이터 버퍼 내 "처리" 관련 정보를 초기화한다.
 */
void INTERNAL j29451_InitGNSSDataBufProcessInfo(void)
{
  g_j29451_mib.obu.gnss.gnss_data_buf.proc.prev = NULL;_DEBUG_LINE
  g_j29451_mib.obu.gnss.gnss_data_buf.proc.recent = NULL;_DEBUG_LINE
}
