/**
 * @file
 * @brief GNSS 데이터 버퍼관련 기능 구현
 * @date 2023-04-03
 * @author gyun
 */


// 시스템 헤더파일
#include <stdlib.h>
#include <string.h>

// 의존 헤더파일
#include <sudo_queue.h>

// 라이브러리 내부 헤더파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"


/**
 * @brief GNSS 데이터 버퍼를 초기화한다.
 */
void INTERNAL j29451_InitGNSSDataBuf(void)
{
  memset(&(g_j29451_mib.obu.gnss.gnss_data_buf), 0, sizeof(struct J29451GNSSDataBuf));
  TAILQ_INIT(&(g_j29451_mib.obu.gnss.gnss_data_buf.head));
}


/**
 * @brief GNSS 데이터 버퍼를 비운다.
 */
void INTERNAL j29451_FlushGNSSDataBuf(void)
{
  Log(kJ29451LogLevel_Event, "Flush GNSS data buf\n");
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
  struct J29451GNSSDataBufEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(buf->head), entries, tmp) {
		/* 20250622 누수 원인 proc.recent eggandi@KETI */
		if(entry != buf->proc.recent || entry != buf->proc.prev)
		{
			TAILQ_REMOVE(&(buf->head), entry, entries);
			free(entry);
		}
  }
	buf->entry_num = 0;
  buf->proc.prev = NULL;
  buf->proc.recent = NULL;
}


/**
 * @brief GNSS 데이터 버퍼 엔트리를 버퍼에 추가한다.
 * @return 추가된 GNSS 데이터 버퍼 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_AddGNSSDataBufEntry(void)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
  struct J29451GNSSDataBufEntry *entry = calloc(1, sizeof(struct J29451GNSSDataBufEntry));
  if (entry) {
    // 버퍼가 가득 차 있으면, 가장 오래된 엔트리를 제거한다.
    if (buf->entry_num == kJ29451GNSSDataBufEntryNum_Max) {
      /* 누수 지점 young@KETI */
      struct J29451GNSSDataBufEntry *first_entry = TAILQ_FIRST(&(buf->head));
			/* 20250622 누수 관련 수정 eggandi@KETI */
			if(first_entry == buf->proc.prev) {
				buf->proc.prev = TAILQ_NEXT(first_entry, entries); // proc.prev가 entry를 가리키고 있으면 NULL로 초기화
			}
			/* 20250622 누수 원인 proc.recent eggandi@KETI */
			if(first_entry == buf->proc.recent) {
				buf->proc.recent = TAILQ_NEXT(first_entry, entries); // proc.recent가 entry를 가리키고 있으면 NULL로 초기화
			}
			TAILQ_REMOVE(&(buf->head), first_entry, entries);
			buf->entry_num--;
      free(first_entry);
    }
    entry->gen_msec = j29451_GetCurrentMsecMonotonic();
    TAILQ_INSERT_TAIL(&(buf->head), entry, entries);
    buf->entry_num++;
  }
  return entry;
}


/**
 * @brief 버퍼 내 특정 GNSS 데이터 버퍼 엔트리 뒤에 새로운 엔트리를 추가한다.
 * @parma[in] 대상 GNSS 데이터 버퍼 엔트리
 * @return 추가된 GNSS 데이터 버퍼 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_AddAfterGNSSDataBufEntry(struct J29451GNSSDataBufEntry *entry)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
  struct J29451GNSSDataBufEntry *next = calloc(1, sizeof(struct J29451GNSSDataBufEntry));
  if (next) {
    // 버퍼가 가득 차 있으면, 가장 오래된 엔트리를 제거한다.
    if (buf->entry_num == kJ29451GNSSDataBufEntryNum_Max) {
      struct J29451GNSSDataBufEntry *first_entry = TAILQ_FIRST(&(buf->head));
			/* 20250622 누수 관련 수정 eggandi@KETI */
			if(first_entry == buf->proc.prev) {
				buf->proc.prev = TAILQ_NEXT(first_entry, entries); // proc.prev가 entry를 가리키고 있으면 NULL로 초기화
			}
			/* 20250622 누수 원인 proc.recent eggandi@KETI */
			if(first_entry == buf->proc.recent) {
				buf->proc.recent = TAILQ_NEXT(first_entry, entries); // proc.recent가 entry를 가리키고 있으면 NULL로 초기화
			}
			TAILQ_REMOVE(&(buf->head), first_entry, entries);
			buf->entry_num--;
      free(first_entry);
    }
    next->gen_msec = j29451_GetCurrentMsecMonotonic();
    TAILQ_INSERT_AFTER(&(buf->head), entry, next, entries);
    buf->entry_num++;
  }
  return next;
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
  uint64_t epoch_msec = j29451_ConvertTimespecToMilliseconds(&(gps_data->fix.time));

  // 프로그램 실행 후 최초 호출이면(last entry=NULL), 새로운 엔트리를 생성하여 반환한다.
  // 새로운 epoch 구간의 정보이면 새로운 엔트리를 할당하여 반환하고 그렇지 않으면 최근에 업데이트하던 엔트리를 그대로 반환한다.
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
  struct J29451GNSSDataBufEntry *entry = TAILQ_LAST(&(buf->head), J29451GNSSDataBufEntryHead); // 버퍼 내 마지막 엔트리(=최근 엔트리)
  if (!entry) {
    entry = j29451_AddGNSSDataBufEntry();
  } else {
    if (epoch_msec > entry->gnss.time) {
      entry = j29451_AddGNSSDataBufEntry();
    }
  }
  return entry;
}


/**
 * @brief GNSS 데이터 버퍼에서 특정 엔트리를 제거한다.
 * @param[in] entry 제거할 엔트리
 */
static void j29451_RemoveGNSSDataBufEntry(struct J29451GNSSDataBufEntry *entry)
{
	struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
	/* 20250622 누수 원인 proc.recent eggandi@KETI */
	if(entry != buf->proc.recent || entry != buf->proc.prev)
	{
		TAILQ_REMOVE(&(buf->head), entry, entries);
		free(entry);
		buf->entry_num--;
	}
}


/**
 * @brief GNSS 데이터 버퍼 내에서 특정 엔트리보다 앞쪽에 저장된(=과거의) 엔트리들을 모두 제거한다.
 * @param[in] entry 기준 엔트리
 */
static void j29451_RemoveAllPrevGNSSDataBufEntry(struct J29451GNSSDataBufEntry *entry)
{
  struct J29451GNSSDataBufEntry *tmp1, *tmp2;
  TAILQ_FOREACH_SAFE(tmp1, &(g_j29451_mib.obu.gnss.gnss_data_buf.head), entries, tmp2) {
    if (tmp1 == entry) {
      break;
    }
    j29451_RemoveGNSSDataBufEntry(tmp1);
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
  struct J29451GNSSDataBufEntry *to = j29451_AddAfterGNSSDataBufEntry(from);
  if (to) {
    memcpy(&(to->gnss), &(from->gnss), sizeof(struct J29451GNSSData));
    to->gnss.time += (uint64_t)interval; // 복제된 엔트리의 epoch time을 강제로 증가시킨다.
    to->gnss.msec = j29451_ConvertMillisecondsToDSecond(to->gnss.time);
  }
  return to;
}


/**
 * @brief Recent 모드에서, GNSS 데이터 버퍼에서 처리할 엔트리를 반환한다.
 * @return 처리할 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_GetNextGNSSDataBufEntryInRecentMode(void)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
  struct J29451GNSSDataBufEntry *entry, *prev = buf->proc.recent;

  /*
   * 프로그램 실행 후 처음으로 엔트리를 처리하는 경우, 버퍼의 가장 마지막 엔트리를 선택한다.
  */
  if (!prev) {
    entry = TAILQ_LAST(&(buf->head), J29451GNSSDataBufEntryHead);
    if (entry) {
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (사용될 일 없는 오래된 엔트리 제거)
      prev = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);
      if (prev) {
        j29451_RemoveAllPrevGNSSDataBufEntry(prev);
      } else {
        // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 GNSS 데이터가 항상 2개 이상(=prev가 존재) 있다고 간주한다.
        Err("[ABNORMAL] [First] No prev entry of recent entry(epoch: %"PRIu64") in gnss data buf\n", entry->gnss.time);
      }
      assert(prev);
    } else {
      // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 버퍼 내에 GNSS 데이터가 항상 있다고 간주한다.
      Err("[ABNORMAL] [First] No entry in gnss data buf\n");
    }
    assert(entry);
  }

  /*
   * 두번째 엔트리 처리부터는, 직전주기에 처리했던 recent 엔트리의 다음 엔트리를 선택한다.
   * GNSS 데이터 선택모드(Recent) 메커니즘이 정상동작한다면, 직전주기에 recent 엔트리를 처리한 후에 버퍼 내에 1개의 GNSS 데이터가 추가되어 있어야 한다.
   * 동작 중에 GNSS fix가 해제되는 경우, 직전주기에 처리했던 recent 엔트리 이후에 새로운 엔트리가 추가되어 있지 않을 수 있다.
   * 이 경우, 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다.
   */
  else {
    entry = TAILQ_NEXT(prev, entries);
    if (entry) {
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (더이상 사용될 일 없는 오래된 엔트리 제거)
      j29451_RemoveAllPrevGNSSDataBufEntry(prev);
    } else {
      Err("Probably the GNSS signal is not fixed - No next entry of prev recent(epoch: %"PRIu64", total entry: %u)\n",
          prev->gnss.time, buf->entry_num);
      // 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다. (직전데이터 재활용, 시간값만 강제로 증가)
      entry = j29451_CloneAndAddGNSSDataBufEntry(prev, g_j29451_mib.bsm_tx.tx_interval);
    }
    assert(entry);
  }

  buf->proc.prev = prev;
  buf->proc.recent = entry;
  return entry;
}


/**
 * @brief Safe 모드에서, GNSS 데이터 버퍼에서 처리할 엔트리를 반환한다.
 * @return 처리할 엔트리 포인터
 */
static struct J29451GNSSDataBufEntry * j29451_GetNextGNSSDataBufEntryInSafeMode(void)
{
  struct J29451GNSSDataBuf *buf = &(g_j29451_mib.obu.gnss.gnss_data_buf);
  struct J29451GNSSDataBufEntry *entry, *prev = buf->proc.recent;

  /*
   * 프로그램 실행 후 처음으로 엔트리를 처리하는 경우, 버퍼의 가장 마지막 엔트리를 선택하되,
   * 마지막 엔트리의 생성시각이 현시점으로부터 epoch 반주기보다 과거의 정보가 아니면, 그 직전 엔트리를 선택한다.
   */
  if (!prev) {
    entry = TAILQ_LAST(&(buf->head), J29451GNSSDataBufEntryHead);
    if (entry) {
      // 마지막 엔트리의 생성시각이 현시점으로부터 epoch 반주기보다 과거의 정보가 아니면, 그 직전 엔트리를 선택한다.
      uint64_t current_msec = j29451_GetCurrentMsecMonotonic();
      if ((current_msec - entry->gen_msec) < (GNSS_EPOCH_INTERVAL_MSEC / 2)) {
        entry = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);
        if (!entry) {
          // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 GNSS 데이터가 항상 2개 이상 있다고 간주한다.
          Err("[ABNORMAL] No previous entry of last entry in gnss data buf\n");
        }
        assert(entry);
      }
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (사용될 일 없는 오래된 엔트리 제거)
      prev = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);
      if (prev) {
        j29451_RemoveAllPrevGNSSDataBufEntry(prev);
      } else {
        // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 GNSS 데이터가 항상 3개 이상 있다고 간주한다.
        Err("[ABNORMAL] [First] No prev entry of recent entry(epoch: %"PRIu64") in gnss data buf\n", entry->gnss.time);
      }
      assert(prev);
    } else {
      // GNSS data update 쓰레드는 과거(J29451_Init() 호출시점)부터 실행되고 있기 때문에 버퍼 내에 GNSS 데이터가 항상 있다고 간주한다.
      Err("[ABNORMAL] [First] No entry in gnss data buf\n");
    }
    assert(entry);
  }

  /*
   * 두번째 엔트리 처리부터는, 직전주기에 처리했던 recent 엔트리의 다음 엔트리를 선택한다.
   * GNSS 데이터 선택모드(Safe) 메커니즘이 정상동작한다면, 직전주기에 recent 엔트리를 처리한 후에 1~2개의 GNSS 데이터가 추가되어 있어야 한다.
   * 동작 중에 GNSS fix가 해제되는 경우, 직전주기에 처리했던 recent 엔트리 이후에 새로운 엔트리가 추가되어 있지 않을 수 있다.
   * 이 경우, 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다.
   */
  else {
    entry = TAILQ_NEXT(prev, entries);
    if (entry) {
      // prev 엔트리 앞쪽에 저장된 엔트리들을 모두 제거한다. (더이상 사용될 일 없는 오래된 엔트리 제거)
      j29451_RemoveAllPrevGNSSDataBufEntry(prev);
      // prev와 entry간 epoch time이 순차적으로 증가하지 않았으면, 두 엔트리 사이에 새로운 엔트리를 복제/추가하고 이를 사용한다. (직전데이터 재활용, 시간값만 강제로 증가)
      // 이는 GNSS fix가 해제된 상태에서 다시 fix 되었을 때, Safe 모드에서 발생할 수 있는 현상에 대처하기 위함이다)
      if (j29451_CheckGNSSDataBufEntryEpochTimeIncrease(entry) == false) {
        entry = j29451_CloneAndAddGNSSDataBufEntry(prev, g_j29451_mib.bsm_tx.tx_interval);
      }
    } else {
      Err("Probably the GNSS signal is not fixed - No next entry of prev recent(epoch: %"PRIu64", total entry: %u)\n",
          prev->gnss.time, buf->entry_num);
      // 직전 엔트리를 그대로 복사하여 버퍼에 추가하고 사용한다. (직전데이터 재활용, 시간값만 강제로 증가)
      entry = j29451_CloneAndAddGNSSDataBufEntry(prev, g_j29451_mib.bsm_tx.tx_interval);
    }
    assert(entry);
  }

  buf->proc.prev = prev;
  buf->proc.recent = entry;
  return entry;
}


/**
 * @brief 처리하고자 하는 GNSS 데이터 버퍼 엔트리를 반환한다.
 * @return GNSS 데이터 버퍼 엔트리
 */
struct J29451GNSSDataBufEntry INTERNAL * j29451_GetGNSSDataBufEntryToProcess(void)
{
  struct J29451GNSSDataBufEntry *entry;
  if (g_j29451_mib.obu.gnss.gnss_data_sel_mode == kJ29451GNSSDataSelectionMode_Recent) {
    entry = j29451_GetNextGNSSDataBufEntryInRecentMode();
  } else {
    entry = j29451_GetNextGNSSDataBufEntryInSafeMode();
  }
  if (entry) {
    j29451_CheckGNSSDataBufEntryEpochTimeIncrease(entry);
  }
  return entry;
}


/**
 * @brief GNSS 데이터 버퍼 내 "처리" 관련 정보를 초기화한다.
 */
void INTERNAL j29451_InitGNSSDataBufProcessInfo(void)
{
  g_j29451_mib.obu.gnss.gnss_data_buf.proc.prev = NULL;
  g_j29451_mib.obu.gnss.gnss_data_buf.proc.recent = NULL;
}
