/**
 * @file
 * @brief GNSS 데이터 관련 헤더 파일
 * @date 2023-04-03
 * @author gyun
 */

#ifndef V2X_SW_J29451_OBU_GNSS_DATA_H
#define V2X_SW_J29451_OBU_GNSS_DATA_H

// 라이브러리 내부 헤더파일
#include "j29451-internal-types.h"


/// GNSS 데이터 업데이트 이벤트 수신 대기 시간
#define GNSS_DATA_WAITING_USEC (1000000)
/// GNSS epoch 구간 길이(밀리초단위)
#define GNSS_EPOCH_INTERVAL_MSEC (100)
/// 최적 GNSS 데이터 업데이트시작 오프셋 추정 수행시간 (밀리초단위)
#define OPTIMAL_GNSS_DATA_UPDATE_START_OFFSET_ESTIMATE_MSEC (10000)
/// 최적 GNSS 데이터 업데이트시작 오프셋 추정 수행횟수
#define OPTINAL_GNSS_DATA_UPDATE_START_OFFSET_ESTIMATE_CNT (OPTIMAL_GNSS_DATA_UPDATE_START_OFFSET_ESTIMATE_MSEC / GNSS_EPOCH_INTERVAL_MSEC)
/// 필수 GNSS 데이터 업데이트 구간
#define MANDATORY_GNSS_DATA_UPDATE_INTERVAL_MSEC (50)


/**
 * @brief GNSS 데이터 버퍼 내 엔트리 개수
 */
enum eJ29451GNSSDataBufEntryNum
{
  kJ29451GNSSDataBufEntryNum_Min = 0,
  kJ29451GNSSDataBufEntryNum_Max = 1024,
};
typedef unsigned int J29451GNSSDataBufEntryNum; ///< @ref eJ29451GNSSDataBufEntryNum


/**
 * @brief GNSS 데이터 버퍼 엔트리
 */
struct J29451GNSSDataBufEntry
{
  uint64_t gen_msec; ///< 엔트리 생성시각(모노토닉) 모노토닉 시간값이므로 시스템시각의 변경에 영향 받지 않는다.
  struct J29451GNSSData gnss; ///< GNSS 데이터
  TAILQ_ENTRY(J29451GNSSDataBufEntry) entries;
};
TAILQ_HEAD(J29451GNSSDataBufEntryHead, J29451GNSSDataBufEntry);


/**
 * @brief GNSS 데이터 업데이트시작 오프셋 정보
 */
struct J29451GNSSDataUpdateStartOffset
{
  int64_t optimal_start_offset; ///< 추정된 최적(=UTC 1msec 오프셋에 가장 가까운) 업데이트시작 오프셋 값 (밀리초단위 MONOTONIC 시간)
  unsigned int estimate_cnt; ///< 최적 업데이트시작 오프셋 추정 수행 횟수
  bool estimate_complete; ///< 추정이 완료되었는지 여부
  uint64_t prev_update_start_epoch_msec; ///< 직전 업데이트시작 시점의 epoch 시간
};


/**
 * @brief GNSS 데이터 버퍼
 */
struct J29451GNSSDataBuf
{
  J29451GNSSDataBufEntryNum entry_num; ///< 버퍼 내 엔트리 개수
  struct J29451GNSSDataBufEntryHead head; ///< GNSS 데이터(들)

  /// 버퍼엔트리 "처리" 시에 사용되는 참조 포인터
  struct {
    struct J29451GNSSDataBufEntry *prev;
    struct J29451GNSSDataBufEntry *recent;
  } proc;
};


// j29451-obu-gnss-data.c
bool INTERNAL j29451_CheckGNSSDataBufEntryEpochTimeIncrease(struct J29451GNSSDataBufEntry *entry);
void INTERNAL * j29451_GNSSDataUpdateThread(void *arg);
bool INTERNAL j29451_InMandatoryGNSSDataUpdateInterval(int64_t offset);
bool INTERNAL j29451_CheckOptimalGNSSDataUpdateStartOffsetEstimation(void);
void INTERNAL j29451_SetGNSSDataSelectionMode(void);
void INTERNAL j29451_InitGNSSDataSelectionMode(void);

// j29451-obu-gnss-data-buf.c
void INTERNAL j29451_InitGNSSDataBuf(void);
void INTERNAL j29451_FlushGNSSDataBuf(void);
struct J29451GNSSDataBufEntry INTERNAL * j29451_GetGNSSDataBufEntryToUpdate(struct gps_data_t *gps_data);
struct J29451GNSSDataBufEntry INTERNAL * j29451_GetGNSSDataBufEntryToProcess(void);
void INTERNAL j29451_InitGNSSDataBufProcessInfo(void);


#endif //V2X_SW_J29451_OBU_GNSS_DATA_H
