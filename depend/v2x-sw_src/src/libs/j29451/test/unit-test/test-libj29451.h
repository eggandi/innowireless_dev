/** 
 * @file
 * @brief
 * @date 2020-10-03
 * @author gyun
 */


#ifndef V2X_SW_TEST_LIBJ29451_H
#define V2X_SW_TEST_LIBJ29451_H


// 시스템 헤더 파일
#include <stdint.h>
#include <time.h>

// 의존 헤더 파일
#include "sudo_queue.h"


/**
 * @brief BSM 송신 콜백함수 결과가 저장되는 엔트리. 해당콜백함수 호출 시마다 엔트리가 추가된다.
 */
struct J29451Test_BSMTransmitCallbackListEntry
{
  uint64_t msec; ///< 호출 시점
  uint8_t bsm[2000];
  size_t bsm_size;
  bool event;
  bool cert_sign;
  bool id_change;
  uint8_t addr[MAC_ALEN];
  TAILQ_ENTRY(J29451Test_BSMTransmitCallbackListEntry) entries;
};
TAILQ_HEAD(J29451Test_BSMTransmitCallbackListHead, J29451Test_BSMTransmitCallbackListEntry);


/**
 * @brief BSM 송신 콜백함수 결과들이 저장되는 리스트
 */
struct J29451Test_BSMTransmitCallbackList
{
  unsigned int entry_num;
  struct J29451Test_BSMTransmitCallbackListHead head;
};


/*
 * 테스트를 위해 정의된 함수
 */
void J29451Test_InitTestGPSData();
void J29451Test_ProcessBSMTransmitCallback(const uint8_t *bsm, size_t bsm_size, bool event, bool cert_sign, bool id_change, uint8_t *addr);
void J29451Test_ReleaseEnv();
bool J29451Test_CompareOctets(const uint8_t *oct1, const uint8_t *oct2, size_t len);

extern struct J29451Test_BSMTransmitCallbackList g_bsm_callback_list;

#endif //V2X_SW_TEST_LIBJ29451_H
