/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 SPDU 관련 공통함수 정의
  * @date 2021-12-30 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"


/*
 * @brief ProcessSPDUCallback 콜백함수로 전달되는 메시지 처리 결과들이 저장되는 리스트
 */
struct Dot2Test_ProcessSPDUCallbackList g_callbacks;


/**
 * @brief Dot2_ProcessSPDU() API 처리결과가 전달되는 콜백함수
 * @param[in] result 처리 결과
 * @param[in] priv 패킷파싱데이터
 */
void Dot2Test_ProcessSPDUCallback(Dot2ResultCode result, void *priv)
{
  if (g_callbacks.cnt < MAX_ENTRY_NUM) {
    struct Dot2Test_ProcessSPDUCallbackEntry *entry = &(g_callbacks.entry[g_callbacks.cnt]);
    entry->result = result;
    entry->parsed = (struct V2XPacketParseData *)priv;
    g_callbacks.cnt++;
  }
}


/**
 * @brief 메시지 처리 결과 리스트를 초기화한다.
 */
void Dot2Test_InitProcessSPDUCallbackList()
{
  memset(&g_callbacks, 0, sizeof(g_callbacks));
}


/**
 * @brief 메시지 처리 결과 리스트를 비운다.
 */
void Dot2Test_FlushProcessSPDUCallbackList()
{
  for (unsigned int i = 0; i < g_callbacks.cnt; i++) {
    if (g_callbacks.entry[i].parsed) {
      V2X_FreePacketParseData(g_callbacks.entry[i].parsed);
    }
  }
  memset(&g_callbacks, 0, sizeof(g_callbacks));
}
