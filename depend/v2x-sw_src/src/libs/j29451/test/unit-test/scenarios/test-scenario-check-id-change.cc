/** 
 * @file
 * @brief ID 변경 기능에 대한 단위테스트를 구현한 파일
 * @date 2020-10-09
 * @author gyun
 */


// 시스템 헤더 파일
#include <time.h>
#include <unistd.h>

// 의존 헤더 파일
#include "sudo_queue.h"
#if defined(_OBJASN1C_)
#include "DSRC.h"
#endif

// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


#define INIT_LAT_RAW (37.406507) ///< 최초 위치의 위도
#define INIT_LON_RAW (127.102377) ///< 최초 위치의 경도
#define LAT_RAW_IN_THRESHOLD (37.389701) ///< 최초 위치에서 1,962m 떨어진 곳의 위도
#define LON_RAW_IN_THRESHOLD (127.109182) ///< 최초 위치에서 1,620m 떨어진 곳의 경도
#define LAT_RAW_OUT_THRESHOLD (37.389312) ///< 최초 위치에서 2,043m 떨어진 곳의 위도
#define LON_RAW_OUT_THRESHOLD (127.110539) ///< 최초 위치에서 2,043m 떨어진 곳의 경도

#define INIT_LAT (374065070) ///< 최초 위치의 위도
#define INIT_LON (1271023770) ///< 최초 위치의 경도
#define LAT_IN_THRESHOLD (373897010) ///< 최초 위치에서 1,970m 떨어진 곳의 위도
#define LON_IN_THRESHOLD (1271091820) ///< 최초 위치에서 1,970m 떨어진 곳의 경도
#define LAT_OUT_THRESHOLD (373893120) ///< 최초 위치에서 2,050m 떨어진 곳의 위도
#define LON_OUT_THRESHOLD (1271105390) ///< 최초 위치에서 2,050m 떨어진 곳의 경도


/*
 * 조건 만족 시, BSM 콜백함수의 id_change 변수가 true로 설정되고 ID가 변경되는 것을 확인한다.
 * 거리 조건이 만족된 후, 시간 조건이 만족 되었을 때 변경되는 것을 확인한다.
 */
TEST(CHECK_ID_CHANGE, SATISFY_TIME_AFTER_DISTNACE)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 테스트 시작시점을 저장한다 - ID 변경관련 모든 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  struct timespec test_start_ts{};
  clock_gettime(CLOCK_REALTIME, &test_start_ts);

  uint8_t init_id[J29451_TEMPORARY_ID_LEN];

  /*
   * 테스트 중 시간 변경을 위해 시스템 시간을 강제로 설정한다.
   */
  system("date -s '2020-10-01 09:00:03'");

  /*
   * BSM이 전송될 수 있도록 최소필요 샘플 GNSS 데이터 및 차량정보를 입력한다. (단위테스트에는 실제 gpsd 입력이 없으므로, 강제 입력한다)
   * Path history를 생성하기 위해 최소한 과거 3개의 GNSS 정보가 필요하므로, 4번째 GNSS 데이터가 확보된 이후에 첫번째 BSM이 송신된다.
   * 따라서 4번째 GNSS 데이터까지 초기값을 넣는다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);
  for (int i = 0; i < 4; i++) {
    g_test_gps_data[i].fix.latitude = INIT_LAT_RAW + (i * 0.0001);
    g_test_gps_data[i].fix.longitude = INIT_LON_RAW + (i * 0.0001);
  } // 첫번째 BSM에 수납되는 정보
  g_test_gps_data[4].fix.latitude = LAT_RAW_IN_THRESHOLD; // 2번째 BSM에 수납되는 정보
  g_test_gps_data[4].fix.longitude = LON_RAW_IN_THRESHOLD; // 2번째 BSM에 수납되는 정보
  g_test_gps_data[5].fix.latitude = LAT_RAW_OUT_THRESHOLD; // 3번째 BSM에 수납되는 정보
  g_test_gps_data[5].fix.longitude = LAT_RAW_OUT_THRESHOLD; // 3번째 BSM에 수납되는 정보
  g_test_gps_data[6].fix.latitude = LAT_RAW_OUT_THRESHOLD; // 4번째 BSM에 수납되는 정보
  g_test_gps_data[6].fix.longitude = LON_RAW_OUT_THRESHOLD; // 4번째 BSM에 수납되는 정보

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * 1번째 BSM 송신 콜백함수로 전달된 id_change 값이 false인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  // BSM 내 id 값을 저장한다.
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  memcpy(init_id, bsm->coreData.id.data, J29451_TEMPORARY_ID_LEN);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  memcpy(init_id, bsm.coreData.id.data, J29451_TEMPORARY_ID_LEN);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  memcpy(init_id, bsm->coreData.id.buf, J29451_TEMPORARY_ID_LEN);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 2번째 BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 1);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 3번째 BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   *  - 거리 기준은 만족하였으나, 시간 기준은 만족하지 못하였으므로 ID는 변경되지 않는다.
   */
  while(g_bsm_callback_list.entry_num == 2);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 시간을 강제로 5분(ID 변경 임계값) 이후로 변경한다.
   */
  system("date -s '2020-10-01 09:05:05'");

  /*
   * 4번째 BSM 송신 콜백함수로 전달된 id_change 값이 true이고, ID가 변경된 것을 확인한다.
   * 인증서 서명 요청과 새로운 MAC 주소가 전달된 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 3);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_TRUE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(J29451Test_CompareOctets(entry->addr, addr, MAC_ALEN));
  memcpy(addr, entry->addr, MAC_ALEN);

  // BSM 내 id 값이 변경된 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif
  J29451Test_ReleaseEnv();

#if 1 // 도커에서 시간이 복구되지 않을때 주석처리
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  struct timespec test_end_ts{};
  while(true) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }
#endif
}


/*
 * 조건 만족 시, BSM 콜백함수의 id_change 변수가 true로 설정되고 ID가 변경되는 것을 확인한다.
 * 시간 조건이 만족된 후, 거리 조건이 만족 되었을 때 변경되는 것을 확인한다.
 */
TEST(CHECK_ID_CHANGE, SATISFY_DISTANCE_AFTER_TIME)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 테스트 시작시점을 저장한다 - ID 변경관련 모든 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  struct timespec test_start_ts{};
  clock_gettime(CLOCK_REALTIME, &test_start_ts);

  uint8_t init_id[J29451_TEMPORARY_ID_LEN];

  /*
   * 테스트 중 시간 변경을 위해 시스템 시간을 강제로 설정한다.
   */
  system("date -s '2020-10-01 09:10:03'");

  /*
   * BSM이 전송될 수 있도록 최소필요 샘플 GNSS 데이터 및 차량정보를 입력한다. (단위테스트에는 실제 gpsd 입력이 없으므로, 강제 입력한다)
   * Path history를 생성하기 위해 최소한 과거 3개의 GNSS 정보가 필요하므로, 4번째 GNSS 데이터가 확보되면 첫번째 BSM이 송신된다.
   * 따라서 4번째 GNSS 데이터까지 초기값을 넣는다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);
  for (int i = 0; i < 4; i++) {
    g_test_gps_data[i].fix.latitude = INIT_LAT_RAW + (i * 0.0001);
    g_test_gps_data[i].fix.longitude = INIT_LON_RAW + (i * 0.0001);
  } // 첫번째 BSM에 수납되는 정보
  g_test_gps_data[4].fix.latitude = LAT_RAW_IN_THRESHOLD; // 2번째 BSM에 수납되는 정보
  g_test_gps_data[4].fix.longitude = LON_RAW_IN_THRESHOLD; // 2번째 BSM에 수납되는 정보
  g_test_gps_data[5].fix.latitude = LAT_RAW_IN_THRESHOLD + 0.0001; // 3번째 BSM에 수납되는 정보
  g_test_gps_data[5].fix.longitude = LON_RAW_IN_THRESHOLD + 0.0001; // 3번째 BSM에 수납되는 정보
  g_test_gps_data[6].fix.latitude = LAT_RAW_OUT_THRESHOLD; // 4번째 BSM에 수납되는 정보
  g_test_gps_data[6].fix.longitude = LON_RAW_OUT_THRESHOLD; // 4번째 BSM에 수납되는 정보

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * 1번째 BSM 송신 콜백함수로 전달된 id_change 값이 false인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  // BSM 내 id 값을 저장한다.
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  memcpy(init_id, bsm->coreData.id.data, J29451_TEMPORARY_ID_LEN);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  memcpy(init_id, bsm.coreData.id.data, J29451_TEMPORARY_ID_LEN);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  memcpy(init_id, bsm->coreData.id.buf, J29451_TEMPORARY_ID_LEN);
  J29451_FreeDecodedMessageFrame(msg);
#endif
  /*
   * 시간을 강제로 5분(ID 변경 임계값) 이후로 변경한다.
   */
  system("date -s '2020-10-01 09:15:05'");

  /*
   * 2번째 BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   *  - 시간 기준은 만족하였으나, 거리 기준은 만족하지 못하였으므로 ID는 변경되지 않는다.
   */
  while(g_bsm_callback_list.entry_num == 1);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 3번째 BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 2);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 4번째 BSM 송신 콜백함수로 전달된 id_change 값이 true이고, ID가 변경된 것을 확인한다.
   * 인증서 서명 요청과 새로운 MAC 주소가 전달된 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 3);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_TRUE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(J29451Test_CompareOctets(entry->addr, addr, MAC_ALEN));
  memcpy(addr, entry->addr, MAC_ALEN);

  // BSM 내 id 값이 변경된 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif
  J29451Test_ReleaseEnv();

#if 1 // 도커에서 시간이 복구되지 않을때 주석처리
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  struct timespec test_end_ts{};
  while(true) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }
#endif
}


/*
 * 조건 만족 시, BSM 콜백함수의 id_change 변수가 true로 설정되고 ID가 변경되는 것을 확인한다.
 * 거리 조건이 만족된 후, 시간 조건이 만족 되었을 때 변경되는 것을 확인한다.
 */
TEST(CHECK_ID_CHANGE, SATISFY_TIME_AFTER_DISTNACE_WITH_USER_GNSS_DATA)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 테스트 시작시점을 저장한다 - ID 변경관련 모든 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  struct timespec test_start_ts{};
  clock_gettime(CLOCK_REALTIME, &test_start_ts);

  uint8_t init_id[J29451_TEMPORARY_ID_LEN];

  /*
   * 테스트 중 시간 변경을 위해 시스템 시간을 강제로 설정한다.
   */
  system("date -s '2020-10-01 09:20:03'");

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * BSM이 전송될 수 있도록 최소필요 샘플 GNSS 데이터 및 차량정보를 입력한다.
   */
  g_j29451_mib.obu.gnss.gnss_data.lat = TEST_GNSS_DATA_INITIAL_LAT;
  g_j29451_mib.obu.gnss.gnss_data.lon = TEST_GNSS_DATA_INITIAL_LON;
  g_j29451_mib.obu.gnss.gnss_data.elev = TEST_GNSS_DATA_INITIAL_ELEV;
  g_j29451_mib.obu.gnss.gnss_data.speed = TEST_GNSS_DATA_INITIAL_SPEED;
  g_j29451_mib.obu.gnss.gnss_data.heading = TEST_GNSS_DATA_INITIAL_HEADING;
  g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_major = TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ACCURACY;
  g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_minor = TEST_GNSS_DATA_INITIAL_SEMI_MINOR_AXIS_ACCURACY;
  g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.orientation = TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ORIENTATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat = TEST_GNSS_DATA_INITIAL_LAT_ACCELERATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon = TEST_GNSS_DATA_INITIAL_LON_ACCELERATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert = TEST_GNSS_DATA_INITIAL_VERT_ACCELERATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw = TEST_GNSS_DATA_INITIAL_YAW_RATE;
  g_j29451_mib.vehicle.size.width = TEST_VEHICLE_INFO_INITIAL_WIDTH;
  g_j29451_mib.vehicle.size.length = TEST_VEHICLE_INFO_INITIAL_LENGTH;

  /*
   * 사용자 GNSS 데이터를 설정한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(INIT_LAT), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(INIT_LON), kJ29451Result_Success);

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  // BSM 내 id 값을 저장한다.
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  memcpy(init_id, bsm->coreData.id.data, J29451_TEMPORARY_ID_LEN);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  memcpy(init_id, bsm.coreData.id.data, J29451_TEMPORARY_ID_LEN);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  memcpy(init_id, bsm->coreData.id.buf, J29451_TEMPORARY_ID_LEN);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 사용자 GNSS 데이터를 설정한다. 초기 위치에서 ID 변경 임계값인 2km 이내에 위치한 곳이다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(LAT_IN_THRESHOLD), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(LON_IN_THRESHOLD), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 1);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 사용자 GNSS 데이터를 설정한다. 초기 위치에서 ID 변경 임계값인 2km 밖에 위치한 곳이다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(LAT_OUT_THRESHOLD), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(LON_OUT_THRESHOLD), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   *  - 거리 기준은 만족하였으나, 시간 기준은 만족하지 못하였으므로 ID는 변경되지 않는다.
   */
  while(g_bsm_callback_list.entry_num == 2);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 시간을 강제로 5분(ID 변경 임계값) 이후로 변경한다.
   */
  system("date -s '2020-10-01 09:25:05'");

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 true이고, ID가 변경된 것을 확인한다.
   * 인증서 서명 요청과 새로운 MAC 주소가 전달된 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 3);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_TRUE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(J29451Test_CompareOctets(entry->addr, addr, MAC_ALEN));
  memcpy(addr, entry->addr, MAC_ALEN);

  // BSM 내 id 값이 변경된 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  J29451Test_ReleaseEnv();

#if 1 // 도커에서 시간이 복구되지 않을때 주석처리
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  struct timespec test_end_ts{};
  while(true) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }
#endif
}


/*
 * 조건 만족 시, BSM 콜백함수의 id_change 변수가 true로 설정되고 ID가 변경되는 것을 확인한다.
 * 시간 조건이 만족된 후, 거리 조건이 만족 되었을 때 변경되는 것을 확인한다.
 */
TEST(CHECK_ID_CHANGE, SATISFY_DISTANCE_AFTER_TIME_WITH_USER_GNSS_DATA)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 테스트 시작시점을 저장한다 - ID 변경관련 모든 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  struct timespec test_start_ts{};
  clock_gettime(CLOCK_REALTIME, &test_start_ts);

  uint8_t init_id[J29451_TEMPORARY_ID_LEN];

  /*
   * 테스트 중 시간 변경을 위해 시스템 시간을 강제로 설정한다.
   */
  system("date -s '2020-10-01 09:25:03'");

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * BSM이 전송될 수 있도록 최소필요 샘플 GNSS 데이터 및 차량정보를 입력한다.
   */
  g_j29451_mib.obu.gnss.gnss_data.lat = TEST_GNSS_DATA_INITIAL_LAT;
  g_j29451_mib.obu.gnss.gnss_data.lon = TEST_GNSS_DATA_INITIAL_LON;
  g_j29451_mib.obu.gnss.gnss_data.elev = TEST_GNSS_DATA_INITIAL_ELEV;
  g_j29451_mib.obu.gnss.gnss_data.speed = TEST_GNSS_DATA_INITIAL_SPEED;
  g_j29451_mib.obu.gnss.gnss_data.heading = TEST_GNSS_DATA_INITIAL_HEADING;
  g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_major = TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ACCURACY;
  g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_minor = TEST_GNSS_DATA_INITIAL_SEMI_MINOR_AXIS_ACCURACY;
  g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.orientation = TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ORIENTATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat = TEST_GNSS_DATA_INITIAL_LAT_ACCELERATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon = TEST_GNSS_DATA_INITIAL_LON_ACCELERATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert = TEST_GNSS_DATA_INITIAL_VERT_ACCELERATION;
  g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw = TEST_GNSS_DATA_INITIAL_YAW_RATE;
  g_j29451_mib.vehicle.size.width = TEST_VEHICLE_INFO_INITIAL_WIDTH;
  g_j29451_mib.vehicle.size.length = TEST_VEHICLE_INFO_INITIAL_LENGTH;

  /*
   * 사용자 GNSS 데이터를 설정한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(INIT_LAT), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(INIT_LON), kJ29451Result_Success);

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  // BSM 내 id 값을 저장한다.
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  memcpy(init_id, bsm->coreData.id.data, J29451_TEMPORARY_ID_LEN);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  memcpy(init_id, bsm.coreData.id.data, J29451_TEMPORARY_ID_LEN);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  memcpy(init_id, bsm->coreData.id.buf, J29451_TEMPORARY_ID_LEN);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 시간을 강제로 5분(ID 변경 임계값) 이후로 변경한다.
   */
  system("date -s '2020-10-01 09:30:05'");

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   *  - 시간 기준은 만족하였으나, 거리 기준은 만족하지 못하였으므로 ID는 변경되지 않는다.
   */
  while(g_bsm_callback_list.entry_num == 1);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 사용자 GNSS 데이터를 설정한다. 초기 위치에서 ID 변경 임계값인 2km 이내에 위치한 곳이다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(LAT_IN_THRESHOLD), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(LON_IN_THRESHOLD), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 2);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);

  // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 사용자 GNSS 데이터를 설정한다. 초기 위치에서 ID 변경 임계값인 2km 밖에 위치한 곳이다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(LAT_OUT_THRESHOLD), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(LON_OUT_THRESHOLD), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 true이고, ID가 변경된 것을 확인한다.
   * 인증서 서명 요청과 새로운 MAC 주소가 전달된 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 3);
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_TRUE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(J29451Test_CompareOctets(entry->addr, addr, MAC_ALEN));
  memcpy(addr, entry->addr, MAC_ALEN);

  // BSM 내 id 값이 변경된 것을 확인한다.
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE(bsm != nullptr);
  ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
  J29451_FreeDecodedMessageFrame(msg);
#endif
  J29451Test_ReleaseEnv();

#if 1 // 도커에서 시간이 복구되지 않을때 주석처리
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  struct timespec test_end_ts{};
  while(true) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }
#endif
}


/*
 * ID change 요청 시, BSM 콜백함수의 id_change 변수가 true로 설정되고 ID가 변경되는 것을 확인한다.
 */
TEST(CHECK_ID_CHANGE, REQUEST_ID_CHANGE)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  uint8_t init_id[J29451_TEMPORARY_ID_LEN], changed_id[J29451_TEMPORARY_ID_LEN];
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false인 것을 확인한다.
   */
  {
    while (g_bsm_callback_list.entry_num == 0);
    entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
    ASSERT_TRUE(entry != nullptr);
    ASSERT_FALSE(entry->id_change);
    ASSERT_FALSE(entry->event);
    ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

    // BSM 내 id 값을 저장한다.
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    memcpy(init_id, bsm->coreData.id.data, J29451_TEMPORARY_ID_LEN);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    memcpy(init_id, bsm.coreData.id.data, J29451_TEMPORARY_ID_LEN);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    memcpy(init_id, bsm->coreData.id.buf, J29451_TEMPORARY_ID_LEN);
    J29451_FreeDecodedMessageFrame(msg);
#endif
  }

  /*
   * ID 변경을 요청한다.
   */
  J29451_RequestBSMIDChange();
  ASSERT_TRUE(g_j29451_mib.bsm_tx.id_change.change_req);

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 true이고, ID가 변경된 것을 확인한다.
   * 인증서 서명 요청과 새로운 MAC 주소가 전달된 것을 확인한다.
   */
  {
    while (g_bsm_callback_list.entry_num == 1);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
    ASSERT_TRUE(entry->id_change);
    ASSERT_FALSE(entry->event);
    ASSERT_TRUE(entry->cert_sign);
    ASSERT_FALSE(J29451Test_CompareOctets(entry->addr, addr, MAC_ALEN));
    memcpy(addr, entry->addr, MAC_ALEN);

    // BSM 내 id 값이 변경된 것을 확인한다.
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
    memcpy(changed_id, bsm->coreData.id.data, J29451_TEMPORARY_ID_LEN);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_FALSE(J29451Test_CompareOctets(bsm.coreData.id.data, init_id, J29451_TEMPORARY_ID_LEN));
    memcpy(changed_id, bsm.coreData.id.data, J29451_TEMPORARY_ID_LEN);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_FALSE(J29451Test_CompareOctets(bsm->coreData.id.buf, init_id, J29451_TEMPORARY_ID_LEN));
    memcpy(changed_id, bsm->coreData.id.buf, J29451_TEMPORARY_ID_LEN);
    J29451_FreeDecodedMessageFrame(msg);
#endif
  }

  /*
   * BSM 송신 콜백함수로 전달된 id_change 값이 false이고 ID가 그대로인 것을 확인한다.
   */
  {
    while (g_bsm_callback_list.entry_num == 2);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
    ASSERT_FALSE(entry->id_change);
    ASSERT_FALSE(entry->event);
    ASSERT_FALSE(entry->cert_sign);

    // BSM 내 id 값이 동일한 것을 확인한다.
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.data, changed_id, J29451_TEMPORARY_ID_LEN));
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_TRUE(J29451Test_CompareOctets(bsm.coreData.id.data, changed_id, J29451_TEMPORARY_ID_LEN));
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_TRUE(J29451Test_CompareOctets(bsm->coreData.id.buf, changed_id, J29451_TEMPORARY_ID_LEN));
    J29451_FreeDecodedMessageFrame(msg);
#endif
  }

  J29451Test_ReleaseEnv();
}
