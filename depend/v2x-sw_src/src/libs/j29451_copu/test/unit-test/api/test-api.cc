/** 
 * @file
 * @brief 기본 API에 대한 단위테스트 구현 파일
 * @date 2020-10-07
 * @author gyun
 */


// 시스템 헤더 파일
#include <unistd.h>

// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-mib.h"
#include "j29451-test.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/**
 * 테스트를 위한 샘플 BSM 메시지
 */
static uint8_t g_sample_bsm[] = {
  0x00, 0x14, 0x4f, 0x40, 0x1a, 0x50, 0x9f, 0x7a, 0x0b, 0x21, 0xe5, 0xf8, 0x58, 0xb6, 0x5b, 0x86,
  0x0d, 0xa6, 0x88, 0x00, 0x00, 0x01, 0x00, 0x09, 0x70, 0x00, 0x00, 0x50, 0xfd, 0xfa, 0x1f, 0xa1,
  0x00, 0x7f, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xcd, 0xf1, 0xf9, 0xf9, 0x28, 0xe9,
  0x08, 0xb2, 0x1e, 0xdc, 0x30, 0x6d, 0x36, 0x5f, 0x85, 0x8b, 0x60, 0x80, 0x00, 0x05, 0x0e, 0x00,
  0x00, 0x00, 0x20, 0x01, 0x26, 0xc0, 0x04, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x23, 0xff,
  0xf8, 0x00,
};
size_t g_sample_bsm_size = sizeof(g_sample_bsm);


/*
 * J29451_Init() API의 기본 동작을 확인한다.
 */
TEST(J29451_Init, NORMAL)
{
  const uint8_t default_addr[MAC_ALEN] = {0x00,0x01,0x02,0x03,0x04,0x05};
  uint8_t addr[MAC_ALEN];
  memcpy(addr, default_addr, MAC_ALEN);

  /*
   * API 호출 시 성공하고, 랜덤 MAC 주소가 반환되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  ASSERT_FALSE(J29451Test_CompareOctets(addr, default_addr, MAC_ALEN));
  J29451_Release();

  /*
   * 널 파라미터 전달 시 정상적으로 예외처리되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, nullptr), -kJ29451Result_InvalidParameters);
}


/*
 * J29451_StartBSMTransmit()/J29451_StopBSMTransmit() API의 기본 동작을 확인한다.
 */
TEST(J29451_StartBSMTransmit, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * J29451_StartBSMTransmit() API 호출 시 내부 변수가 정상적으로 설정되고, BSM이 지정된 주기로 송신되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.bsm_tx.tx_interval, kJ29451BSMTxInterval_Default);

  /*
   * 이미 전송 중일 때 중복 호출하면, 정상적으로 에외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), -kJ29451Result_Busy);

#define TEST_CNT (10)
  unsigned int callback_entry_num = 1;
  for (int i = 0; i < TEST_CNT; i++) {
    while (g_bsm_callback_list.entry_num < callback_entry_num);
    callback_entry_num++;
  }

  /*
   * J29451_StopBSMTransmit() API 호출 시 BSM 송신이 중지되는 것을 확인한다.
   *  - 전송주기의 10배를 기다려도 더 이상의 BSM 콜백이 호출되지 않는 것을 확인한다.
   */
  J29451_StopBSMTransmit();
  callback_entry_num = g_bsm_callback_list.entry_num;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 10 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, callback_entry_num);

  /*
   * 각 BSM 송신시점의 주기가 지정된 값과 동일한지 확인한다. (+- 10msec 허용 지터 적용)
   */
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  uint64_t prev_msec = entry->msec;
  for (int i = 1; i < TEST_CNT; i++) {
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
    uint64_t offset = entry->msec - prev_msec;
    ASSERT_TRUE((offset >= g_j29451_mib.bsm_tx.tx_interval - 10) && (offset <= g_j29451_mib.bsm_tx.tx_interval + 10));
    prev_msec = entry->msec;
  }

  J29451Test_ReleaseEnv();
}


/*
 * J29451_StartBSMTransmit() API의 파라미터에 따른 동작을 확인한다.
 */
TEST(J29451_StartBSMTransmit, CHECK_PARAMS)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * 너무 작은 주기를 전달하면, 정상적으로 에외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Min - 1), -kJ29451Result_InvalidParameters);

  /*
   * 너무 큰 주기를 전달하면, 정상적으로 에외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_RequestBSMIDChange() API의 기본 동작을 확인한다.
 */
TEST(J29451_RequestBSMIDChange, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 내부 변수가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_FALSE(g_j29451_mib.bsm_tx.id_change.change_req);
  J29451_RequestBSMIDChange();
  ASSERT_TRUE(g_j29451_mib.bsm_tx.id_change.change_req);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_InitPathInfo() API의 기본 동작을 확인한다.
 */
TEST(J29451_InitPathInfo, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * 약 3초간 BSM을 송신한 후, J29451_InitPathInfo API()를 호출하여 동작을 확인한다.
   */
  sleep(3);
  J29451_InitPathInfo();
  ASSERT_EQ(g_j29451_mib.path.ph.gnss_point_list.entry_num, 0U);
  ASSERT_TRUE(g_j29451_mib.path.ph.gnss_point_list.internal.p_start == nullptr);
  ASSERT_TRUE(g_j29451_mib.path.ph.gnss_point_list.internal.p_prev == nullptr);
  ASSERT_TRUE(g_j29451_mib.path.ph.gnss_point_list.internal.p_next == nullptr);
  ASSERT_TRUE(g_j29451_mib.path.ph.gnss_point_list.internal.p_recent == nullptr);
  ASSERT_EQ(g_j29451_mib.path.ph.ph_points.point_num, 0U);
  ASSERT_EQ(g_j29451_mib.path.ph.ph_points.total_dist, 0.0);
  ASSERT_TRUE(g_j29451_mib.path.ph.ph_points.oldest == nullptr);
  ASSERT_TRUE(g_j29451_mib.path.ph.ph_points.recent == nullptr);
  ASSERT_EQ(g_j29451_mib.path.pp.radius_of_curve, kJ29451RadiusOfCurvature_Straight);
  ASSERT_EQ(g_j29451_mib.path.pp.confidence, 0);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SavePathInfoBackupFile() 및 J29451_LoadPathInfoBackupFile() API의 기본 동작을 확인한다.
 */
TEST(J29451_SavePathInfoBackupFile, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * 약 3초간 BSM을 송신 후 종료한다.
   */
  sleep(3);
  J29451_StopBSMTransmit();

  /*
   * J29451_SavePathInfoBackupFile() API를 호출하여 경로정보가 파일에 저장되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SavePathInfoBackupFile("path.info"), kJ29451Result_Success);

  /*
   * 경로정보를 초기화한다.
   */
  J29451_InitPathInfo();

  /*
   * J29451_LoadPathInfoBackupFile() API를 호출하여 파일에 저장된 경로정보가 정상적으로 로딩되는 것을 확인한다.
   */
  J29451_LoadPathInfoBackupFile("path.info");

  /*
   * Null 파라미터 전달 시 J29451_SavePathInfoBackupFile() API의 호출이 정상적으로 실패하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SavePathInfoBackupFile(nullptr), -kJ29451Result_InvalidParameters);

  /*
   * Null 파라미터 전달 시 J29451_LoadPathInfoBackupFile() API의 호출이 정상적으로 실패하는 것을 확인한다.
   */
  J29451_LoadPathInfoBackupFile(nullptr);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetCertificationMode() API의 기본 동작을 확인한다.
 */
TEST(J29451_SetCertificationMode, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);

  J29451_SetCertificationMode();

  J29451Test_ReleaseEnv();
}


#if defined(_FFASN1C_)

/*
 * J29451_DecodeMessageFrame()/J29451_FreeDecodedMessageFrame() API의 기본 동작을 확인한다.
 */
TEST(J29451_DecodeMessageFrame, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM 전달 시 정상적으로 디코딩되는 것을 확인한다.
   */
  j2735MessageFrame *frame = J29451_DecodeMessageFrame(g_sample_bsm, g_sample_bsm_size);
  ASSERT_TRUE(frame != nullptr);
  J29451_FreeDecodedMessageFrame(frame);

  /*
   * 유효하지 않은 메시지 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  frame = J29451_DecodeMessageFrame(nullptr, g_sample_bsm_size);
  ASSERT_TRUE(frame == nullptr);

  /*
   * 실제보다 짧은 메시지 길이 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   * 실제보다 긴 메시지 길이 전달 시에는 정상 디코딩된다.
   */
  frame = J29451_DecodeMessageFrame(g_sample_bsm, g_sample_bsm_size - 1);
  ASSERT_TRUE(frame == nullptr);
  frame = J29451_DecodeMessageFrame(g_sample_bsm, 0);
  ASSERT_TRUE(frame == nullptr);
  frame = J29451_DecodeMessageFrame(g_sample_bsm, g_sample_bsm_size + 1);
  ASSERT_TRUE(frame != nullptr);
  J29451_FreeDecodedMessageFrame(frame);

  /*
   * J29451_FreeDecodedMessageFrame() API 호출에 nullptr 파라미터 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  J29451_FreeDecodedMessageFrame(nullptr);

  J29451Test_ReleaseEnv();
}

#endif
