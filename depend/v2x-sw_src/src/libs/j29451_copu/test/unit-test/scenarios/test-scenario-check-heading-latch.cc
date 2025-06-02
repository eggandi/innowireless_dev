/** 
 * @file
 * @brief Heading latch 기능에 대한 단위테스트를 구현한 파일
 * @date 2020-10-09
 * @author gyun
 */


// 의존 헤더 파일
#include "sudo_queue.h"
#if defined(_OBJASN1C_)
#include "DSRC.h"
#endif

// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-defines.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


#define INIT_SPEED (TEST_GNSS_DATA_INITIAL_SPEED) ///< 초기 속도
#define INIT_HEADING (TEST_GNSS_DATA_INITIAL_HEADING) ///< 초기 Heading 값
#define LATCH_SPEED (J29451_SPEED_THRESH_LATCH_HEADING - 1) ///< Heading latch 기준값(J29451_SPEED_THRESH_LATCH_HEADING)보다 조금 작은 속도
#define UNLATCH_SPEED (J29451_SPEED_THRESH_UNLATCH_HEADING + 1) ///< Heading unlatch 기준값(J29451_SPEED_THRESH_UNLATCH_HEADING)보다 조금 큰 속도


/*
 * Heading latch 기능이 정상적으로 동작하는지 확인한다.
 */
TEST(CHECK_HEADING_LATCH, NORMAL_WITH_USER_GNSS_DATA)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  J29451Speed speed;
  J29451Heading heading, latched_heading, not_latched_heading;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

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
   * BSM의 Speed와 Heading 값이 지정한 대로 수납되는지 확인한다.
   */
  {
    speed = INIT_SPEED;
    heading = INIT_HEADING;
    not_latched_heading = heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 0);
    entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading); // 최신 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }


  /*
   * Speed를 증가시키면 Speed와 Heading 값이 지정한 대로 수납되는지 확인한다.
   */
  {
    speed = speed + 10;
    heading = heading + 10;
    not_latched_heading = heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 1);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading); // 최신 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }

  /*
   * Speed를 latch 기준값으로 감소시키면, latching 상태가 되지 않는 것을 확인한다.
   * - latch 기준값과 같을 때에는 latching 되지 않고, 기준값 보다 작아질 때 latching 된다.
   */
  {
    speed = J29451_SPEED_THRESH_LATCH_HEADING;
    heading = heading + 10;
    not_latched_heading = heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 2);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading);
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }

  /*
   * Speed를 latch 기준값 미만으로 감소시키면, latching 상태가 되는 것을 확인한다.
   */
  {
    speed = LATCH_SPEED;
    heading = heading + 10;
    latched_heading = not_latched_heading; // latching 되기 직전의 heading 값으로 설정된다.
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 3);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 값 저장
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  /*
   * Speed를 더 감소시키면, latching 상태가 유지되고 BSM에 latching 된 heading 값이 수납되는 것을 확인한다.
   */
  {
    speed = LATCH_SPEED - 1;
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 4);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 값 유지
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  /*
   * Speed를 증가시켜도 Unlatch 기준값 미만이면, latching 상태가 유지되고 BSM에 latching 된 heading 값이 수납되는 것을 확인한다.
   */
  {
    speed = LATCH_SPEED + 5; // UNLATCH_SPEED 보다는 작다.
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 5);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, (int)heading);
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 값 유지
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  /*
   * Speed를 Unlatch 기준값으로 증가시켜도, latching 상태가 유지되고 BSM에 latching 된 heading 값이 수납되는 것을 확인한다.
   *  - unlatch 기준값과 같으면 unlatch 되지 않고, 기준값보다 커질때 unlatch 된다.
   */
  {
    speed = J29451_SPEED_THRESH_UNLATCH_HEADING;
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 6);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, (int)heading);
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 값 유지
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }


  /*
   * Speed를 Unlatch 기준값보다 크게 높이면, latching 상태가 해제되고 BSM에 새로운 heading 값이 수납되는 것을 확인한다.
   */
  {
    speed = UNLATCH_SPEED;
    heading += 10;
    not_latched_heading = heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 7);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, latched_heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, latched_heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading); // 최신 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false,
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }

  /*
   * Speed를 latch 기준값과 unlatch 기준값 사이로 줄여도, unlatch 상태가 유지되는 것을 확인한다.
   */
  {
    speed = UNLATCH_SPEED - 10; // LATCH_SPEED 보다는 크다.
    heading += 10;
    not_latched_heading = heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 8);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, latched_heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, latched_heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading); // 최신 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false,
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }


  /*
   * Speed를 다시 unlatch 기준값 이상으로 늘리면, unlatch 상태가 유지되는 것을 확인한다.
   */
  {
    speed = UNLATCH_SPEED + 10;
    heading += 10;
    not_latched_heading = heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 9);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, latched_heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, latched_heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading); // 최신 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false,
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }


  /*
   * Speed를 latch 기준값 밑으로 줄이면, 다시 latch 상태가 되는 것을 확인한다.
   */
  {
    speed = LATCH_SPEED;
    heading += 10;
    latched_heading = not_latched_heading;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 10);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // latched heading 값이 수납되었는지 확인. 최신 heading값과 동일
    ASSERT_EQ(bsm->coreData.heading, latched_heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // latched heading 값이 수납되었는지 확인. 최신 heading값과 동일
    ASSERT_EQ(bsm.coreData.heading, latched_heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latched heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, (int)heading);
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 저장
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }


  /*
   * Speed가 계속 latch 기준값 밑이면, latch 상태를 유지하는 것을 확인한다.
   */
  {
    speed = LATCH_SPEED - 1;
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 11);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latched heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latched heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latched heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, (int)heading);
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 유지
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  J29451Test_ReleaseEnv();
}


/*
 * Initial Heading latch 기능이 정상적으로 동작하는지 확인한다.
 */
TEST(CHECK_HEADING_LATCH, INITIAL_HEADING_LATCH)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  J29451Speed speed;
  J29451Heading heading, latched_heading;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

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
   * BSM의 Speed와 Heading 값이 지정한 대로 수납되는지 확인한다.
   *  - 최초 속도가 latching 기준값보다 작으면, heading이 latching 되고 최초 heading 값이 수납된다.
   */
  {
    speed = LATCH_SPEED;
    heading = INIT_HEADING;
    latched_heading = heading; // 초기 헤딩값이 latching heading 값이 된다.
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 0);
    entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  /*
   * Speed를 증가시켜도 Unlatch 기준값 미만이면, latching 상태가 유지되고 BSM에 latching 된 heading 값이 수납되는 것을 확인한다.
   */
  {
    speed = LATCH_SPEED + 5; // UNLATCH_SPEED 보다는 작다.
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 1);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 값 유지
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  /*
   * Speed를 Unlatch 기준값으로 증가시켜도, latching 상태가 유지되고 BSM에 latching 된 heading 값이 수납되는 것을 확인한다.
   *  - unlatch 기준값과 같으면 unlatch 되지 않고, 기준값보다 커질때 unlatch 된다.
   */
  {
    speed = J29451_SPEED_THRESH_UNLATCH_HEADING;
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 2);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, latched_heading); // latching된 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading 값 유지
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }


  /*
   * Speed를 Unlatch 기준값보다 크게 높이면, latching 상태가 해제되고 BSM에 새로운 heading 값이 수납되는 것을 확인한다.
   */
  {
    speed = UNLATCH_SPEED;
    heading += 10;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 3);
    entry = TAILQ_NEXT(entry, entries);
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm->coreData.heading, latched_heading);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
    ASSERT_NE(bsm.coreData.heading, latched_heading);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading); // 최신 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: false,
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_FALSE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
  }

  J29451Test_ReleaseEnv();
}


/*
 * 백업/로딩된 경로정보의 Heading latch 기능이 정상적으로 동작하는지 확인한다.
 */
TEST(CHECK_HEADING_LATCH, BACKUP_HEADING_LATCH)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  J29451Speed speed;
  J29451Heading heading, latched_heading;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

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
   * BSM의 Speed와 Heading 값이 지정한 대로 수납되는지 확인한다.
   *  - 최초 속도가 latching 기준값보다 작으면, heading이 latching 되고 최초 heading 값이 수납된다.
   */
  {
    speed = LATCH_SPEED;
    heading = INIT_HEADING;
    latched_heading = heading; // 초기 헤딩값이 latching heading 값이 된다.
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 0);
    entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  /*
   * BSM 송신을 중지한다.
   */
  J29451_StopBSMTransmit();

  /*
   * 경로정보를 백업한 후 다시 로딩한다.
   */
  ASSERT_EQ(J29451_SavePathInfoBackupFile("path.info"), kJ29451Result_Success);
  J29451_InitPathInfo(); // 경로정보 초기화
  J29451_LoadPathInfoBackupFile("path.info");

  /*
   * BSM 송신을 재개한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * BSM의 Speed와 Heading 값이 지정한 대로 수납되는지 확인한다.
   *  - 백업/로딩된 latching된 heading 정보가 BSM에 수납된다.
   */
  {
    speed = LATCH_SPEED;
    heading = INIT_HEADING;
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    while (g_bsm_callback_list.entry_num == 0);
    entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
    ASSERT_TRUE(entry != nullptr);
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    ASSERT_EQ(bsm->coreData.speed, speed);
    ASSERT_EQ(bsm->coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    ASSERT_EQ(bsm.coreData.speed, speed);
    ASSERT_EQ(bsm.coreData.heading, heading); // 최신 heading 값이 수납되었는지 확인
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    ASSERT_TRUE(bsm != nullptr);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)latched_heading); // latching된 heading 값이 수납되었는지 확인
    J29451_FreeDecodedMessageFrame(msg);
#endif

    // 내부 상태정보 확인 - latched: true, latched heading
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.initialized);
    ASSERT_TRUE(g_j29451_mib.obu.gnss.heading_latch.latched);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_speed, speed);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.prev_heading, heading);
    ASSERT_EQ(g_j29451_mib.obu.gnss.heading_latch.heading, latched_heading);
  }

  J29451Test_ReleaseEnv();
}
