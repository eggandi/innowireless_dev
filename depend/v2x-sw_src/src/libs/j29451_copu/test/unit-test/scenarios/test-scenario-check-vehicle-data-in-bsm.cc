/** 
 * @file
 * @brief 입력되는 차량상태정보가 BSM에 정확하게 반영되는지 시험하는 단위테스트 구현 파일
 * @date 2020-10-07
 * @author gyun
 */


// 시스템 헤더 파일
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
#include "j29451-internal-inline.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/*
 * 입력된 차량상태정보가 정상적으로 BSMCoreData에 수납되는 것을 확인한다.
 */
TEST(CHECK_VEHICLE_IN_BSM, BSMCoreData)
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

  unsigned int rx_pkt_num = 0;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * 설정한 기어상태정보가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_Neutral), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Neutral);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Neutral);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Neutral);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_Unavailable), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 속도정보가 BSM에 수납되지 않는 것을 확인한다 - 현재 BSM에는 GNSS 속도정보가 수납된다.
   */
  J29451_SetVehicleSpeed(j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed) + 1);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.speed, (int)j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 스티어링휠각도정보가 BSM에 정상 수납되는지 확인한다.
   */
  J29451_SetVehicleSteeringWheelAngle(kJ29451SteeringWheelAngle_Min);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Min);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.angle, kJ29451SteeringWheelAngle_Min);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Min);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 브레이크적용상태가 BSM에 정상 수납되는지 확인한다.
   */
  struct J29451BrakeAppliedStatus brake_applied_status = { true, false, true, false, true};
  ASSERT_EQ(J29451_SetVehicleBrakeAppliedStatus(&brake_applied_status), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE((bsm->coreData.brakes.wheelBrakes.data[0] >> 7) & 1);
  ASSERT_FALSE((bsm->coreData.brakes.wheelBrakes.data[0] >> 6) & 1);
  ASSERT_TRUE((bsm->coreData.brakes.wheelBrakes.data[0] >> 5) & 1);
  ASSERT_FALSE((bsm->coreData.brakes.wheelBrakes.data[0] >> 4) & 1);
  ASSERT_TRUE((bsm->coreData.brakes.wheelBrakes.data[0] >> 3) & 1);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE((bsm.coreData.brakes.wheelBrakes.data[0] >> 7) & 1);
  ASSERT_FALSE((bsm.coreData.brakes.wheelBrakes.data[0] >> 6) & 1);
  ASSERT_TRUE((bsm.coreData.brakes.wheelBrakes.data[0] >> 5) & 1);
  ASSERT_FALSE((bsm.coreData.brakes.wheelBrakes.data[0] >> 4) & 1);
  ASSERT_TRUE((bsm.coreData.brakes.wheelBrakes.data[0] >> 3) & 1);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_TRUE((*(bsm->coreData.brakes.wheelBrakes.buf) >> 7) & 1);
  ASSERT_FALSE((*(bsm->coreData.brakes.wheelBrakes.buf) >> 6) & 1);
  ASSERT_TRUE((*(bsm->coreData.brakes.wheelBrakes.buf) >> 5) & 1);
  ASSERT_FALSE((*(bsm->coreData.brakes.wheelBrakes.buf) >> 4) & 1);
  ASSERT_TRUE((*(bsm->coreData.brakes.wheelBrakes.buf) >> 3) & 1);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 traction control 상태가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleTractionControlStatus(kJ29451TractionControlStatus_Off), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.brakes.traction, kJ29451TractionControlStatus_Off);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.brakes.traction, kJ29451TractionControlStatus_Off);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.brakes.traction, (int)kJ29451TractionControlStatus_Off);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 anti lock brake 상태가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleAntiLockBrakeStatus(kJ29451AntiLockBrakeStatus_Engaged), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.brakes.abs_, kJ29451AntiLockBrakeStatus_Engaged);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.brakes.albs, kJ29451AntiLockBrakeStatus_Engaged);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.brakes.albs, (int)kJ29451AntiLockBrakeStatus_Engaged);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 stability control 상태가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleStabilityControlStatus(kJ29451StabilityControlStatus_On), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.brakes.scs, kJ29451StabilityControlStatus_On);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.brakes.scs, kJ29451StabilityControlStatus_On);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.brakes.scs, (int)kJ29451StabilityControlStatus_On);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 brake boost applied 상태가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleBrakeBoostApplied(kJ29451BrakeBoostApplied_Off), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Off);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Off);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.brakes.brakeBoost, (int)kJ29451BrakeBoostApplied_Off);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 보조 브레이크 상태가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleAuxiliaryBrakeStatus(kJ29451AuxiliaryBrakeStatus_On), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_On);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_On);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.brakes.auxBrakes, (int)kJ29451AuxiliaryBrakeStatus_On);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 설정한 차량 크기가 BSM에 정상 수납되는지 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleSize(kJ29451VehicleWidth_Max, kJ29451VehicleLength_Max), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_EQ(bsm->coreData.size.width, kJ29451VehicleWidth_Max);
  ASSERT_EQ(bsm->coreData.size.length, kJ29451VehicleLength_Max);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_EQ(bsm.coreData.size.width, kJ29451VehicleWidth_Max);
  ASSERT_EQ(bsm.coreData.size.length, kJ29451VehicleLength_Max);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  ASSERT_EQ(bsm->coreData.size.width, (int)kJ29451VehicleWidth_Max);
  ASSERT_EQ(bsm->coreData.size.length, (int)kJ29451VehicleLength_Max);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  J29451Test_ReleaseEnv();
}


/*
 * 입력된 차량상태정보가 정상적으로 ExteriorLights 필드에 수납되는 것을 확인한다.
 */
TEST(CHECK_VEHICLE_IN_BSM, EXTERIOR_LIGHTS)
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

  unsigned int rx_pkt_num = 0;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * 설정한 외부등상태정보가 BSM에 정상 수납되는지 확인한다.
   */
  struct J29451ExteriorLights lights = { true, false, true, false, true, false, true, false, true };
  ASSERT_EQ(J29451_SetVehicleExteriorLights(&lights), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
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
  ASSERT_TRUE(bsm->m.partIIPresent);
  OSRTDListNode *node = bsm->partII.head;
  auto *content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  VehicleSafetyExtensions *ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_TRUE(ext->m.lightsPresent);
  ASSERT_TRUE((ext->lights.data[0] >> 7) & 1); // low_beam_headlight_on
  ASSERT_FALSE((ext->lights.data[0] >> 6) & 1); // high_beam_headlight_on
  ASSERT_TRUE((ext->lights.data[0] >> 5) & 1); // left_turn_signal_on
  ASSERT_FALSE((ext->lights.data[0] >> 4) & 1); // right_turn_signal_on
  ASSERT_TRUE((ext->lights.data[0] >> 3) & 1); // hazard_signal_on
  ASSERT_FALSE((ext->lights.data[0] >> 2) & 1); // automatic_light_control_on
  ASSERT_TRUE((ext->lights.data[0] >> 1) & 1); // daytime_running_lights_on
  ASSERT_FALSE((ext->lights.data[0] >> 0) & 1); // fog_light_on
  ASSERT_TRUE((ext->lights.data[1] >> 7) & 1); // parking_light_on
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  OSRTDListNode *node = bsm.partII.head;
  PartIIcontent *content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  VehicleSafetyExtensions ext;
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_TRUE(ext.m.lightsPresent);
  ASSERT_TRUE((ext.lights.data[0] >> 7) & 1); // low_beam_headlight_on
  ASSERT_FALSE((ext.lights.data[0] >> 6) & 1); // high_beam_headlight_on
  ASSERT_TRUE((ext.lights.data[0] >> 5) & 1); // left_turn_signal_on
  ASSERT_FALSE((ext.lights.data[0] >> 4) & 1); // right_turn_signal_on
  ASSERT_TRUE((ext.lights.data[0] >> 3) & 1); // hazard_signal_on
  ASSERT_FALSE((ext.lights.data[0] >> 2) & 1); // automatic_light_control_on
  ASSERT_TRUE((ext.lights.data[0] >> 1) & 1); // daytime_running_lights_on
  ASSERT_FALSE((ext.lights.data[0] >> 0) & 1); // fog_light_on
  ASSERT_TRUE((ext.lights.data[1] >> 7) & 1); // parking_light_on
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts->lights_option);
  ASSERT_TRUE((*(exts->lights.buf) >> 7) & 1); // low_beam_headlight_on
  ASSERT_FALSE((*(exts->lights.buf) >> 6) & 1); // high_beam_headlight_on
  ASSERT_TRUE((*(exts->lights.buf) >> 5) & 1); // left_turn_signal_on
  ASSERT_FALSE((*(exts->lights.buf) >> 4) & 1); // right_turn_signal_on
  ASSERT_TRUE((*(exts->lights.buf) >> 3) & 1); // hazard_signal_on
  ASSERT_FALSE((*(exts->lights.buf) >> 2) & 1); // automatic_light_control_on
  ASSERT_TRUE((*(exts->lights.buf) >> 1) & 1); // daytime_running_lights_on
  ASSERT_FALSE((*(exts->lights.buf) >> 0) & 1); // fog_light_on
  ASSERT_TRUE((*(exts->lights.buf + 1) >> 7) & 1); // parking_light_on
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 외부등상태정보를 해제하면 BSM에 수납되지 않는 것을 확인한다.
   */
  J29451_ClearVehicleExteriorLights();
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);
#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  node = bsm->partII.head;
  content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_FALSE(ext->m.lightsPresent);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  node = bsm.partII.head;
  content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_FALSE(ext.m.lightsPresent);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_FALSE(exts->lights_option);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  J29451Test_ReleaseEnv();
}


/*
 * 입력된 처량이벤트정보가 정상적으로 VehicleEventFlags 필드에 수납되는 것을 확인한다.
 */
TEST(CHECK_VEHICLE_IN_BSM, VEHICLE_EVENT_FLAGS)
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
   * J29451_SetVehicleEventFlags() API로 설정한 hard braking 이벤트가 라이브러리 내부 판정결과에 영향받는 것을 막기 위해
   * 해당 기능을 비활성화한다.
   */
  J29451_ActivateHardBrakingEventDecision(false);

  unsigned int rx_pkt_num = 0;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * 설정한 차량이벤트정보가 BSM에 정상 수납되는지 확인한다.
   */
  struct J29451VehicleEventFlags event = {true, false, true, false, true, false, false, true, false, true, false, true, false};
  ASSERT_EQ(J29451_SetVehicleEventFlags(&event), kJ29451Result_Success);
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event 변수가 true로 설정된 것을 확인한다.
  ASSERT_TRUE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  OSRTDListNode *node = bsm->partII.head;
  auto *content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  VehicleSafetyExtensions *ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_TRUE(ext->m.eventsPresent);
  ASSERT_TRUE((ext->events.data[0] >> 7) & 1); // hazard_lights
  ASSERT_FALSE((ext->events.data[0] >> 6) & 1); // stop_line_violation
  ASSERT_TRUE((ext->events.data[0] >> 5) & 1); // abs_activated
  ASSERT_FALSE((ext->events.data[0] >> 4) & 1); // traction_control_loss
  ASSERT_TRUE((ext->events.data[0] >> 3) & 1); // stability_control_activated
  ASSERT_FALSE((ext->events.data[0] >> 2) & 1); // hazardous_materials
  ASSERT_TRUE((ext->events.data[0] >> 0) & 1); // hard_braking
  ASSERT_FALSE((ext->events.data[1] >> 7) & 1); // lights_changed
  ASSERT_TRUE((ext->events.data[1] >> 6) & 1); // wiper_changed
  ASSERT_FALSE((ext->events.data[1] >> 5) & 1); // flat_tire
  ASSERT_TRUE((ext->events.data[1] >> 4) & 1); // disabled_vehicle
  ASSERT_FALSE((ext->events.data[1] >> 3) & 1); // airbag_deployment
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  OSRTDListNode *node = bsm.partII.head;
  PartIIcontent *content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  VehicleSafetyExtensions ext;
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_TRUE(ext.m.eventsPresent);
  ASSERT_TRUE((ext.events.data[0] >> 7) & 1); // hazard_lights
  ASSERT_FALSE((ext.events.data[0] >> 6) & 1); // stop_line_violation
  ASSERT_TRUE((ext.events.data[0] >> 5) & 1); // abs_activated
  ASSERT_FALSE((ext.events.data[0] >> 4) & 1); // traction_control_loss
  ASSERT_TRUE((ext.events.data[0] >> 3) & 1); // stability_control_activated
  ASSERT_FALSE((ext.events.data[0] >> 2) & 1); // hazardous_materials
  ASSERT_TRUE((ext.events.data[0] >> 0) & 1); // hard_braking
  ASSERT_FALSE((ext.events.data[1] >> 7) & 1); // lights_changed
  ASSERT_TRUE((ext.events.data[1] >> 6) & 1); // wiper_changed
  ASSERT_FALSE((ext.events.data[1] >> 5) & 1); // flat_tire
  ASSERT_TRUE((ext.events.data[1] >> 4) & 1); // disabled_vehicle
  ASSERT_FALSE((ext.events.data[1] >> 3) & 1); // airbag_deployment
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);

  // 설정한 차량이벤트정보와 동일한지 확인한다.
  ASSERT_TRUE(exts->events_option);
  ASSERT_TRUE((*(exts->events.buf) >> 7) & 1); // hazard_lights
  ASSERT_FALSE((*(exts->events.buf) >> 6) & 1); // stop_line_violation
  ASSERT_TRUE((*(exts->events.buf) >> 5) & 1); // abs_activated
  ASSERT_FALSE((*(exts->events.buf) >> 4) & 1); // traction_control_loss
  ASSERT_TRUE((*(exts->events.buf) >> 3) & 1); // stability_control_activated
  ASSERT_FALSE((*(exts->events.buf) >> 2) & 1); // hazardous_materials
  ASSERT_TRUE((*(exts->events.buf) >> 0) & 1); // hard_braking
  ASSERT_FALSE((*(exts->events.buf + 1) >> 7) & 1); // lights_changed
  ASSERT_TRUE((*(exts->events.buf + 1) >> 6) & 1); // wiper_changed
  ASSERT_FALSE((*(exts->events.buf + 1) >> 5) & 1); // flat_tire
  ASSERT_TRUE((*(exts->events.buf + 1) >> 4) & 1); // disabled_vehicle
  ASSERT_FALSE((*(exts->events.buf + 1) >> 3) & 1); // airbag_deployment

  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * 처량이벤트정보가 해제하면 BSM에 수납되지 않는 것을 확인한다.
   */
  J29451_ClearVehicleEventFlags();
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event 변수가 false로 설정된 것을 확인한다.
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);
  ASSERT_FALSE(entry->id_change);

#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  node = bsm->partII.head;
  content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_FALSE(ext->m.eventsPresent);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  node = bsm.partII.head;
  content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_FALSE(ext.m.eventsPresent);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);

  // 차량이벤트정보 필드가 존재하지 않는 것을 확인한다.
  ASSERT_FALSE(exts->events_option);

  J29451_FreeDecodedMessageFrame(msg);

#endif
  J29451Test_ReleaseEnv();
}


/*
 * Hard braking 이벤트를 정상적으로 감지하는 것을 확인한다.
 */
TEST(CHECK_VEHICLE_IN_BSM, HARD_BRAKING)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * Hard braking event가 잘 감지될 수 있도록 샘플 종방향 가속도 값을 기준값 근처로 설정한다.
   * - 필터가 적용되기 때문에, 변경된 값의 반영 효과가 감소된다.
   */
  for (int i = 0; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].attitude.acc_x = J29451_HARD_BRAKIG_THRESHOLD;
  }

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  unsigned int rx_pkt_num = 0;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * 일단 첫번째 BSM을 수신한다. (g_test_gps_data의 추적을 용이하게 하기 위함임 -> 기능적인 의미는 없음)
   * Path history를 생성하기 위해 최소한 과거 3개의 GNSS 정보가 필요하므로, 4번째 GNSS 데이터가 확보된 이후에 첫번째 BSM이 송신된다.
   * 따라서 첫번째 BSM의 CoreData에는 4번째 GNSS 데이터 정보가 포함되어 있다.
   */
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  // 콜백함수의 event,id_change=false로 설정된 것을 확인한다.
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM이므로 인증서로 서명

  /*
   * Hard braking 조건을 만족하지 않으면 BSM 내 이벤트가 set 되지 않는 것을 확인한다.
   */
  g_test_gps_data[g_test_gps_data_idx+1].attitude.acc_x = J29451_HARD_BRAKIG_THRESHOLD;
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event,id_change,cert_sign=false로 설정된 것을 확인한다.
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->cert_sign);

#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  OSRTDListNode *node = bsm->partII.head;
  auto *content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  VehicleSafetyExtensions *ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_FALSE(ext->m.eventsPresent); // 차량이벤트 정보가 수납되지 않은 것을 확인한다.
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  OSRTDListNode *node = bsm.partII.head;
  PartIIcontent *content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  VehicleSafetyExtensions ext;
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_FALSE(ext.m.eventsPresent); // 차량이벤트 정보가 수납되지 않은 것을 확인한다.
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_FALSE(exts->events_option); // 차량이벤트 정보가 수납되지 않은 것을 확인한다.
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * Hard braking 조건을 만족하면 BSM 내 이벤트가 set 되는 것을 확인한다.
   */
  g_test_gps_data[g_test_gps_data_idx+1].attitude.acc_x = J29451_HARD_BRAKIG_THRESHOLD - 0.0001;
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event,cert_sign=true, id_change=false로 설정된 것을 확인한다.
  ASSERT_TRUE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(entry->id_change);

#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  node = bsm->partII.head;
  content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_TRUE(ext->m.eventsPresent); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((ext->events.data[0] >> 0) & 1); // hard_braking 이벤트가 set된 것을 확인한다.
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  node = bsm.partII.head;
  content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_TRUE(ext.m.eventsPresent); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((ext.events.data[0] >> 0) & 1); // hard_braking 이벤트가 set된 것을 확인한다.
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts->events_option); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((*(exts->events.buf) >> 0) & 1); // hard_braking 이벤트가 set된 것을 확인한다.
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * Hard braking 조건이 해제되면 BSM 내 이벤트가 clear 되는 것을 확인한다.
   *  - 필터효과를 감안하여 적절히 큰 변경값을 적용한다.
   */
  g_test_gps_data[g_test_gps_data_idx+1].attitude.acc_x = J29451_HARD_BRAKIG_THRESHOLD + 3;
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event,cert_sign=false로 설정된 것을 확인한다.
  ASSERT_FALSE(entry->event);
  ASSERT_FALSE(entry->cert_sign);
  // ASSERT_FALSE(entry->id_change); // don't care

#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  node = bsm->partII.head;
  content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_FALSE(ext->m.eventsPresent); // 차량이벤트 정보가 수납되지 않은 것을 확인한다.
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  node = bsm.partII.head;
  content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_FALSE(ext.m.eventsPresent); // 차량이벤트 정보가 수납되지 않은 것을 확인한다.
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_FALSE(exts->events_option); // 차량이벤트 정보가 수납되지 않은 것을 확인한다.
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * Hard braking 조건을 만족하면 BSM 내 이벤트가 set 되는 것을 확인한다. (다른 이벤트와 함께)
   *  - 필터효과를 감안하여 적절히 큰 변경값을 적용한다.
   */
  struct J29451VehicleEventFlags event = {true, false, false, false, false, false, false, false, false, false, false, false, false};
  ASSERT_EQ(J29451_SetVehicleEventFlags(&event), kJ29451Result_Success);
  g_test_gps_data[g_test_gps_data_idx+1].attitude.acc_x = J29451_HARD_BRAKIG_THRESHOLD - 7;
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event,cert_sign=true, id_change=false로 설정된 것을 확인한다.
  ASSERT_TRUE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(entry->id_change);

#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  node = bsm->partII.head;
  content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_TRUE(ext->m.eventsPresent); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((ext->events.data[0] >> 7) & 1); // hazard_lights
  ASSERT_TRUE((ext->events.data[0] >> 0) & 1); // hard_braking 이벤트가 set된 것을 확인한다.
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  node = bsm.partII.head;
  content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_TRUE(ext.m.eventsPresent); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((ext.events.data[0] >> 7) & 1); // hazard_lights
  ASSERT_TRUE((ext.events.data[0] >> 0) & 1); // hard_braking 이벤트가 set된 것을 확인한다.
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts->events_option); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((*(exts->events.buf) >> 7) & 1); // hazard_lights
  ASSERT_TRUE((*(exts->events.buf) >> 0) & 1); // hard_braking 이벤트가 set된 것을 확인한다.
  J29451_FreeDecodedMessageFrame(msg);
#endif

  /*
   * Hard braking 조건이 해제되면 BSM 내 이벤트가 clear 되는 것을 확인한다. (다른 이벤트는 유지)
   *  - 필터효과를 감안하여 적절히 큰 변경값을 적용한다.
   */
  event.hard_braking = true;
  ASSERT_EQ(J29451_SetVehicleEventFlags(&event), kJ29451Result_Success); // Code coverage를 높이기 위한 설정 (동작 자체에는 영향 x)
  g_test_gps_data[g_test_gps_data_idx+1].attitude.acc_x = J29451_HARD_BRAKIG_THRESHOLD + 13;
  while(g_bsm_callback_list.entry_num == rx_pkt_num);
  rx_pkt_num++;
  entry = TAILQ_NEXT(entry, entries);
  ASSERT_TRUE(entry != nullptr);

  // 콜백함수의 event,cert_sign=true, id_change=false로 설정된 것을 확인한다.
  ASSERT_TRUE(entry->event);
  ASSERT_TRUE(entry->cert_sign);
  ASSERT_FALSE(entry->id_change);

#if defined(_OBJASN1C_)
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  ASSERT_TRUE(bsm->m.partIIPresent);
  node = bsm->partII.head;
  content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_TRUE(ext->m.eventsPresent); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((ext->events.data[0] >> 7) & 1); // hazard_lights
  ASSERT_FALSE((ext->events.data[0] >> 0) & 1); // hard_braking 이벤트가 clear된 것을 확인한다.
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
  ASSERT_TRUE(bsm.m.partIIPresent);
  node = bsm.partII.head;
  content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_TRUE(ext.m.eventsPresent); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((ext.events.data[0] >> 7) & 1); // hazard_lights
  ASSERT_FALSE((ext.events.data[0] >> 0) & 1); // hard_braking 이벤트가 clear된 것을 확인한다.
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
  content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts->events_option); // 차량이벤트 정보가 수납된 것을 확인한다.
  ASSERT_TRUE((*(exts->events.buf) >> 7) & 1); // hazard_lights
  ASSERT_FALSE((*(exts->events.buf) >> 0) & 1); // hard_braking 이벤트가 clear 된 것을 확인한다.
  J29451_FreeDecodedMessageFrame(msg);
#endif

  J29451Test_ReleaseEnv();
}


/*
 * Vehicle Size 정보가 존재하지 않으면(유효하지 않으면) BSM을 전송하지 않는 것을 확인한다.
 */
TEST(CHECK_VEHICLE_IN_BSM, NO_VEHICLE_SIZE)
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
   * width가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_j29451_mib.vehicle.size.width = kJ29451VehicleWidth_Unavailable;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * length가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_j29451_mib.vehicle.size.length = kJ29451VehicleLength_Unavailable;
  g_j29451_mib.vehicle.size.width = TEST_VEHICLE_INFO_INITIAL_WIDTH;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * width/length가 모두 유효해지면 BSM 전송이 시작되면서 콜백함수가 정상적으로 호출되는 것을 확인한다.
   */
  g_j29451_mib.vehicle.size.length = TEST_VEHICLE_INFO_INITIAL_LENGTH;
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  /*
   * BSM 디코딩 및 데이터 비교 - 강제로 설정한 데이터가 맞게 수납되었는지 확인한다.
   */
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
  //  ASSERT_EQ(bsm->coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 알 수 없다.
  ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
  ASSERT_EQ(bsm->coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
  ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
  ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
  ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm->coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  ASSERT_EQ(bsm->coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
  ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
  ASSERT_EQ(bsm->coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_x));
  ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_y));
  ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_z));
  ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].attitude.gyro_z));
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
  ASSERT_EQ(bsm->coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.abs_, kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
  ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
  ASSERT_TRUE(bsm->m.partIIPresent);
  OSRTDListNode *node = bsm->partII.head;
  auto *content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  VehicleSafetyExtensions *ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_FALSE(ext->m.eventsPresent);
  ASSERT_TRUE(ext->m.pathHistoryPresent);
  ASSERT_TRUE(ext->m.pathPredictionPresent);
  ASSERT_FALSE(ext->m.lightsPresent);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
//  ASSERT_EQ(bsm->coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 알 수 없다.
  ASSERT_EQ(bsm.coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
  ASSERT_EQ(bsm.coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
  ASSERT_EQ(bsm.coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
  ASSERT_EQ(bsm.coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
  ASSERT_EQ(bsm.coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
  ASSERT_EQ(bsm.coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
  ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm.coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  ASSERT_EQ(bsm.coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
  ASSERT_EQ(bsm.coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
  ASSERT_EQ(bsm.coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lat));
  ASSERT_EQ(bsm.coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lon));
  ASSERT_EQ(bsm.coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.vert));
  ASSERT_EQ(bsm.coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].accel.yaw));
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
  ASSERT_EQ(bsm.coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.albs, kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
  ASSERT_EQ(bsm.coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
  ASSERT_TRUE(bsm.m.partIIPresent);
  OSRTDListNode *node = bsm.partII.head;
  PartIIcontent *content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  VehicleSafetyExtensions ext;
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_FALSE(ext.m.eventsPresent);
  ASSERT_TRUE(ext.m.pathHistoryPresent);
  ASSERT_TRUE(ext.m.pathPredictionPresent);
  ASSERT_FALSE(ext.m.lightsPresent);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
//  ASSERT_EQ(bsm->coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 알 수 없다.
  ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
  ASSERT_EQ(bsm->coreData.Long, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
  ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
  ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
  ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm->coreData.speed, (int)j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  ASSERT_EQ(bsm->coreData.heading, (int)j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
  ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
  // 가속도 값들은 butter-worth filter를 거치기 때문에 테스트입력값과 출력값이 다를 수 있다.
  // 따라서 가속도값들에 대한 비교는 생략한다 (가속도값들의 정확성은 J2945/1 드라이빙테스트를 통해 확인할 수 있다)
#if 0
  ASSERT_EQ(bsm->coreData.accelSet.Long, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_x));
  ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_y));
  ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_z));
  ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].attitude.gyro_z));
#endif
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 7) & 1, 1); // unavailable: set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 6) & 1, 0); // left front: not set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 5) & 1, 0); // left rear: not set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 4) & 1, 0); // right front: not set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 3) & 1, 0); // right rear: not set
  ASSERT_EQ(bsm->coreData.brakes.traction, (int)kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.albs, (int)kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.scs, (int)kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.brakeBoost, (int)kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.auxBrakes, (int)kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
  ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
  ASSERT_TRUE(bsm->partII_option);
  auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts != nullptr);
  ASSERT_FALSE(exts->events_option);
  // PH & PP의 내용 확인은 생략한다
  ASSERT_TRUE(exts->pathHistory_option); // per j2945/1
  ASSERT_FALSE(exts->pathHistory.initialPosition_option); // per j2945/1
  ASSERT_FALSE(exts->pathHistory.currGNSSstatus_option); // per j2945/1
  ASSERT_TRUE(exts->pathPrediction_option); // per j2945/1
  ASSERT_FALSE(exts->lights_option);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  J29451Test_ReleaseEnv();
}
