/** 
 * @file
 * @brief Dot3_StartUASManagement() API에 대한 단위테스트 구현 파일
 * @date 2020-07-31
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_StartUASManagement() API 호출 시 UAS 관리 기능이 정상적으로 시작되는 것을 확인한다.
 */
TEST(Dot3_StartUASManagement, NORMAL)
{
  InitTestEnv();

  /*
   * API 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Default), kDot3Result_Success);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_StartUASManagement() API 호출 시 전달되는 interval 파라미터 값에 따른 동작을 확인한다.
 */
TEST(Dot3_StartUASManagement, CHECK_PARAM_INTERVAL)
{
  InitTestEnv();

  /*
   * 최소값 전달 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Min), kDot3Result_Success);
  Dot3_StopUASManagement();

  /*
   * 최대값 전달 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Max), kDot3Result_Success);
  Dot3_StopUASManagement();

  /*
   * 너무 작은 값 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Min - 1), -kDot3Result_InvalidUASManagementInterval);
  Dot3_StopUASManagement();

  /*
   * 너무 작은 값 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Max + 1), -kDot3Result_InvalidUASManagementInterval);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_StartUASManagement() API 호출 시 해당 기능이 이미 동작 중이면 실패하는 것을 확인한다.
 */
TEST(Dot3_StartUASManagement, ALREADY_RUNNING)
{
  InitTestEnv();

  /*
   * 최초 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Min), kDot3Result_Success);

  /*
   * 동작 중일 때 다시 호출 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Max), -kDot3Result_AlreadyRunning);

  ReleaseTestEnv();
}
