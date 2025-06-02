/**
 * @file
 * @brief Dot3_GetResultStr() API에 대한 단위테스트 구현 파일
 * @date 2022-03-30
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_GetResultStr() API 호출 시 정상적인 결과설명문자열이 반환되는 것을 확인한다.
 */
TEST(Dot3_GetResultStr, NORMAL)
{
  const char *str;

  /*
   * 유효한 리턴값을 전달하면 정상적인 문자열이 반환되는 것을 확인한다.
   */
  ASSERT_TRUE((str = Dot3_GetResultStr(kDot3Result_Success)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_Success") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NullParameters)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NullParameters") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMPayloadSize)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMPayloadSize") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidPSID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidPSID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidPSIDFormat)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidPSIDFormat") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidPriority)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidPriority") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidChannelNumber)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidChannelNumber") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidDataRate)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidDataRate") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidPower)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidPower") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidOperatingClass)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidOperatingClass") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSARCPIThreshold)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSARCPIThreshold") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSACountThreshold)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSACountThreshold") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSACountThresholdInterval)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSACountThresholdInterval") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSAType)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSAType") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidRCPI)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidRCPI") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidUASManagementInterval)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidUASManagementInterval") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidChannelIndex)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidChannelIndex") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMPNHeaderSubType)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMPNHeaderSubType") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMPNHeaderExtensionID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMPNHeaderExtensionID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMPNHeaderTPID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMPNHeaderTPID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMPNHeaderWSMPVersion)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMPNHeaderWSMPVersion") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidLowerLayerProtocolVersion)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidLowerLayerProtocolVersion") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidLowerLayerFrameType)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidLowerLayerFrameType") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSAIdentifier)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSAIdentifier") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSAContentCount)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSAContentCount") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidChannelAccess)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidChannelAccess") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidAdvertiserIDLen)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidAdvertiserIDLen") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidPSCLen)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidPSCLen") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidLatitude)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidLatitude") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidLongitude)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidLongitude") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidElevation)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidElevation") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSAHdrExtensionID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSAHdrExtensionID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWCIExtensionID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWCIExtensionID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSIExtensionID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSIExtensionID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSAMessage)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSAMessage") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSAVersion)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSAVersion") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidIPv6PrefixLen)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidIPv6PrefixLen") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWRARouterLifetime)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWRARouterLifetime") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMMaxLength)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMMaxLength") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidRepeatRate)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidRepeatRate") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidWSMSize)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidWSMSize") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidMPDUSize)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidMPDUSize") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidAIFSN)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidAIFSN") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidECWMin)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidECWMin") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_InvalidECWMax)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_InvalidECWMax") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_Asn1Encode)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_Asn1Encode") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_Asn1Decode)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_Asn1Decode") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_Asn1AbnormalOp)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_Asn1AbnormalOp") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NotWildcardBSSID)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NotWildcardBSSID") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NotSupportedEtherType)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NotSupportedEtherType") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_WSRTableFull)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_WSRTableFull") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_DuplicatedWSR)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_DuplicatedWSR") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NoSuchWSR)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NoSuchWSR") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_PSRTableFull)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_PSRTableFull") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_DuplicatedPSR)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_DuplicatedPSR") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NoSuchPSR)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NoSuchPSR") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_PCITableFull)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_PCITableFull") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NoSuchPCI)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NoSuchPCI") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_USRTableFull)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_USRTableFull") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_DuplicatedUSR)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_DuplicatedUSR") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NoSuchUSR)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NoSuchUSR") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_UASTableFull)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_UASTableFull") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_AlreadyRunning)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_AlreadyRunning") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NoRelatedChannelInfo)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NoRelatedChannelInfo") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_NoMemory)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_NoMemory") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(-kDot3Result_SystemCallFailed)) != nullptr);
  ASSERT_TRUE(strcmp(str, "kDot3Result_SystemCallFailed") == 0);

  /*
   * 유효하지 않은 리턴값을 전달하면 에러 메시지가 반환되는 것을 확인한다.
   */
  ASSERT_TRUE((str = Dot3_GetResultStr(-(kDot3Result_SystemCallFailed + 1))) != nullptr);
  ASSERT_TRUE(strcmp(str, "No result string - You may specify invalid return value") == 0);
  ASSERT_TRUE((str = Dot3_GetResultStr(1)) != nullptr);
  ASSERT_TRUE(strcmp(str, "No result string - You may specify invalid return value") == 0);
}
