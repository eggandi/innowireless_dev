/** 
  * @file 
  * @brief SignedData 유형 SPDU의 생성/처리 기능에 대한 테스트 구현 파일
  * @date 2021-06-24 
  * @author gyun 
  */


// 이제 하나의 장치에서 RSU 인증서와 OBU 인증서를 동시에 사용할 수 없으므로 본 테스트는 삭제

// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"



/**
 * @brief Application CMH를 이용한 SPDU 생성/처리를 테스트한다.
 */
TEST(EXCHANGE_SIGNED_SPDU, APPLICATION_CMH)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_0_SCCCerts();

  /*
   * 서명에 사용되는 Application CMHF들을 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_AppCMHFs();

  /*
   * WSA용 Security profile을 추가한다 - PSID=135에 대한 security profile이 등록된다.
   */
  Dot2Test_AddWSASecurityProfile();

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * App CMH#0을 이용한 SPDU 생성/처리가 성공하는 것을 확인한다.
   */
  {
    // SPDU 생성
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537111334000000ULL; // App 인증서#0의 유효기간 시작시점
    params.signed_data.psid = 135; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = 375163721;
    params.signed_data.gen_location.lon = 1270332651;
    params.signed_data.gen_location.elev = 0;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.ret > 0); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

    // SPDU 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = res.spdu;
    size_t spdu_size = res.ret;
    struct Dot2SPDUProcessParams proc_params = {537111334000000ULL, 135, {375163721, 1270332651}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 537111334000000ULL);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 537111334000000ULL + 30000000ULL/*security profile에 저장된 SPDU lifetime*/);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 375163721);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270332651);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0);
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
    free(res.spdu);
  }

  /*
   * App CMH#1을 이용한 SPDU 생성/처리가 성공하는 것을 확인한다.
   *  - 다이제스트로 서명된 첫번째 SPDU는 실패 처리된다. (아직 인증서가 수신되지 않아 검증이 불가능하므로)
   *  - 인증서로 서명된 두번째 SPDU는 성공 처리된다.
   *  - 다이제스트로 서명된 세번째 SPDU는 이제 성공 처리된다.
   */
  {
    // 다이제스트로 서명된 첫번째 SPDU -> 처리 실패
    {
      // SPDU 생성
      memset(&params, 0, sizeof(params));
      params.type = kDot2SPDUConstructType_Signed;
      params.time = 540171334000000ULL + 1000000ULL; // App 인증서#1의 유효기간 시작시점 + 1초 (App인증서#0의 유효기간을 벗어난 시점)
      params.signed_data.psid = 135; // Security profile에 등록된 PSID
      params.signed_data.signer_id_type = kDot2SignerId_Digest;
      params.signed_data.gen_location.lat = 375163721 + 1;
      params.signed_data.gen_location.lon = 1270332651 + 1;
      params.signed_data.gen_location.elev = 0 + 1;
      params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_TRUE(res.ret > 0); // 생성된 SPDU의 길이를 확인
      ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

      // SPDU 처리
      struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
      ASSERT_TRUE(parsed != nullptr);
      uint8_t *spdu = res.spdu;
      size_t spdu_size = res.ret;
      struct Dot2SPDUProcessParams proc_params = {540171334000000ULL + 1000000ULL, 135, {375163721, 1270332651}};
      ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
      WAIT_MSG_PROCESS_CALLBACK;
      ASSERT_EQ(g_callbacks.cnt, 2U);
      ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_SPDU_NoSignerIdCertInTable);
      free(res.spdu);
    }

    // 인증서로 서명된 두번째 SPDU -> 처리 성공
    {
      // SPDU 생성
      memset(&params, 0, sizeof(params));
      params.type = kDot2SPDUConstructType_Signed;
      params.time = 540171334000000ULL + 1000000ULL; // App 인증서#1의 유효기간 시작시점 + 1초 (App인증서#0의 유효기간을 벗어난 시점)
      params.signed_data.psid = 135; // Security profile에 등록된 PSID
      params.signed_data.signer_id_type = kDot2SignerId_Certificate;
      params.signed_data.gen_location.lat = 375163721 + 1;
      params.signed_data.gen_location.lon = 1270332651 + 1;
      params.signed_data.gen_location.elev = 0 + 1;
      params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_TRUE(res.ret > 0); // 생성된 SPDU의 길이를 확인
      ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

      // SPDU 처리
      struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
      ASSERT_TRUE(parsed != nullptr);
      uint8_t *spdu = res.spdu;
      size_t spdu_size = res.ret;
      struct Dot2SPDUProcessParams proc_params = {540171334000000ULL + 1000000ULL, 135, {375163721, 1270332651}};
      ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
      WAIT_MSG_PROCESS_CALLBACK;
      ASSERT_EQ(g_callbacks.cnt, 3U);
      ASSERT_EQ(g_callbacks.entry[2].result, kDot2Result_Success);
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 다이제스트로 서명
      ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.psid, 135U); // PSID=135
      ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
      ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
      ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time, 540171334000000ULL + 1000000ULL);
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time, 540171334000000ULL + 1000000ULL + 30000000ULL/*security profile에 저장된 SPDU lifetime*/);
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.lat, 375163721 + 1);
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.lon, 1270332651 + 1);
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.elev, 0 + 1);
      ASSERT_TRUE(g_callbacks.entry[2].parsed->ssdu); // 페이로드 비교
      ASSERT_EQ(g_callbacks.entry[2].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
      ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[2].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
      free(res.spdu);
    }

    // 다이제스트로 서명된 두번째 SPDU -> 처리 성공
    {
      // SPDU 생성
      memset(&params, 0, sizeof(params));
      params.type = kDot2SPDUConstructType_Signed;
      params.time = 540171334000000ULL + 1000000ULL; // App 인증서#1의 유효기간 시작시점 + 1초 (App인증서#0의 유효기간을 벗어난 시점)
      params.signed_data.psid = 135; // Security profile에 등록된 PSID
      params.signed_data.signer_id_type = kDot2SignerId_Digest;
      params.signed_data.gen_location.lat = 375163721 + 1;
      params.signed_data.gen_location.lon = 1270332651 + 1;
      params.signed_data.gen_location.elev = 0 + 1;
      params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_TRUE(res.ret > 0); // 생성된 SPDU의 길이를 확인
      ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

      // SPDU 처리
      struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
      ASSERT_TRUE(parsed != nullptr);
      uint8_t *spdu = res.spdu;
      size_t spdu_size = res.ret;
      struct Dot2SPDUProcessParams proc_params = {540171334000000ULL + 1000000ULL, 135, {375163721, 1270332651}};
      ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
      WAIT_MSG_PROCESS_CALLBACK;
      ASSERT_EQ(g_callbacks.cnt, 4U);
      ASSERT_EQ(g_callbacks.entry[3].result, kDot2Result_Success);
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Digest); // 다이제스트로 서명
      ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.psid, 135U); // PSID=135
      ASSERT_TRUE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
      ASSERT_TRUE(g_callbacks.entry[3].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
      ASSERT_TRUE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.gen_time, 540171334000000ULL + 1000000ULL);
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.expiry_time, 540171334000000ULL + 1000000ULL + 30000000ULL/*security profile에 저장된 SPDU lifetime*/);
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location.lat, 375163721 + 1);
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location.lon, 1270332651 + 1);
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location.elev, 0 + 1);
      ASSERT_TRUE(g_callbacks.entry[3].parsed->ssdu); // 페이로드 비교
      ASSERT_EQ(g_callbacks.entry[3].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
      ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[3].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
      free(res.spdu);
    }
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}



/**
 * @brief Pseudonym CMH를 이용한 SPDU 생성/처리를 테스트한다.
 */
TEST(EXCHANGE_SIGNED_SPDU, PSEUDONYM_CMH)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_0_SCCCerts();

  /*
   * 서명에 사용되는 Application CMHF들을 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_PseudonymCMHFs();

  /*
   * WSA용 Security profile을 추가한다 - PSID=135에 대한 security profile이 등록된다.
   */
  Dot2Test_AddBSMSecurityProfile();

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * Pseudonym CMH 세트#0을 이용한 SPDU 생성/처리가 성공하는 것을 확인한다.
   */
  {
    // SPDU 생성
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537526803000001ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
    params.signed_data.psid = 32; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.ret > 0);
    ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

    // SPDU 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = res.spdu;
    size_t spdu_size = res.ret;
    struct Dot2SPDUProcessParams proc_params = {537526803000001ULL, 32, {375163721, 1270332651}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 32U);
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
    free(res.spdu);
  }

  /*
   * Pseudonym CMH 세트#0 내 CMH를 변경했을 때 SPDU 생성/처리가 성공하는 것을 확인한다.
   *  - 다이제스트로 서명된 첫번째 SPDU는 실패 처리된다. (아직 인증서가 수신되지 않아 검증이 불가능하므로)
   *  - 인증서로 서명된 두번째 SPDU는 성공 처리된다.
   *  - 다이제스트로 서명된 세번째 SPDU는 이제 성공 처리된다.
   */
  {
    // 다이제스트로 서명된 첫번째 SPDU -> 처리 실패
    {
      // SPDU 생성
      memset(&params, 0, sizeof(params));
      params.type = kDot2SPDUConstructType_Signed;
      params.time = 537526803000001ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
      params.signed_data.psid = 32; // Security profile에 등록된 PSID
      params.signed_data.signer_id_type = kDot2SignerId_Digest;
      params.signed_data.cmh_change = true; // CMH를 바꾸도록 요청
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_TRUE(res.ret > 0);
      ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

      // SPDU 처리
      struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
      ASSERT_TRUE(parsed != nullptr);
      uint8_t *spdu = res.spdu;
      size_t spdu_size = res.ret;
      struct Dot2SPDUProcessParams proc_params = {537526803000001ULL, 32, {375163721, 1270332651}};
      ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
      WAIT_MSG_PROCESS_CALLBACK;
      ASSERT_EQ(g_callbacks.cnt, 2U);
      ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_SPDU_NoSignerIdCertInTable);
      free(res.spdu);
    }

    // 인증서로 서명된 두번째 SPDU -> 처리 성공
    {
      // SPDU 생성
      memset(&params, 0, sizeof(params));
      params.type = kDot2SPDUConstructType_Signed;
      params.time = 537526803000001ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
      params.signed_data.psid = 32; // Security profile에 등록된 PSID
      params.signed_data.signer_id_type = kDot2SignerId_Certificate;
      params.signed_data.cmh_change = false;
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_TRUE(res.ret > 0);
      ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

      // SPDU 처리
      struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
      ASSERT_TRUE(parsed != nullptr);
      uint8_t *spdu = res.spdu;
      size_t spdu_size = res.ret;
      struct Dot2SPDUProcessParams proc_params = {537526803000001ULL, 32, {375163721, 1270332651}};
      ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
      WAIT_MSG_PROCESS_CALLBACK;
      ASSERT_EQ(g_callbacks.cnt, 3U);
      ASSERT_EQ(g_callbacks.entry[2].result, kDot2Result_Success);
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate);
      ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
      ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.psid, 32U);
      ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
      ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
      ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
      ASSERT_TRUE(g_callbacks.entry[2].parsed->ssdu);
      ASSERT_EQ(g_callbacks.entry[2].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
      ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[2].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
      free(res.spdu);
    }

    // 다이제스트로 서명된 두번째 SPDU -> 처리 성공
    {
      // SPDU 생성
      memset(&params, 0, sizeof(params));
      params.type = kDot2SPDUConstructType_Signed;
      params.time = 537526803000001ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
      params.signed_data.psid = 32; // Security profile에 등록된 PSID
      params.signed_data.signer_id_type = kDot2SignerId_Digest;
      params.signed_data.cmh_change = false;
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_TRUE(res.ret > 0);
      ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인

      // SPDU 처리
      struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
      ASSERT_TRUE(parsed != nullptr);
      uint8_t *spdu = res.spdu;
      size_t spdu_size = res.ret;
      struct Dot2SPDUProcessParams proc_params = {537526803000001ULL, 32, {375163721, 1270332651}};
      ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &proc_params, parsed), kDot2Result_Success);
      WAIT_MSG_PROCESS_CALLBACK;
      ASSERT_EQ(g_callbacks.cnt, 4U);
      ASSERT_EQ(g_callbacks.entry[3].result, kDot2Result_Success);
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Digest); // 다이제스트로 서명
      ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
      ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.psid, 32U);
      ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
      ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
      ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포불함
      ASSERT_TRUE(g_callbacks.entry[3].parsed->ssdu);
      ASSERT_EQ(g_callbacks.entry[3].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
      ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[3].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
      free(res.spdu);
    }
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}



#if 0
// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


// 테스트에 사용될 인증서의 개수
#define EXCHANGE_TEST_CERT_NUM (5)

/// 시나리오 별 테스트 SPDU 개수
#define EXCHANGE_TEST_SPDU_NUM (20)

// Alice가 사용할 CMHF들
uint8_t *g_alice_cmhf[EXCHANGE_TEST_CERT_NUM];
size_t g_alice_cmhf_size[EXCHANGE_TEST_CERT_NUM];

// Bob이 사용할 CMHF들
uint8_t *g_bob_cmhf[EXCHANGE_TEST_CERT_NUM];
size_t g_bob_cmhf_size[EXCHANGE_TEST_CERT_NUM];


static void Dot2Test_MakeAliceCMHFs();
static void Dot2Test_MakeBobCMHFs();
static void Dot2Test_AddAliceCMHFs();
static void Dot2Test_AddBobCMHFs();
static void Dot2Test_AddAliceSecurityProfile();
static void Dot2Test_AddBobSecurityProfile();


/**
 * @brief Alice가 SignedData를 Bob에게 전송하는 시나리오 테스트
 */
TEST(EXCHANGE_SIGNED_DATA, NORMAL)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  uint8_t signed_data[kDot2MsgSize_Max];
  struct timespec ts_start, ts_end;
  uint64_t process_time_usec;


  /////////////////////// 준비 단계 ///////////////////////////////////////////////////////
  /*
   * 사전에 각 CMHF들을 생성한다.
   */
  Dot2Test_MakeAliceCMHFs();
  Dot2Test_MakeBobCMHFs();
  /*
   * 실제 동작 단계에 영향을 주지 않기 위해 장치를 리셋한다.
   */
  Dot2_Release();
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();
  ////////////////////////////////////////////////////////////////////////////////////////


  /////////////////////// 장치 초기화 단계 /////////////////////////////////////////////////
  /*
   * Alice 및 Bob이 사용할 상위(CA)인증서들을 인증서정보테이블에 추가한다.
   */
  Dot2Test_AddCACerts();

  /*
   * Alice가 사용할 RSE용 CMHF들을 CMH 테이블에 추가한다.
   */
  Dot2Test_AddAliceCMHFs();

  /*
   * Bob이 사용할 OBU용 CMHF들을 CMH 테이블에 추가한다.
   */
  Dot2Test_AddBobCMHFs();

  /*
   * Alice가 사용할 RSE용 Security profile들을 Security profile 테이블에 추가한다.
   */
  Dot2Test_AddAliceSecurityProfile();

  /*
   * Bob이 사용할 OBU용 Security profile들을 Security profile 테이블에 추가한다.
   */
  Dot2Test_AddBobSecurityProfile();
  ////////////////////////////////////////////////////////////////////////////////////////

#if 0 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  struct timespec test_start_ts;
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #1 rse-0 인증서 유효기간 ///////////////////////////////
  /*
   * Alice가 100msec 주기로 rse-0 인증서를 이용하여 서명메시지를 생성하여 전송하고, Bob이 수신하여 처리한다.
   *  - 시스템 시각을 rse-0 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 450msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2019-10-30 13:03:08'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive RSE message (Alice -> Bob)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_rse_0_psid; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_rse_0_valid_lat;
    construct_params.signed_data.lon = g_sample_rse_0_valid_lon;
    construct_params.signed_data.elev = g_sample_rse_0_valid_elev;
    construct_params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_rse_0_cert_signed_data_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_rse_0_digest_signed_data_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_rse_0_psid);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_rse_0_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_rse_0_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_rse_0_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  struct timespec test_end_ts;
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #2 obu-10a-0 인증서 유효기간 ////////////////////////////
  /*
   * Bob이 100msec 주기로 obu-10a-0 인증서를 이용하여 서명메시지를 생성하여 전송하고, Alice가 수신하여 처리한다.
   *  - 시스템 시각을 obu-10a-0 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 495msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-02-11 09:00:03'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive OBU message (Bob -> Alice)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_obu_10a_0_psid_pvd; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_obu_10a_0_valid_lat;
    construct_params.signed_data.lon = g_sample_obu_10a_0_valid_lon;
    construct_params.signed_data.elev = g_sample_obu_10a_0_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10a_0_cert_signed_pvd_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10a_0_digest_signed_pvd_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 38, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_obu_10a_0_psid_pvd);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_obu_10a_0_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_obu_10a_0_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_obu_10a_0_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #3 rse-1 인증서 유효기간 ///////////////////////////////
  /*
   * Alice가 100msec 주기로 rse-1 인증서를 이용하여 서명메시지를 생성하여 전송하고, Bob이 수신하여 처리한다.
   *  - 시스템 시각을 rse-1 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 450msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2019-12-04 23:03:08'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive RSE message (Alice -> Bob)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_rse_1_psid; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_rse_1_valid_lat;
    construct_params.signed_data.lon = g_sample_rse_1_valid_lon;
    construct_params.signed_data.elev = g_sample_rse_1_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_rse_1_cert_signed_data_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_rse_1_digest_signed_data_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_rse_1_psid);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_rse_1_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_rse_1_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_rse_1_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #4 obu-10b-0 인증서 유효기간 ////////////////////////////
  /*
   * Bob이 100msec 주기로 obu-10b-0 인증서를 이용하여 서명메시지를 생성하여 전송하고, Alice가 수신하여 처리한다.
   *  - 시스템 시각을 obu-10b-0 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 495msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-02-18 09:00:03'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive OBU message (Bob -> Alice)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_obu_10b_0_psid_pvd; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_obu_10b_0_valid_lat;
    construct_params.signed_data.lon = g_sample_obu_10b_0_valid_lon;
    construct_params.signed_data.elev = g_sample_obu_10b_0_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10b_0_cert_signed_pvd_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10b_0_digest_signed_pvd_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 38, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_obu_10b_0_psid_pvd);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_obu_10b_0_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_obu_10b_0_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_obu_10b_0_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #5 rse-2 인증서 유효기간 ///////////////////////////////
  /*
   * Alice가 100msec 주기로 rse-2 인증서를 이용하여 서명메시지를 생성하여 전송하고, Bob이 수신하여 처리한다.
   *  - 시스템 시각을 rse-2 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 450msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-01-09 09:03:08'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive RSE message (Alice -> Bob)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_rse_2_psid; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_rse_2_valid_lat;
    construct_params.signed_data.lon = g_sample_rse_2_valid_lon;
    construct_params.signed_data.elev = g_sample_rse_2_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_rse_2_cert_signed_data_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_rse_2_digest_signed_data_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_rse_2_psid);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_rse_2_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_rse_2_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_rse_2_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #6 obu-10c-0 인증서 유효기간 ////////////////////////////
  /*
   * Bob이 100msec 주기로 obu-10c-0 인증서를 이용하여 서명메시지를 생성하여 전송하고, Alice가 수신하여 처리한다.
   *  - 시스템 시각을 obu-10c-0 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 495msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-02-25 09:00:03'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive OBU message (Bob -> Alice)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_obu_10c_0_psid_pvd; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_obu_10c_0_valid_lat;
    construct_params.signed_data.lon = g_sample_obu_10c_0_valid_lon;
    construct_params.signed_data.elev = g_sample_obu_10c_0_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10c_0_cert_signed_pvd_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10c_0_digest_signed_pvd_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 38, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_obu_10c_0_psid_pvd);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_obu_10c_0_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_obu_10c_0_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_obu_10c_0_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #7 rse-3 인증서 유효기간 ///////////////////////////////
  /*
   * Alice가 100msec 주기로 rse-3 인증서를 이용하여 서명메시지를 생성하여 전송하고, Bob이 수신하여 처리한다.
   *  - 시스템 시각을 rse-3 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 450msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-02-13 19:03:08'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive RSE message (Alice -> Bob)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_rse_3_psid; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_rse_3_valid_lat;
    construct_params.signed_data.lon = g_sample_rse_3_valid_lon;
    construct_params.signed_data.elev = g_sample_rse_3_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_rse_3_cert_signed_data_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_rse_3_digest_signed_data_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_rse_3_psid);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_rse_3_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_rse_3_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_rse_3_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #8 obu-10d-0 인증서 유효기간 ////////////////////////////
  /*
   * Bob이 100msec 주기로 obu-10d-0 인증서를 이용하여 서명메시지를 생성하여 전송하고, Alice가 수신하여 처리한다.
   *  - 시스템 시각을 obu-10d-0 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 495msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-03-03 09:00:03'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive OBU message (Bob -> Alice)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_obu_10d_0_psid_pvd; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_obu_10d_0_valid_lat;
    construct_params.signed_data.lon = g_sample_obu_10d_0_valid_lon;
    construct_params.signed_data.elev = g_sample_obu_10d_0_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10d_0_cert_signed_pvd_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10d_0_digest_signed_pvd_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 38, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_obu_10d_0_psid_pvd);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_obu_10d_0_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_obu_10d_0_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_obu_10d_0_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #9 rse-4 인증서 유효기간 ///////////////////////////////
  /*
   * Alice가 100msec 주기로 rse-4 인증서를 이용하여 서명메시지를 생성하여 전송하고, Bob이 수신하여 처리한다.
   *  - 시스템 시각을 rse-4 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 450msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-03-20 05:03:08'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive RSE message (Alice -> Bob)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_rse_4_psid; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_rse_4_valid_lat;
    construct_params.signed_data.lon = g_sample_rse_4_valid_lon;
    construct_params.signed_data.elev = g_sample_rse_4_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_rse_4_cert_signed_data_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_rse_4_digest_signed_data_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_rse_4_psid);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_rse_4_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_rse_4_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_rse_4_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  // 결과 리스트를 비운다.
  Dot2Test_FlushProcessSPDUCallbackList();

#if 1 // NOTE:: WSL2 기반 도커로 설치했을 경우, 컨테이너 내 시간 동기화가 수행되지 않는 경우
  sleep(1);
#else
  /*
   * 시스템 시각이 원상복구될 때까지 기다린다.
   */
  while(1) {
    printf("Wait for the system time to recover\n");
    sleep(1);
    clock_gettime(CLOCK_REALTIME, &test_end_ts);
    if (test_end_ts.tv_sec > test_start_ts.tv_sec) {
      break;
    }
  }

  /*
   * 테스트 시작시점을 저장한다 - 각 테스트 종료 후, 원래의 시스템 시각으로 복구되는 것을 확인하기 위해 사용된다.
   */
  clock_gettime(CLOCK_REALTIME, &test_start_ts);
#endif

  /////////////////////// 통신 단계 #10 obu-10e-0 인증서 유효기간 ///////////////////////////
  /*
   * Bob이 100msec 주기로 obu-10e-0 인증서를 이용하여 서명메시지를 생성하여 전송하고, Alice가 수신하여 처리한다.
   *  - 시스템 시각을 obu-10e-0 인증서 유효기간으로 맞춘 후 시도한다.
   *  - Min Inter Cert Time이 495msec이므로, 5번째 메시지마다 인증서로 서명되는 것을 확인한다. (그 외에는 다이제스트로 서명된다)
   */
  system("date -s '2020-03-10 09:00:03'");
  for (unsigned int i = 0; i < EXCHANGE_TEST_SPDU_NUM; i++)
  {
    clock_gettime(CLOCK_REALTIME, &ts_start);

    printf("[%03u] Send/Receive OBU message (Bob -> Alice)\n", i + 1);

    // 서명 메시지 생성
    // 생성된 서명메시지 중 생성시각과 만기시각, 서명은 실행 시마다 달라지므로 메시지 내용은 테스트벡터와 비교할 수 없다.
    struct Dot2SPDUConstructParams construct_params;
    struct Dot2SPDUConstructResult res;
    memset(&construct_params, 0, sizeof(construct_params));
    construct_params.type = kDot2SPDUConstructType_Signed;
    construct_params.time = 0ULL;
    construct_params.signed_data.psid = g_sample_obu_10e_0_psid_pvd; // Security profile에 등록된 PSID
    construct_params.signed_data.signer_id_type = kDot2SignerId_Profile;
    construct_params.signed_data.lat = g_sample_obu_10e_0_valid_lat;
    construct_params.signed_data.lon = g_sample_obu_10e_0_valid_lon;
    construct_params.signed_data.elev = g_sample_obu_10e_0_valid_elev;
    construct_params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&construct_params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    if (i % 5 == 0) {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10e_0_cert_signed_pvd_size);
    } else {
      ASSERT_EQ(res.ret, (int)g_sample_obu_10e_0_digest_signed_pvd_size);
    }

    // 서명 메시지 처리
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams process_params = {0, 38, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(res.spdu, res.ret, &process_params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, i + 1);
    ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.content_type, kDot2Content_SignedData);
    ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size);
    ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size));
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.ext_hash_present, false);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.psid, g_sample_obu_10e_0_psid_pvd);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_time_present, true); // gen_time의 정확한 값은 알 수 없다.
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.expiry_time, g_callbacks.entry[i].parsed->dot2.gen_time + 30 * 1000 * 1000);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_location_present, true);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lat, g_sample_obu_10e_0_valid_lat);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_lon, g_sample_obu_10e_0_valid_lon);
    ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.gen_elev, g_sample_obu_10e_0_valid_elev);
    if (i % 5 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Certificate);
    } else {
      ASSERT_EQ(g_callbacks.entry[i].parsed->dot2.signer_id_type, kDot2SignerId_Digest);
    }

    // 서명 메시지 해제
    free(res.spdu);

    clock_gettime(CLOCK_REALTIME, &ts_end);
    process_time_usec =
      ((ts_end.tv_sec * 1000000) + (ts_end.tv_nsec / 1000)) - ((ts_start.tv_sec * 1000000) + (ts_start.tv_nsec / 1000));

    // 100msec 마다 전송하는 것처럼 동작하도록 지연
    usleep(100000 - process_time_usec);
  }
  ////////////////////////////////////////////////////////////////////////////////////////

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Alice가 사용할 RSE 인증서들(rse-0 ~ rse-4)에 대한 CMHF들을 생성한다.
 */
static void Dot2Test_MakeAliceCMHFs()
{
  char cmhf_name[kDot2CMHFNameLen_Max];
  g_alice_cmhf[0] = Dot2_MakeImplicitCertCMHF(g_sample_rse_0_cr_priv_key,
                                              g_sample_rse_0_recon_priv,
                                              g_sample_rse_0_cert,
                                              g_sample_rse_0_cert_size,
                                              g_sample_pca_cert,
                                              g_sample_pca_cert_size,
                                              cmhf_name,
                                              sizeof(cmhf_name),
                                              (int *)&g_alice_cmhf_size[0]);
  ASSERT_TRUE(g_alice_cmhf[0] != nullptr);
  g_alice_cmhf[1] = Dot2_MakeImplicitCertCMHF(g_sample_rse_1_cr_priv_key,
                                              g_sample_rse_1_recon_priv,
                                              g_sample_rse_1_cert,
                                              g_sample_rse_1_cert_size,
                                              g_sample_pca_cert,
                                              g_sample_pca_cert_size,
                                              cmhf_name,
                                              sizeof(cmhf_name),
                                              (int *)&g_alice_cmhf_size[1]);
  ASSERT_TRUE(g_alice_cmhf[1] != nullptr);
  g_alice_cmhf[2] = Dot2_MakeImplicitCertCMHF(g_sample_rse_2_cr_priv_key,
                                              g_sample_rse_2_recon_priv,
                                              g_sample_rse_2_cert,
                                              g_sample_rse_2_cert_size,
                                              g_sample_pca_cert,
                                              g_sample_pca_cert_size,
                                              cmhf_name,
                                              sizeof(cmhf_name),
                                              (int *)&g_alice_cmhf_size[2]);
  ASSERT_TRUE(g_alice_cmhf[2] != nullptr);
  g_alice_cmhf[3] = Dot2_MakeImplicitCertCMHF(g_sample_rse_3_cr_priv_key,
                                              g_sample_rse_3_recon_priv,
                                              g_sample_rse_3_cert,
                                              g_sample_rse_3_cert_size,
                                              g_sample_pca_cert,
                                              g_sample_pca_cert_size,
                                              cmhf_name,
                                              sizeof(cmhf_name),
                                              (int *)&g_alice_cmhf_size[3]);
  ASSERT_TRUE(g_alice_cmhf[3] != nullptr);
  g_alice_cmhf[4] = Dot2_MakeImplicitCertCMHF(g_sample_rse_4_cr_priv_key,
                                              g_sample_rse_4_recon_priv,
                                              g_sample_rse_4_cert,
                                              g_sample_rse_4_cert_size,
                                              g_sample_pca_cert,
                                              g_sample_pca_cert_size,
                                              cmhf_name,
                                              sizeof(cmhf_name),
                                              (int *)&g_alice_cmhf_size[4]);
  ASSERT_TRUE(g_alice_cmhf[4] != nullptr);
}


/**
 * @brief Bob이 사용할 OBU 인증서에 대한 CMHF들을 생성한다.
 */
static void Dot2Test_MakeBobCMHFs()
{
  char cmhf_name[kDot2CMHFNameLen_Max];
  g_bob_cmhf[0] = Dot2_MakeButterflyImplicitCertCMHF(g_sample_obu_10a_0_i,
                                                     g_sample_obu_10a_0_j,
                                                     g_sample_obu_expansion_key,
                                                     g_sample_obu_seed_priv,
                                                     g_sample_obu_10a_0_recon_priv,
                                                     g_sample_obu_10a_0_cert,
                                                     g_sample_obu_10a_0_cert_size,
                                                     g_sample_pca_cert,
                                                     g_sample_pca_cert_size,
                                                     cmhf_name, sizeof(cmhf_name),
                                                     (int *)&g_bob_cmhf_size[0]);
  ASSERT_TRUE(g_bob_cmhf[0] != nullptr);
  g_bob_cmhf[1] = Dot2_MakeButterflyImplicitCertCMHF(g_sample_obu_10b_0_i,
                                                     g_sample_obu_10b_0_j,
                                                     g_sample_obu_expansion_key,
                                                     g_sample_obu_seed_priv,
                                                     g_sample_obu_10b_0_recon_priv,
                                                     g_sample_obu_10b_0_cert,
                                                     g_sample_obu_10b_0_cert_size,
                                                     g_sample_pca_cert,
                                                     g_sample_pca_cert_size,
                                                     cmhf_name, sizeof(cmhf_name),
                                                     (int *)&g_bob_cmhf_size[1]);
  ASSERT_TRUE(g_bob_cmhf[1] != nullptr);
  g_bob_cmhf[2] = Dot2_MakeButterflyImplicitCertCMHF(g_sample_obu_10c_0_i,
                                                     g_sample_obu_10c_0_j,
                                                     g_sample_obu_expansion_key,
                                                     g_sample_obu_seed_priv,
                                                     g_sample_obu_10c_0_recon_priv,
                                                     g_sample_obu_10c_0_cert,
                                                     g_sample_obu_10c_0_cert_size,
                                                     g_sample_pca_cert,
                                                     g_sample_pca_cert_size,
                                                     cmhf_name, sizeof(cmhf_name),
                                                     (int *)&g_bob_cmhf_size[2]);
  ASSERT_TRUE(g_bob_cmhf[2] != nullptr);
  g_bob_cmhf[3] = Dot2_MakeButterflyImplicitCertCMHF(g_sample_obu_10d_0_i,
                                                     g_sample_obu_10d_0_j,
                                                     g_sample_obu_expansion_key,
                                                     g_sample_obu_seed_priv,
                                                     g_sample_obu_10d_0_recon_priv,
                                                     g_sample_obu_10d_0_cert,
                                                     g_sample_obu_10d_0_cert_size,
                                                     g_sample_pca_cert,
                                                     g_sample_pca_cert_size,
                                                     cmhf_name, sizeof(cmhf_name),
                                                     (int *)&g_bob_cmhf_size[3]);
  ASSERT_TRUE(g_bob_cmhf[3] != nullptr);
  g_bob_cmhf[4] = Dot2_MakeButterflyImplicitCertCMHF(g_sample_obu_10e_0_i,
                                                     g_sample_obu_10e_0_j,
                                                     g_sample_obu_expansion_key,
                                                     g_sample_obu_seed_priv,
                                                     g_sample_obu_10e_0_recon_priv,
                                                     g_sample_obu_10e_0_cert,
                                                     g_sample_obu_10e_0_cert_size,
                                                     g_sample_pca_cert,
                                                     g_sample_pca_cert_size,
                                                     cmhf_name, sizeof(cmhf_name),
                                                     (int *)&g_bob_cmhf_size[4]);
  ASSERT_TRUE(g_bob_cmhf[4] != nullptr);
}


/**
 * @brief Alice의 CMHF들을 등록한다.
 */
static void Dot2Test_AddAliceCMHFs()
{
  /*
   * rse-0 ~ rse-4 인증서에 대한 CMHF들을 CMH 테이블에 추가한다.
   * 각 인증서에는 psid=135가 포함되어 있다
   * rse-0 유효기간(UTC): 2019-10-30 13:03:08 ~ 2019-12-04 23:03:08
   * rse-1 유효기간(UTC): 2019-12-04 23:03:08 ~ 2020-01-09 09:03:08
   * rse-2 유효기간(UTC): 2020-01-09 09:03:08 ~ 2020-02-13 19:03:08
   * rse-3 유효기간(UTC): 2020-02-13 19:03:08 ~ 2020-03-20 05:03:08
   * rse-4 유효기간(UTC): 2020-03-20 05:03:08 ~ 2020-04-24 15:03:08
   */
  ASSERT_EQ(Dot2_LoadCMHF(g_alice_cmhf[0], g_alice_cmhf_size[0]), 0); // = g_sample_rse_0_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_alice_cmhf[1], g_alice_cmhf_size[1]), 0); // = g_sample_rse_1_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_alice_cmhf[2], g_alice_cmhf_size[2]), 0); // = g_sample_rse_2_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_alice_cmhf[3], g_alice_cmhf_size[3]), 0); // = g_sample_rse_3_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_alice_cmhf[4], g_alice_cmhf_size[4]), 0); // = g_sample_rse_4_cmhf
}


/**
 * @brief Bob의 CMHF들을 등록한다.
 */
static void Dot2Test_AddBobCMHFs()
{
  /*
   * obu-10a-0 ~ obu_10e-0 인증서에 대한 CMHF들을 CMH 테이블에 추가한다.
   * 각 인증서에는 psid=32,38이 포함되어 있다.
   * obu-10a-0 유효기간(UTC): 2020-02-11 09:00:03 ~ 2020-02-18 10:00:03
   * obu-10b-0 유효기간(UTC): 2020-02-18 09:00:03 ~ 2020-02-25 10:00:03
   * obu-10c-0 유효기간(UTC): 2020-02-25 09:00:03 ~ 2020-03-03 10:00:03
   * obu-10d-0 유효기간(UTC): 2020-03-03 09:00:03 ~ 2020-03-10 10:00:03
   * obu-10e-0 유효기간(UTC): 2020-03-10 09:00:03 ~ 2020-03-17 10:00:03
   */
  ASSERT_EQ(Dot2_LoadCMHF(g_bob_cmhf[0], g_bob_cmhf_size[0]), 0); // = g_sample_obu_10a_0_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_bob_cmhf[1], g_bob_cmhf_size[1]), 0); // = g_sample_obu_10b_0_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_bob_cmhf[2], g_bob_cmhf_size[2]), 0); // = g_sample_obu_10c_0_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_bob_cmhf[3], g_bob_cmhf_size[3]), 0); // = g_sample_obu_10d_0_cmhf
  ASSERT_EQ(Dot2_LoadCMHF(g_bob_cmhf[4], g_bob_cmhf_size[4]), 0); // = g_sample_obu_10e_0_cmhf
}


/**
 * @brief Alice의 Security profile을 등록한다.
 */
static void Dot2Test_AddAliceSecurityProfile()
{
  /*
   * Alice는 WSA를 송신한다 -> WSA용 Security profile을 등록한다.
   */
  Dot2Test_AddWSASecurityProfile();
}


/**
 * @brief Bob의 Security profile을 등록한다.
 */
static void Dot2Test_AddBobSecurityProfile()
{
  /*
   * Bob은 PVD를 송신한다 -> PVD용 Security profile을 등록한다.
   */
  Dot2Test_AddPVDSecurityProfile();
}
#endif
