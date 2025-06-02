/**
  * @file
  * @brief Dot2_LoadCRL() API 단위테스트
  * @date 2023-03-03
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cert-info/dot2-cert-info-inline.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Hash CRL 기본동작 테스트
 */
TEST(Dot2_LoadCRL, HASH_CRL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t crl[1000];
  Dot2CRLSize crl_size;
  uint8_t ac_h10[10], ac_h8[8];
  uint8_t ac_h1;
  struct Dot2HashBasedCertRevocationEntry *app_cert_revo_entry;
  uint8_t cert_signed_spdu[kDot2SPDUSize_Max], digest_signed_spdu[kDot2SPDUSize_Max];
  size_t cert_signed_spdu_size, digest_signed_spdu_size;
  struct V2XPacketParseData *parsed;
  struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(cert_signed_spdu_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_spdu, cert_signed_spdu), g_tv_bluetech_app_cert_spdu_size);
    ASSERT_EQ(digest_signed_spdu_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_digest_spdu, digest_signed_spdu), g_tv_bluetech_app_cert_digest_spdu_size);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_down, crl), g_tv_bluetech_hash_crl_down_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_app_cert_h10, ac_h10), 10);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_h8, ac_h8), 8);
    ac_h1 = ac_h10[9];

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(crlg.octs, crlg.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 6u);

    // Security profile 등록
    struct Dot2SecProfile sec_profile{};
    memset(&sec_profile, 0, sizeof(sec_profile));
    sec_profile.psid = 135;
    sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
    sec_profile.rx.verify_data = true;
    ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

    // SPDU 처리 콜백합수 등록
    Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
    Dot2Test_InitProcessSPDUCallbackList();
  }

  SAVE_TEST_START_TIME;

  /*
   * 테스트
   */
  {
    // 현재시각을 CRL 유효기간 내로 변경
    system("date -s '2023-03-03 09:11:35'");

    // 정상동작 확인
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size), kDot2Result_Success);

    // 해시기반 정보테이블이 정상적으로 생성되는 것을 확인한다.
    ASSERT_EQ(g_dot2_mib.crl.hash.list[ac_h1].entry_num, 1u);
    app_cert_revo_entry = TAILQ_FIRST(&(g_dot2_mib.crl.hash.list[ac_h1].head));
    ASSERT_TRUE(app_cert_revo_entry);
    ASSERT_TRUE(Dot2Test_CompareOctets(app_cert_revo_entry->h10, ac_h10, 10));

    // 해당 인증서로 서명된 SPDU 수신 시, 처리 실패하는 것을 확인한다.
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed);
    ASSERT_EQ(Dot2_ProcessSPDU(cert_signed_spdu, cert_signed_spdu_size, &params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDUProcess_SignerRevoked);

    // 첫 수신 시, 해당 인증서 정보가 EE 캐시 테이블에 추가된 것을 확인한다.
    struct Dot2EECertCacheEntry *entry = dot2_FindEECertCacheWithH8(ac_h8);
    ASSERT_TRUE(entry);
    ASSERT_TRUE(entry->revoked);

    // 두번째 수신 시, 처리 실패하는 것을 확인한다.
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed);
    ASSERT_EQ(Dot2_ProcessSPDU(cert_signed_spdu, cert_signed_spdu_size, &params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_SPDUProcess_SignerRevoked);
    entry = dot2_FindEECertCacheWithH8(ac_h8);
    ASSERT_TRUE(entry);
    ASSERT_TRUE(entry->revoked);

    // 해당 인증서 다이제스트로 서명된 SPDU 수신 시, 처리 실패하는 것을 확인한다.
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed);
    ASSERT_EQ(Dot2_ProcessSPDU(digest_signed_spdu, digest_signed_spdu_size, &params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 3U);
    ASSERT_EQ(g_callbacks.entry[2].result, -kDot2Result_SPDUProcess_SignerRevoked);
    entry = dot2_FindEECertCacheWithH8(ac_h8);
    ASSERT_TRUE(entry);
    ASSERT_TRUE(entry->revoked);
  }

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief LV CRL 기본동작 테스트
 */
TEST(Dot2_LoadCRL, LV_CRL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t crl[1000];
  Dot2CRLSize crl_size;
  uint8_t pc_h8[8];
  uint8_t lv_1A9[DOT2_LINKAGE_VALUE_LEN], lv_1AA[DOT2_LINKAGE_VALUE_LEN];
  unsigned int i_period_1A9 = g_tv_bluetech_lv_crl_pseudonym_cert_1A9_i;
  unsigned int i_period_1AA = g_tv_bluetech_lv_crl_pseudonym_cert_1AA_i;
  struct Dot2LVBasedCRLEntry *crl_entry;
  struct Dot2LVBasedCertRevocationList *cr_list;
  struct Dot2LVBasedCertRevocationEntry *cr_entry;
  uint8_t cert_signed_spdu[kDot2SPDUSize_Max], digest_signed_spdu[kDot2SPDUSize_Max];
  size_t cert_signed_spdu_size, digest_signed_spdu_size;
  struct V2XPacketParseData *parsed;
  struct Dot2SPDUProcessParams params = {0, 32, {374063230L, 1271023340L}};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(cert_signed_spdu_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_1A9_spdu, cert_signed_spdu), g_tv_bluetech_pseudonym_cert_1A9_spdu_size);
    ASSERT_EQ(digest_signed_spdu_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_1A9_digest_spdu, digest_signed_spdu), g_tv_bluetech_pseudonym_cert_1A9_digest_spdu_size);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lv_crl_down, crl), g_tv_bluetech_lv_crl_down_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lv_crl_pseudonym_cert_1A9_linkage_value, lv_1A9), DOT2_LINKAGE_VALUE_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lv_crl_pseudonym_cert_1AA_linkage_value, lv_1AA), DOT2_LINKAGE_VALUE_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_1A9_h8, pc_h8), 8);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(crlg.octs, crlg.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 6u);

    // Security profile 등록
    struct Dot2SecProfile sec_profile{};
    memset(&sec_profile, 0, sizeof(sec_profile));
    sec_profile.psid = 32;
    sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
    sec_profile.rx.verify_data = true;
    ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

    // SPDU 처리 콜백합수 등록
    Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
    Dot2Test_InitProcessSPDUCallbackList();
  }

  SAVE_TEST_START_TIME;

  /*
   * 테스트
   */
  {
    // 현재시각을 CRL 유효기간 내로 변경
    system("date -s '2023-03-01 09:58:30'");

    // 정상동작 확인
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size), kDot2Result_Success);

    // LV기반 정보테이블이 정상적으로 생성되는 것을 확인한다.
    ASSERT_EQ(g_dot2_mib.crl.lv.entry_num, 1u);
    crl_entry = TAILQ_FIRST(&g_dot2_mib.crl.lv.head);
    ASSERT_TRUE(crl_entry);
    ASSERT_EQ(crl_entry->i, i_period_1A9);
    cr_list = &(crl_entry->list[lv_1A9[DOT2_LINKAGE_VALUE_LEN-1]]);
    ASSERT_EQ(cr_list->entry_num, 1u);
    cr_entry = TAILQ_FIRST(&cr_list->head);
    ASSERT_TRUE(Dot2Test_CompareOctets(cr_entry->lv, lv_1A9, sizeof(lv_1A9)));

    // 해당 인증서로 서명된 SPDU 수신 시, 처리 실패하는 것을 확인한다.
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed);
    ASSERT_EQ(Dot2_ProcessSPDU(cert_signed_spdu, cert_signed_spdu_size, &params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDUProcess_SignerRevoked);

    // 첫 수신 시, 해당 인증서 정보가 EE 캐시 테이블에 추가된 것을 확인한다.
    struct Dot2EECertCacheEntry *entry = dot2_FindEECertCacheWithH8(pc_h8);
    ASSERT_TRUE(entry);
    ASSERT_TRUE(entry->revoked);

    // 두번째 수신 시, 처리 실패하는 것을 확인한다.
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed);
    ASSERT_EQ(Dot2_ProcessSPDU(cert_signed_spdu, cert_signed_spdu_size, &params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_SPDUProcess_SignerRevoked);
    entry = dot2_FindEECertCacheWithH8(pc_h8);
    ASSERT_TRUE(entry);
    ASSERT_TRUE(entry->revoked);

    // 해당 인증서 다이제스트로 서명된 SPDU 수신 시, 처리 실패하는 것을 확인한다.
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed);
    ASSERT_EQ(Dot2_ProcessSPDU(digest_signed_spdu, digest_signed_spdu_size, &params, parsed), kDot2Result_Success);
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 3U);
    ASSERT_EQ(g_callbacks.entry[2].result, -kDot2Result_SPDUProcess_SignerRevoked);
    entry = dot2_FindEECertCacheWithH8(pc_h8);
    ASSERT_TRUE(entry);
    ASSERT_TRUE(entry->revoked);

    // CRL 유효기간을 무시하도록 한다.
    g_dot2_mib.lcm.test.crl.ignore_valid_period = true;

    // iCert 값이 iRev 값보다 커지도록 현재시간을 설정했을 때 정상동작하는 것을 확인한다.
    system("date -s '2023-03-08 09:58:30'");
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.crl.lv.entry_num, 2u);
    crl_entry = TAILQ_NEXT(TAILQ_FIRST(&g_dot2_mib.crl.lv.head), entries);
    ASSERT_TRUE(crl_entry);
    ASSERT_EQ(crl_entry->i, i_period_1AA);
    cr_list = &(crl_entry->list[lv_1AA[DOT2_LINKAGE_VALUE_LEN-1]]);
    ASSERT_EQ(cr_list->entry_num, 1u);
    cr_entry = TAILQ_FIRST(&cr_list->head);
    ASSERT_TRUE(Dot2Test_CompareOctets(cr_entry->lv, lv_1AA, sizeof(lv_1AA)));

    // iCert 값이 iMax 값보다 커지도록 현재시간을 설정했을 때 정상동작하는 것을 확인한다.
    // 내부적으로 처리가 생략되고, 성공이 리턴된다.
    system("date -s '2027-03-08 09:58:30'");
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.crl.lv.entry_num, 2u); // 추가되지 않은 것을 확인
  }

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief 유효하지 않은 파라미터
 */
TEST(Dot2_LoadCRL, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t crl[1000];
  Dot2CRLSize crl_size;
  uint8_t ac_h10[10];

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_down, crl), g_tv_bluetech_hash_crl_down_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_app_cert_h10, ac_h10), 10);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(crlg.octs, crlg.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 6u);
  }

  /*
   * 테스트
   */
  {
    // 널 파라미터 전달
    ASSERT_EQ(Dot2_LoadCRL(nullptr, crl_size), -kDot2Result_NullParameters);

    // 유효하지 않은 CRL 길이 전달
    ASSERT_EQ(Dot2_LoadCRL(crl, kDot2CRLSize_Min - 1), -kDot2Result_CRL_InvalidSize);
    ASSERT_EQ(Dot2_LoadCRL(crl, kDot2CRLSize_Max + 1), -kDot2Result_CRL_InvalidSize);

    // CRL 길이를 실제와 다르게 전달
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size - 1), -kDot2Result_ASN1_DecodeCRL);
  }

  Dot2_Release();
}


/**
 * @brief CRLG 인증서 없음
 */
TEST(Dot2_LoadCRL, NO_CRLG_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t crl[1000];
  Dot2CRLSize crl_size;
  uint8_t ac_h10[10];

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_down, crl), g_tv_bluetech_hash_crl_down_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_app_cert_h10, ac_h10), 10);

    // SCC 인증서 등록 - CRLG 누락
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);
  }

  SAVE_TEST_START_TIME;

  /*
   * 테스트
   */
  {
    // 현재시각을 CRL 유효기간 내로 변경
    system("date -s '2023-03-03 09:11:35'");

    // CRLG 인증서 등록 없이 호출
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size), -kDot2Result_NoSignerIdCertInTable);
  }

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 CRL 유효기간
 */
TEST(Dot2_LoadCRL, INVALID_DATE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t crl[1000];
  Dot2CRLSize crl_size;
  uint8_t ac_h10[10];

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_down, crl), g_tv_bluetech_hash_crl_down_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_hash_crl_app_cert_h10, ac_h10), 10);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(crlg.octs, crlg.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 6u);
  }

  SAVE_TEST_START_TIME;

  /*
   * 테스트
   */
  {
    // 현재시각을 CRL 유효기간 이전으로 변경 후 호출
    system("date -s '2023-03-03 09:11:30'");
    ASSERT_EQ(Dot2_LoadCRL(crl, crl_size), -kDot2Result_CRL_InvalidPeriod);
  }

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}
