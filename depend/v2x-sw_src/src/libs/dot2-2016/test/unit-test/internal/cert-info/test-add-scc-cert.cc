/** 
  * @file 
  * @brief SCC 인증서정보 저장기능에 대한 단위테스트
  * @date 2022-07-02 
  * @author gyun 
  */


// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"
#include "certificate/cert-info/dot2-cert-info.h"


/**
 * @brief SCC에 속한 RCA 인증서정보 저장 기능이 정상동작하는지 확인한다.
 */
TEST(ADD_SCC_CERT, RCA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SCCCertContents expected;
  uint8_t rca_cert[kDot2CertSize_Max];
  size_t rca_cert_size;
  uint8_t rca_cert_h[DOT2_SHA_256_LEN];
  struct Dot2SCCCertInfoEntry *entry_rca;

  /*
   * 준비
   */
  {
    // 기대값 설정
    Dot2Test_InitTestVector_RCACertContents(&expected);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert), g_tv_rca_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_h, rca_cert_h), DOT2_SHA_256_LEN);
  }

  /*
   * 테스트: RCA가 성공적으로 저장되는 것을 확인한다.
   */
  entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
  ASSERT_TRUE(entry_rca != nullptr);
  ASSERT_EQ(ret, kDot2Result_Success);

  /*
   * 확인 - 라이브러리 내부 정보에 접근하여 기대값과 동일한지 비교한다.
   */
  {
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u); // 한개의 인증서정보 엔트리가 추가된 것을 확인한다.
    struct Dot2SCCCertInfoEntry *entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(rca_cert_h));
    ASSERT_TRUE(entry != nullptr); // 엔트리 존재
    // 저장된 엔트리 정보 확인
    ASSERT_TRUE(entry->cert != nullptr); // 인증서바이트열 존재
    ASSERT_EQ(entry->cert_size, rca_cert_size); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert, rca_cert, rca_cert_size)); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert_h.octs, rca_cert_h, DOT2_SHA_256_LEN)); // 해시값 비교
    // 저장된 CA인증서 컨텐츠 확인
    struct Dot2SCCCertContents *contents = &(entry->contents);
    ASSERT_EQ(contents->type, expected.type); // 인증서 종류 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, expected.verify_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
    ASSERT_TRUE(contents->eck_verify_pub_key != nullptr); // EC_KEY 형식 서명검증용 공개키 존재
    ASSERT_TRUE(contents->eck_enc_pub_key == nullptr); // EC_KEY 형식 암호화용 공개키 부재
    // 저장된 CA인증서 공통정보 확인
    ASSERT_EQ(contents->common.type, expected.common.type); // 인증서유형 비교
    ASSERT_EQ(contents->common.issuer.type, expected.common.issuer.type); /// 상위인증서식별자 유형 비교
    ASSERT_EQ(contents->common.id.type, expected.common.id.type); // 인증서 ID 유형 비교
    ASSERT_EQ(contents->common.id.u.name.len, expected.common.id.u.name.len); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.id.u.name.name, expected.common.id.u.name.name, contents->common.id.u.name.len)); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.craca_id, expected.common.craca_id, 3)); // CracaId 비교
    ASSERT_EQ(contents->common.crl_series, expected.common.crl_series); // CrlSeries 비교
    ASSERT_EQ(contents->common.valid_start, expected.common.valid_start); // 유효기간 시작시점 비교
    ASSERT_EQ(contents->common.valid_end, expected.common.valid_end); // 유효기간 종료시점 비교
    ASSERT_EQ(contents->common.valid_region.type, expected.common.valid_region.type); // 인증서 유효지역 유형 비교
    ASSERT_EQ(contents->common.verify_key_indicator.type, expected.common.verify_key_indicator.type); // 검증키 지시자 유형 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.verify_key_indicator.key.u.octs, expected.common.verify_key_indicator.key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 검징키(공개키) 비교
    ASSERT_EQ(contents->common.enc_pub_key_present, expected.common.enc_pub_key_present); // 암호화용 공개키 존재여부 비교
    // 상위인증서(Issuer) 확인
    ASSERT_TRUE(entry->issuer == nullptr); // Self-signed이므로 issuer 존재하지 않음
  }

  /*
   * 테스트: RCA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
  ASSERT_TRUE(entry_rca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief SCC에 속한 ICA 인증서정보 저장 기능이 정상동작하는지 확인한다.
 */
TEST(ADD_SCC_CERT, ICA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SCCCertContents expected;
  uint8_t ica_cert[kDot2CertSize_Max];
  size_t ica_cert_size;
  uint8_t ica_cert_h[DOT2_SHA_256_LEN];
  struct Dot2SCCCertInfoEntry *entry_rca, *entry_ica;

  /*
   * 준비
   */
  {
    // 기대값 설정
    Dot2Test_InitTestVector_ICACertContents(&expected);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(ica_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert, ica_cert), g_tv_ica_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, ica_cert_h), DOT2_SHA_256_LEN);
  }

  /*
   * 테스트: 상위인증서인 RCA가 저장되어 있지 않아 ICA가 저장되지 않는 것을 확인한다.
   */
  entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
  ASSERT_TRUE(entry_ica == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 상위인증서인 RCA를 먼저 저장한다.
   */
  {
    uint8_t rca_cert[kDot2CertSize_Max];
    auto rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
    entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
    ASSERT_TRUE(entry_rca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: ICA가 성공적으로 저장되는 것을 확인한다.
   */
  entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
  ASSERT_TRUE(entry_ica != nullptr);
  ASSERT_EQ(ret, kDot2Result_Success);

  /*
   * 확인 - 라이브러리 내부 정보에 접근하여 기대값과 동일한지 비교한다.
   */
  {
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u); // 두개의 인증서정보 엔트리가 저장된 것을 확인한다.
    struct Dot2SCCCertInfoEntry *entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(ica_cert_h));
    ASSERT_TRUE(entry != nullptr); // 엔트리 존재
    // 저장된 엔트리 정보 확인
    ASSERT_TRUE(entry->cert != nullptr); // 인증서바이트열 존재
    ASSERT_EQ(entry->cert_size, ica_cert_size); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert, ica_cert, ica_cert_size)); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert_h.octs, ica_cert_h, DOT2_SHA_256_LEN)); // 해시값 비교
    // 저장된 CA인증서 컨텐츠 확인
    struct Dot2SCCCertContents *contents = &(entry->contents);
    ASSERT_EQ(contents->type, expected.type); // 인증서 종류 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, expected.verify_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
    ASSERT_TRUE(contents->eck_verify_pub_key != nullptr); // EC_KEY 형식 서명검증용 공개키 존재
    ASSERT_TRUE(contents->eck_enc_pub_key == nullptr); // EC_KEY 형식 암호화용 공개키 부재
    // 저장된 CA인증서 공통정보 확인
    ASSERT_EQ(contents->common.type, expected.common.type); // 인증서유형 비교
    ASSERT_EQ(contents->common.issuer.type, expected.common.issuer.type); /// 상위인증서식별자 유형 비교
    ASSERT_EQ(contents->common.id.type, expected.common.id.type); // 인증서 ID 유형 비교
    ASSERT_EQ(contents->common.id.u.name.len, expected.common.id.u.name.len); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.id.u.name.name, expected.common.id.u.name.name, contents->common.id.u.name.len)); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.craca_id, expected.common.craca_id, 3)); // CracaId 비교
    ASSERT_EQ(contents->common.crl_series, expected.common.crl_series); // CrlSeries 비교
    ASSERT_EQ(contents->common.valid_start, expected.common.valid_start); // 유효기간 시작시점 비교
    ASSERT_EQ(contents->common.valid_end, expected.common.valid_end); // 유효기간 종료시점 비교
    ASSERT_EQ(contents->common.valid_region.type, expected.common.valid_region.type); // 인증서 유효지역 유형 비교
    ASSERT_EQ(contents->common.valid_region.u.id.num, expected.common.valid_region.u.id.num); // 인증서 유효지역 비교
    for (unsigned int i = 0; i < contents->common.valid_region.u.id.num; i++) { // 인증서 유효지역 비교
      ASSERT_EQ(contents->common.valid_region.u.id.country[i], expected.common.valid_region.u.id.country[i]);
    }
    ASSERT_EQ(contents->common.verify_key_indicator.type, expected.common.verify_key_indicator.type); // 검증키 지시자 유형 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.verify_key_indicator.key.u.octs, expected.common.verify_key_indicator.key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 검징키(공개키) 비교
    ASSERT_EQ(contents->common.enc_pub_key_present, expected.common.enc_pub_key_present); // 암호화용 공개키 존재여부 비교
    // 상위인증서(Issuer) 확인 - RCA와 동일한지 확인
    uint8_t issuer_h[DOT2_SHA_256_LEN];
    Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_h, issuer_h);
    struct Dot2SCCCertInfoEntry *issuer_entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(issuer_h));
    ASSERT_TRUE(entry->issuer == issuer_entry); // 상위인증서(Issuer) 확인
    ASSERT_TRUE(entry->issuer == entry_rca); // 상위인증서(Issuer) 확인
  }

  /*
   * 테스트: ICA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
  ASSERT_TRUE(entry_ica == nullptr);
  ASSERT_EQ(ret, -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief SCC에 속한 PCA 인증서정보 저장 기능이 정상동작하는지 확인한다.
 */
TEST(ADD_SCC_CERT, PCA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SCCCertContents expected;
  uint8_t pca_cert[kDot2CertSize_Max];
  size_t pca_cert_size;
  uint8_t pca_cert_h[DOT2_SHA_256_LEN];
  struct Dot2SCCCertInfoEntry *entry_rca, *entry_ica, *entry_pca;

  /*
   * 준비
   */
  {
    // 기대값 설정
    Dot2Test_InitTestVector_PCACertContents(&expected);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(pca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert, pca_cert), g_tv_pca_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_h, pca_cert_h), DOT2_SHA_256_LEN);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 PCA가 저장되지 않는 것을 확인한다.
   */
  entry_pca = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
  ASSERT_TRUE(entry_pca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 최상위인증서인 RCA를 먼저 저장한다.
   */
  {
    uint8_t rca_cert[kDot2CertSize_Max];
    auto rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
    entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
    ASSERT_TRUE(entry_rca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 PCA가 저장되지 않는 것을 확인한다.
   */
  entry_pca = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
  ASSERT_TRUE(entry_pca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - PCA의 상위인증서인 ICA를 저장한다.
   */
  {
    uint8_t ica_cert[kDot2CertSize_Max];
    auto ica_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert, ica_cert);
    ASSERT_EQ(ica_cert_size, g_tv_ica_cert_size);
    entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
    ASSERT_TRUE(entry_ica != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);
  }

  /*
   * 테스트: PCA가 성공적으로 저장되는 것을 확인한다.
   */
  entry_pca = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
  ASSERT_TRUE(entry_pca != nullptr);
  ASSERT_EQ(ret, kDot2Result_Success);

  /*
   * 확인 - 라이브러리 내부 정보에 접근하여 기대값과 동일한지 비교한다.
   */
  {
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 3개의 인증서정보 엔트리가 저장된 것을 확인한다.
    struct Dot2SCCCertInfoEntry *entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(pca_cert_h));
    ASSERT_TRUE(entry != nullptr); // 엔트리 존재
    // 저장된 엔트리 정보 확인
    ASSERT_TRUE(entry->cert != nullptr); // 인증서바이트열 존재
    ASSERT_EQ(entry->cert_size, pca_cert_size); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert, pca_cert, pca_cert_size)); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert_h.octs, pca_cert_h, DOT2_SHA_256_LEN)); // 해시값 비교
    // 저장된 CA인증서 컨텐츠 확인
    struct Dot2SCCCertContents *contents = &(entry->contents);
    ASSERT_EQ(contents->type, expected.type); // 인증서 종류 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, expected.verify_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
    ASSERT_TRUE(contents->eck_verify_pub_key != nullptr); // EC_KEY 형식 서명검증용 공개키 존재
    ASSERT_TRUE(contents->eck_enc_pub_key != nullptr); // EC_KEY 형식 암호화용 공개키 존재
    // 저장된 CA인증서 공통정보 확인
    ASSERT_EQ(contents->common.type, expected.common.type); // 인증서유형 비교
    ASSERT_EQ(contents->common.issuer.type, expected.common.issuer.type); /// 상위인증서식별자 유형 비교
    ASSERT_EQ(contents->common.id.type, expected.common.id.type); // 인증서 ID 유형 비교
    ASSERT_EQ(contents->common.id.u.name.len, expected.common.id.u.name.len); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.id.u.name.name, expected.common.id.u.name.name, contents->common.id.u.name.len)); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.craca_id, expected.common.craca_id, 3)); // CracaId 비교
    ASSERT_EQ(contents->common.crl_series, expected.common.crl_series); // CrlSeries 비교
    ASSERT_EQ(contents->common.valid_start, expected.common.valid_start); // 유효기간 시작시점 비교
    ASSERT_EQ(contents->common.valid_end, expected.common.valid_end); // 유효기간 종료시점 비교
    ASSERT_EQ(contents->common.valid_region.type, expected.common.valid_region.type); // 인증서 유효지역 유형 비교
    ASSERT_EQ(contents->common.valid_region.u.id.num, expected.common.valid_region.u.id.num); // 인증서 유효지역 비교
    for (unsigned int i = 0; i < contents->common.valid_region.u.id.num; i++) { // 인증서 유효지역 비교
      ASSERT_EQ(contents->common.valid_region.u.id.country[i], expected.common.valid_region.u.id.country[i]);
    }
    ASSERT_EQ(contents->common.enc_pub_key_present, expected.common.enc_pub_key_present); // 암호화용 공개키 존재여부 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.enc_pub_key.u.octs, expected.common.enc_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 암호용 공개키 비교
    ASSERT_EQ(contents->common.verify_key_indicator.type, expected.common.verify_key_indicator.type); // 검증키 지시자 유형 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.verify_key_indicator.key.u.octs, expected.common.verify_key_indicator.key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 검징키(공개키) 비교
    // 상위인증서(Issuer) 확인 - ICA와 동일한지 확인
    uint8_t issuer_h[DOT2_SHA_256_LEN];
    Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, issuer_h);
    struct Dot2SCCCertInfoEntry *issuer_entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(issuer_h));
    ASSERT_TRUE(entry->issuer == issuer_entry); // 상위인증서(Issuer) 확인
    ASSERT_TRUE(entry->issuer == entry_ica); // 상위인증서(Issuer) 확인
  }

  /*
   * 테스트: PCA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  entry_pca = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
  ASSERT_TRUE(entry_pca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief SCC에 속한 ECA 인증서정보 저장 기능이 정상동작하는지 확인한다.
 */
TEST(ADD_SCC_CERT, ECA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SCCCertContents expected;
  uint8_t eca_cert[kDot2CertSize_Max];
  size_t eca_cert_size;
  uint8_t eca_cert_h[DOT2_SHA_256_LEN];
  struct Dot2SCCCertInfoEntry *entry_rca, *entry_ica, *entry_eca;

  /*
   * 준비
   */
  {
    // 기대값 설정
    Dot2Test_InitTestVector_ECACertContents(&expected);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(eca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert, eca_cert), g_tv_eca_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_h, eca_cert_h), DOT2_SHA_256_LEN);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 ECA가 저장되지 않는 것을 확인한다.
   */
  entry_eca = dot2_AddSCCCert(eca_cert, eca_cert_size, &ret);
  ASSERT_TRUE(entry_eca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 최상위인증서인 RCA를 먼저 저장한다.
   */
  {
    uint8_t rca_cert[kDot2CertSize_Max];
    auto rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
    entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
    ASSERT_TRUE(entry_rca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 ECA가 저장되지 않는 것을 확인한다.
   */
  entry_eca = dot2_AddSCCCert(eca_cert, eca_cert_size, &ret);
  ASSERT_TRUE(entry_eca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - ECA의 상위인증서인 ICA를 저장한다.
   */
  {
    uint8_t ica_cert[kDot2CertSize_Max];
    auto ica_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert, ica_cert);
    ASSERT_EQ(ica_cert_size, g_tv_ica_cert_size);
    entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
    ASSERT_TRUE(entry_ica != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);
  }

  /*
   * 테스트: ECA가 성공적으로 저장되는 것을 확인한다.
   */
  entry_eca = dot2_AddSCCCert(eca_cert, eca_cert_size, &ret);
  ASSERT_TRUE(entry_eca != nullptr);
  ASSERT_EQ(ret, kDot2Result_Success);

  /*
   * 확인 - 라이브러리 내부 정보에 접근하여 기대값과 동일한지 비교한다.
   */
  {
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 3개의 인증서정보 엔트리가 저장된 것을 확인한다.
    struct Dot2SCCCertInfoEntry *entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(eca_cert_h));
    ASSERT_TRUE(entry != nullptr); // 엔트리 존재
    // 저장된 엔트리 정보 확인
    ASSERT_TRUE(entry->cert != nullptr); // 인증서바이트열 존재
    ASSERT_EQ(entry->cert_size, eca_cert_size); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert, eca_cert, eca_cert_size)); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert_h.octs, eca_cert_h, DOT2_SHA_256_LEN)); // 해시값 비교
    // 저장된 CA인증서 컨텐츠 확인
    struct Dot2SCCCertContents *contents = &(entry->contents);
    ASSERT_EQ(contents->type, expected.type); // 인증서 종류 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, expected.verify_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
    ASSERT_TRUE(contents->eck_verify_pub_key != nullptr); // EC_KEY 형식 서명검증용 공개키 존재
    ASSERT_TRUE(contents->eck_enc_pub_key != nullptr); // EC_KEY 형식 암호화용 공개키 존재
    // 저장된 CA인증서 공통정보 확인
    ASSERT_EQ(contents->common.type, expected.common.type); // 인증서유형 비교
    ASSERT_EQ(contents->common.issuer.type, expected.common.issuer.type); /// 상위인증서식별자 유형 비교
    ASSERT_EQ(contents->common.id.type, expected.common.id.type); // 인증서 ID 유형 비교
    ASSERT_EQ(contents->common.id.u.name.len, expected.common.id.u.name.len); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.id.u.name.name, expected.common.id.u.name.name, contents->common.id.u.name.len)); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.craca_id, expected.common.craca_id, 3)); // CracaId 비교
    ASSERT_EQ(contents->common.crl_series, expected.common.crl_series); // CrlSeries 비교
    ASSERT_EQ(contents->common.valid_start, expected.common.valid_start); // 유효기간 시작시점 비교
    ASSERT_EQ(contents->common.valid_end, expected.common.valid_end); // 유효기간 종료시점 비교
    ASSERT_EQ(contents->common.valid_region.type, expected.common.valid_region.type); // 인증서 유효지역 유형 비교
    ASSERT_EQ(contents->common.valid_region.u.id.num, expected.common.valid_region.u.id.num); // 인증서 유효지역 비교
    for (unsigned int i = 0; i < contents->common.valid_region.u.id.num; i++) { // 인증서 유효지역 비교
      ASSERT_EQ(contents->common.valid_region.u.id.country[i], expected.common.valid_region.u.id.country[i]);
    }
    ASSERT_EQ(contents->common.enc_pub_key_present, expected.common.enc_pub_key_present); // 암호화용 공개키 존재여부 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.enc_pub_key.u.octs, expected.common.enc_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 암호용 공개키 비교
    ASSERT_EQ(contents->common.verify_key_indicator.type, expected.common.verify_key_indicator.type); // 검증키 지시자 유형 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.verify_key_indicator.key.u.octs, expected.common.verify_key_indicator.key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 검징키(공개키) 비교
    // 상위인증서(Issuer) 확인 - ICA와 동일한지 확인
    uint8_t issuer_h[DOT2_SHA_256_LEN];
    Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, issuer_h);
    struct Dot2SCCCertInfoEntry *issuer_entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(issuer_h));
    ASSERT_TRUE(entry->issuer == issuer_entry); // 상위인증서(Issuer) 확인
    ASSERT_TRUE(entry->issuer == entry_ica); // 상위인증서(Issuer) 확인
  }

  /*
   * 테스트: ECA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  entry_eca = dot2_AddSCCCert(eca_cert, eca_cert_size, &ret);
  ASSERT_TRUE(entry_eca == nullptr);
  ASSERT_EQ(ret, -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief SCC에 속한 RA 인증서정보 저장 기능이 정상동작하는지 확인한다.
 */
TEST(ADD_SCC_CERT, RA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SCCCertContents expected;
  uint8_t ra_cert[kDot2CertSize_Max];
  size_t ra_cert_size;
  uint8_t ra_cert_h[DOT2_SHA_256_LEN];
  struct Dot2SCCCertInfoEntry *entry_rca, *entry_ica, *entry_ra;

  /*
   * 준비
   */
  {
    // 기대값 설정
    Dot2Test_InitTestVector_RACertContents(&expected);

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(ra_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert, ra_cert), g_tv_ra_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_h, ra_cert_h), DOT2_SHA_256_LEN);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 RA가 저장되지 않는 것을 확인한다.
   */
  entry_ra = dot2_AddSCCCert(ra_cert, ra_cert_size, &ret);
  ASSERT_TRUE(entry_ra == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 최상위인증서인 RCA를 먼저 저장한다.
   */
  {
    uint8_t rca_cert[kDot2CertSize_Max];
    auto rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
    entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
    ASSERT_TRUE(entry_rca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 RA가 저장되지 않는 것을 확인한다.
   */
  entry_ra = dot2_AddSCCCert(ra_cert, ra_cert_size, &ret);
  ASSERT_TRUE(entry_ra == nullptr);
  ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);

  /*
   * 준비 - RA의 상위인증서인 ICA를 저장한다.
   */
  {
    uint8_t ica_cert[kDot2CertSize_Max];
    auto ica_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert, ica_cert);
    ASSERT_EQ(ica_cert_size, g_tv_ica_cert_size);
    entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
    ASSERT_TRUE(entry_ica != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);
  }

  /*
   * 확인 : CA인증서정보 저장소 내 RA 참조 포인터가 설정되어 있지 않은 것을 확인한다.
   */
  ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == nullptr);

  /*
   * 테스트: RA가 성공적으로 저장되는 것을 확인한다.
   */
  {
    entry_ra = dot2_AddSCCCert(ra_cert, ra_cert_size, &ret);
    ASSERT_TRUE(entry_ra != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u);
  }

  /*
   * 확인 - 라이브러리 내부 정보에 접근하여 기대값과 동일한지 비교한다.
   */
  {
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 3개의 인증서정보 엔트리가 저장된 것을 확인한다.
    struct Dot2SCCCertInfoEntry *entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(ra_cert_h));
    ASSERT_TRUE(entry != nullptr); // 엔트리 존재
    // 저장된 엔트리 정보 확인
    ASSERT_TRUE(entry->cert != nullptr); // 인증서바이트열 존재
    ASSERT_EQ(entry->cert_size, ra_cert_size); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert, ra_cert, ra_cert_size)); // 인증서바이트열 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert_h.octs, ra_cert_h, DOT2_SHA_256_LEN)); // 해시값 비교
    // 저장된 CA인증서 컨텐츠 확인
    struct Dot2SCCCertContents *contents = &(entry->contents);
    ASSERT_EQ(contents->type, expected.type); // 인증서 종류 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, expected.verify_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
    ASSERT_TRUE(contents->eck_verify_pub_key != nullptr); // EC_KEY 형식 서명검증용 공개키 존재
    ASSERT_TRUE(contents->eck_enc_pub_key != nullptr); // EC_KEY 형식 암호화용 공개키 존재
    // 저장된 CA인증서 공통정보 확인
    ASSERT_EQ(contents->common.type, expected.common.type); // 인증서유형 비교
    ASSERT_EQ(contents->common.issuer.type, expected.common.issuer.type); /// 상위인증서식별자 유형 비교
    ASSERT_EQ(contents->common.id.type, expected.common.id.type); // 인증서 ID 유형 비교
    ASSERT_EQ(contents->common.id.u.name.len, expected.common.id.u.name.len); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.id.u.name.name, expected.common.id.u.name.name, contents->common.id.u.name.len)); // 인증서 ID (Name) 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.craca_id, expected.common.craca_id, 3)); // CracaId 비교
    ASSERT_EQ(contents->common.crl_series, expected.common.crl_series); // CrlSeries 비교
    ASSERT_EQ(contents->common.valid_start, expected.common.valid_start); // 유효기간 시작시점 비교
    ASSERT_EQ(contents->common.valid_end, expected.common.valid_end); // 유효기간 종료시점 비교
    ASSERT_EQ(contents->common.valid_region.type, expected.common.valid_region.type); // 인증서 유효지역 유형 비교
    ASSERT_EQ(contents->common.valid_region.u.id.num, expected.common.valid_region.u.id.num); // 인증서 유효지역 비교
    for (unsigned int i = 0; i < contents->common.valid_region.u.id.num; i++) { // 인증서 유효지역 비교
      ASSERT_EQ(contents->common.valid_region.u.id.country[i], expected.common.valid_region.u.id.country[i]);
    }
    ASSERT_EQ(contents->common.enc_pub_key_present, expected.common.enc_pub_key_present); // 암호화용 공개키 존재여부 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.enc_pub_key.u.octs, expected.common.enc_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 암호용 공개키 비교
    ASSERT_EQ(contents->common.verify_key_indicator.type, expected.common.verify_key_indicator.type); // 검증키 지시자 유형 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(contents->common.verify_key_indicator.key.u.octs, expected.common.verify_key_indicator.key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // 검징키(공개키) 비교
    // 상위인증서(Issuer) 확인 - ICA와 동일한지 확인
    uint8_t issuer_h[DOT2_SHA_256_LEN];
    Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, issuer_h);
    struct Dot2SCCCertInfoEntry *issuer_entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(issuer_h));
    ASSERT_TRUE(entry->issuer == issuer_entry); // 상위인증서(Issuer) 확인
    ASSERT_TRUE(entry->issuer == entry_ica); // 상위인증서(Issuer) 확인
  }

  /*
   * 확인 : CA인증서정보 저장소 내 RA 참조 포인터가 정상 설정된 것을 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra != nullptr); // RA 참조 포인터가 설정된 것을 확인
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == entry_ra); // RA 참조 포인터와 실제 저장된 RA 엔트리 포인터가 동일함을 확인
  }

  /*
   * 테스트: RA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  entry_ra = dot2_AddSCCCert(ra_cert, ra_cert_size, &ret);
  ASSERT_TRUE(entry_ra == nullptr);
  ASSERT_EQ(ret, -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief SCC에 속한 CA 인증서정보 저장 시 인증서체인이 정상적으로 생성되는지 확인한다.
 *
 * pca/eca/ra -> ica(/crlg/ma) -> rca
 * 현재 정상적인 crlg/ma 인증서를 구할 수 없어 해당 인증서는 생략
 */
TEST(ADD_SCC_CERT, CERT_CHAIN)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SCCCertContents expected;
  uint8_t pca_cert[kDot2CertSize_Max], eca_cert[kDot2CertSize_Max], ra_cert[kDot2CertSize_Max];
  uint8_t ica_cert[kDot2CertSize_Max], rca_cert[kDot2CertSize_Max];
  size_t pca_cert_size, eca_cert_size, ra_cert_size, ica_cert_size, rca_cert_size;
  struct Dot2SCCCertInfoEntry *entry_pca, *entry_eca, *entry_ra, *entry_ica, *entry_rca;

  /*
   * 준비
   */
  {
    // 테스트벡터 PCA 인증서 바이트열 변환
    pca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert, pca_cert);
    ASSERT_EQ(pca_cert_size, g_tv_pca_cert_size);
    // 테스트벡터 ECA 인증서 바이트열 변환
    eca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert, eca_cert);
    ASSERT_EQ(eca_cert_size, g_tv_eca_cert_size);
    // 테스트벡터 RA 인증서 바이트열 변환
    ra_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert, ra_cert);
    ASSERT_EQ(ra_cert_size, g_tv_ra_cert_size);
    // 테스트벡터 ICA 인증서 바이트열 변환
    ica_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert, ica_cert);
    ASSERT_EQ(ica_cert_size, g_tv_ica_cert_size);
    // 테스트벡터 RCA 인증서 바이트열 변환
    rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
  }

  /*
   * 테스트 - 하위인증서부터 저장하면 실패하는 것을 확인한다.
   */
  {
    // PCA
    entry_pca = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
    ASSERT_TRUE(entry_pca == nullptr);
    ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);
    // ECA
    entry_eca = dot2_AddSCCCert(eca_cert, eca_cert_size, &ret);
    ASSERT_TRUE(entry_eca == nullptr);
    ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);
    // RA
    entry_ra = dot2_AddSCCCert(ra_cert, ra_cert_size, &ret);
    ASSERT_TRUE(entry_ra == nullptr);
    ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);
    // ICA
    entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
    ASSERT_TRUE(entry_ica == nullptr);
    ASSERT_EQ(ret, -kDot2Result_NoIssuerCert);
    // 하나도 등록되지 않은 것을 확인
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);
  }

  /*
   * 테스트 : 상위인증서부터 저장하면 성공하는 것을 확인한다.
   */
  {
    // RCA
    entry_rca = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
    ASSERT_TRUE(entry_rca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    // ICA
    entry_ica = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
    ASSERT_TRUE(entry_ica != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    // PCA
    entry_pca = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
    ASSERT_TRUE(entry_pca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    // ECA
    entry_eca = dot2_AddSCCCert(eca_cert, eca_cert_size, &ret);
    ASSERT_TRUE(entry_eca != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    // RA
    entry_ra = dot2_AddSCCCert(ra_cert, ra_cert_size, &ret);
    ASSERT_TRUE(entry_ra != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    // 모두 등록된 것을 확인
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);
  }

  /*
   * 확인 - 인증서 체인이 맞게 구성되었는지 확인한다.
   * 각 인증서정보 엔트리 내 상위인증서 참조 포인터 값을 확인한다.
   */
  {
    ASSERT_TRUE(entry_pca->issuer == entry_ica); // PCA의 상위인증서는 ICA
    ASSERT_TRUE(entry_eca->issuer == entry_ica); // ECA의 상위인증서는 ICA
    ASSERT_TRUE(entry_ra->issuer == entry_ica); // RA의 상위인증서는 ICA
    ASSERT_TRUE(entry_ica->issuer == entry_rca); // ICA의 상위인증서는 RCA
    ASSERT_TRUE(entry_rca->issuer == nullptr); // RCA의 상위인증서는 없음
  }

  /*
   * 확인 - RA 참조 포인터가 잘 설정되었는지 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == entry_ra); // RA 참조 포인터와 실제 저장된 RA 엔트리 포인터가 동일함을 확인
  }

  Dot2_Release();
}
