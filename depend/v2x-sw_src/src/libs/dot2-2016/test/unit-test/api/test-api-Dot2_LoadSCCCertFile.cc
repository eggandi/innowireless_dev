/** 
  * @file 
  * @brief Dot2_LoadSCCCertFile() API 단위 테스트
  * @date 2022-07-03 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_LoadSCCCertFile() API를 이용한 RCA 인증서 저장 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, RCA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SCCCertContents expected;
  const char *rca_cert_file_path = "test/test-file/certificates/scc/rca";
  uint8_t rca_cert[kDot2CertSize_Max];
  size_t rca_cert_size;
  uint8_t rca_cert_h[DOT2_SHA_256_LEN];

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
   * 테스트 : RCA 인증서가 성공적으로 저장되는 것을 확인한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(rca_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 확인 : 라이브러리 내부 정보에 접근하여 기대값과 동일한지 비교한다.
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
   * 확인 : RA 및 PCA 인증서정보 참조 포인터가 설정되지 않은 것을 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == nullptr);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.pca == nullptr);
  }

  /*
   * 테스트: RCA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(rca_cert_file_path), -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief Dot2_LoadSCCCertFile() API를 이용한 ICA 인증서 저장 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, ICA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *rca_cert_file_path = "test/test-file/certificates/scc/rca";
  const char *ica_cert_file_path = "test/test-file/certificates/scc/ica";
  struct Dot2SCCCertContents expected;
  uint8_t ica_cert[kDot2CertSize_Max];
  size_t ica_cert_size;
  uint8_t ica_cert_h[DOT2_SHA_256_LEN];

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
  ASSERT_EQ(Dot2_LoadSCCCertFile(ica_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 상위인증서인 RCA를 먼저 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(rca_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: ICA가 성공적으로 저장되는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(ica_cert_file_path), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);

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
  }

  /*
   * 확인 : RA 및 PCA 인증서정보 참조 포인터가 설정되지 않은 것을 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == nullptr);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.pca == nullptr);
  }

  /*
   * 테스트: ICA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(ica_cert_file_path), -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief Dot2_LoadSCCCertFile() API를 이용한 PCA 인증서 저장 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, PCA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *rca_cert_file_path = "test/test-file/certificates/scc/rca";
  const char *ica_cert_file_path = "test/test-file/certificates/scc/ica";
  const char *pca_cert_file_path = "test/test-file/certificates/scc/pca";
  struct Dot2SCCCertContents expected;
  uint8_t pca_cert[kDot2CertSize_Max];
  size_t pca_cert_size;
  uint8_t pca_cert_h[DOT2_SHA_256_LEN];

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
  ASSERT_EQ(Dot2_LoadSCCCertFile(pca_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 최상위인증서인 RCA를 먼저 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(rca_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 PCA가 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(pca_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - PCA의 상위인증서인 ICA를 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(ica_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);
  }

  /*
   * 테스트: PCA가 성공적으로 저장되는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(pca_cert_file_path), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u);

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
  }

  /*
   * 확인 : RA 인증서정보 참조 포인터가 설정되지 않은 것을 확인한다.
   * PCA 인증서정보 참조 포인터가 설정된 것을 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == nullptr);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.pca != nullptr);
  }

  /*
   * 테스트: PCA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(pca_cert_file_path), -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief Dot2_LoadSCCCertFile() API를 이용한 ECA 인증서 저장 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, ECA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *rca_cert_file_path = "test/test-file/certificates/scc/rca";
  const char *ica_cert_file_path = "test/test-file/certificates/scc/ica";
  const char *eca_cert_file_path = "test/test-file/certificates/scc/eca";
  struct Dot2SCCCertContents expected;
  uint8_t eca_cert[kDot2CertSize_Max];
  size_t eca_cert_size;
  uint8_t eca_cert_h[DOT2_SHA_256_LEN];

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
  ASSERT_EQ(Dot2_LoadSCCCertFile(eca_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 최상위인증서인 RCA를 먼저 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(rca_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 ECA가 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(eca_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - ECA의 상위인증서인 ICA를 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(ica_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);
  }

  /*
   * 테스트: ECA가 성공적으로 저장되는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(eca_cert_file_path), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u);

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
  }

  /*
   * 확인 : RA 및 PCA 인증서정보 참조 포인터가 설정되지 않은 것을 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == nullptr);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.pca == nullptr);
  }

  /*
   * 테스트: ECA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(eca_cert_file_path), -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief Dot2_LoadSCCCertFile() API를 이용한 RA 인증서 저장 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, RA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *rca_cert_file_path = "test/test-file/certificates/scc/rca";
  const char *ica_cert_file_path = "test/test-file/certificates/scc/ica";
  const char *ra_cert_file_path = "test/test-file/certificates/scc/ra";
  struct Dot2SCCCertContents expected;
  uint8_t ra_cert[kDot2CertSize_Max];
  size_t ra_cert_size;
  uint8_t ra_cert_h[DOT2_SHA_256_LEN];

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
  ASSERT_EQ(Dot2_LoadSCCCertFile(ra_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - 최상위인증서인 RCA를 먼저 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(rca_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);
  }

  /*
   * 테스트: 상위인증서인 ICA가 저장되어 있지 않아 ECA가 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(ra_cert_file_path), -kDot2Result_NoIssuerCert);

  /*
   * 준비 - RA의 상위인증서인 ICA를 저장한다.
   */
  {
    ASSERT_EQ(Dot2_LoadSCCCertFile(ica_cert_file_path), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 2u);
  }

  /*
   * 테스트: RA가 성공적으로 저장되는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(ra_cert_file_path), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u);

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
  }

  /*
   * 확인 : RA 인증서정보 참조 포인터가 설정된 것을 확인한다.
   * RA 인증서정보 참조 포인터가 설정되지 않은 것을 확인한다.
   */
  {
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra != nullptr);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.pca == nullptr);
  }

  /*
   * 테스트: RA가 등록된 상태에서 중복으로 저장하는 경우 저장되지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(ra_cert_file_path), -kDot2Result_CERT_SameCertInTable);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 3u); // 인증서정보 엔트리의 수가 그대로인 것을 확인한다.

  Dot2_Release();
}


/**
 * @brief 잘못된 파라미터 입력시의 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *rca_cert_file_path = "test/test-file/certificates/scc/rca";

  /*
   * 테스트
   *  - file_path = NULL 전달 시 실패하는 것을 확인한다.
   *  - 존재하지 않는 파일 전달 시 실패하는 것을 확인한다.
   *  - 디렉토리명 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(nullptr), -kDot2Result_NullParameters);
  ASSERT_EQ(Dot2_LoadSCCCertFile("test/test-file/certificates/scc/nofile"), -kDot2Result_FILE_Access);
  ASSERT_EQ(Dot2_LoadSCCCertFile("test/test-file/certificates/scc"), -kDot2Result_FILE_Access);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);

  Dot2_Release();
}


/**
 * @brief 잘못된 파일 입력시의 동작을 확인한다.
 */
TEST(API_Dot2_LoadSCCCertFile, INVALID_FILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *too_long_cert_file_path = "test/test-file/certificates/scc/abnormal-scc-cert-too-long";
  const char *too_short_cert_file_path = "test/test-file/certificates/scc/abnormal-scc-cert-too-short";
  const char *not_cert_file_path = "test/test-file/certificates/scc/abnormal-not-cert";

  /*
   * 테스트
   *  - 너무 큰 파일 전달 시 실패하는 것을 확인한다.
   *  - 너무 작은 파일 전달 시 실패하는 것을 확인한다.
   *  - 내용이 인증서가 아닌 파일 전달 시 실패하는 것을 확인한다 -> ASN.1 디코딩 실패
   */
  ASSERT_EQ(Dot2_LoadSCCCertFile(too_long_cert_file_path), -kDot2Result_FILE_InvalidLength);
  ASSERT_EQ(Dot2_LoadSCCCertFile(too_short_cert_file_path), -kDot2Result_FILE_InvalidLength);
  ASSERT_EQ(Dot2_LoadSCCCertFile(not_cert_file_path), -kDot2Result_ASN1_DecodeCertificate);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);

  Dot2_Release();
}
