/** 
  * @file 
  * @brief 
  * @date 2022-07-02 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-executer/openssl/dot2-openssl.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-vectors/test-vectors.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "dot2-2016/dot2-types.h"


/**
 * @brief RCA 인증서 서명검증 테스트 (인증서 내 서명은 X-only 형식을 가진다)
 *
 * RCA 인증서의 서명이 RCA 공개키로 검증되는 것을 확인한다.
 */
TEST(VERIFY_CERT_SIGN, RCA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  uint8_t tbs[kDot2CertSize_Max];
  size_t tbs_size;
  EC_KEY *eck_pub_key;
  struct Dot2ECPublicKey pub_key;
  struct Dot2Signature sign;

  /*
   * 준비 : 서명검증 입력 정보를 설정한다.
   */
  {
    tbs_size = Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_tbs, tbs); // RCA의 ToBeSignedCertificate
    ASSERT_EQ(tbs_size, g_tv_rca_cert_tbs_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_key_indicator, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN); // RCA 공개키
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret); // RCA 공개키
    ASSERT_TRUE(eck_pub_key != nullptr); // RCA 공개키
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_sig_r, sign.R_r.u.point.u.xy.x), DOT2_EC_256_KEY_LEN); // RCA 인증서 서명 r
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_sig_s, sign.s), DOT2_EC_256_KEY_LEN); // RCA 인증서 서명 s
  }

  /*
   * 테스트 : 서명 검증이 성공하는 것을 확인한다.
   * Self-signed 인증서이므로 상위인증서 해시는 NULL을 전달한다.
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, nullptr, eck_pub_key, &sign), kDot2Result_Success);
  }

  /*
   * 테스트 : 데이터 변조 시 검증이 실패하는 것을 확인한다.
   */
  {
    tbs[0]++; // TBS 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, nullptr, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    tbs[0]--; // TBS 원상복구

    pub_key.u.point.u.xy.x[0]++; // 공개키 변조
    EC_KEY *eck_pub_key_invalid = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key_invalid != nullptr);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, nullptr, eck_pub_key_invalid, &sign), -kDot2Result_SignatureVerificationFailed);
    EC_KEY_free(eck_pub_key_invalid);

    sign.R_r.u.point.u.xy.x[0]++; // 서명 r 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, nullptr, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.R_r.u.point.u.xy.x[0]--; // 서명 r 원상복구

    sign.s[0]++; // 서명 s 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, nullptr, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.s[0]--; // 서명 s 원상 복구
  }

  EC_KEY_free(eck_pub_key);

  Dot2_Release();
}


/**
 * @brief ICA 인증서 서명검증 테스트 (인증서 내 서명은 X-only 형식을 가진다)
 *
 * ICA 인증서의 서명이 RCA 공개키로 검증되는 것을 확인한다.
 */
TEST(VERIFY_CERT_SIGN, ICA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  uint8_t tbs[kDot2CertSize_Max];
  size_t tbs_size;
  struct Dot2SHA256 issuer_h;
  EC_KEY *eck_pub_key;
  struct Dot2ECPublicKey pub_key;
  struct Dot2Signature sign;

  /*
   * 준비 : 서명검증 입력 정보를 설정한다.
   */
  {
    tbs_size = Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_tbs, tbs); // ICA의 ToBeSignedCertificate
    ASSERT_EQ(tbs_size, g_tv_ica_cert_tbs_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_h, issuer_h.octs), DOT2_SHA_256_LEN); // 상위인증서(RCA) 해시
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_key_indicator, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN); // 상위인증서(RCA) 공개키
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret); // 상위인증서(RCA) 공개키
    ASSERT_TRUE(eck_pub_key != nullptr); // 상위인증서(RCA) 공개키
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_sig_r, sign.R_r.u.point.u.xy.x), DOT2_EC_256_KEY_LEN); // ICA 인증서 서명 r
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_sig_s, sign.s), DOT2_EC_256_KEY_LEN); // ICA 인증서 서명 s
  }

  /*
   * 테스트 : 서명 검증이 성공하는 것을 확인한다.
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), kDot2Result_Success);
  }

  /*
   * 테스트 : 데이터 변조 시 검증이 실패하는 것을 확인한다.
   */
  {
    tbs[0]++; // TBS 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    tbs[0]--; // TBS 원상복구

    pub_key.u.point.u.xy.x[0]++; // 상위인증서(RCA) 공개키 변조
    EC_KEY *eck_pub_key_invalid = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key_invalid != nullptr); // 상위인증서(RCA) 공개키
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key_invalid, &sign), -kDot2Result_SignatureVerificationFailed);
    EC_KEY_free(eck_pub_key_invalid);

    issuer_h.octs[0]++; // 상위인증서(RCA) 해시 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    issuer_h.octs[0]--; // 상위인증서(RCA) 해시 원상복구

    sign.R_r.u.point.u.xy.x[0]++; // 서명 r 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.R_r.u.point.u.xy.x[0]--; // 서명 r 원상복구

    sign.s[0]++; // 서명 s 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.s[0]--; // 서명 s 원상 복구
  }

  EC_KEY_free(eck_pub_key);

  Dot2_Release();
}


/**
 * @brief PCA 인증서 서명검증 테스트 (인증서 내 서명은 X-only 형식을 가진다)
 *
 * PCA 인증서의 서명이 ICA 공개키로 검증되는 것을 확인한다.
 */
TEST(VERIFY_CERT_SIGN, PCA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  uint8_t tbs[kDot2CertSize_Max];
  size_t tbs_size;
  struct Dot2SHA256 issuer_h;
  EC_KEY *eck_pub_key;
  struct Dot2ECPublicKey pub_key;
  struct Dot2Signature sign;

  /*
   * 준비 : 서명검증 입력 정보를 설정한다.
   */
  {
    tbs_size = Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_tbs, tbs); // PCA의 ToBeSignedCertificate
    ASSERT_EQ(tbs_size, g_tv_pca_cert_tbs_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, issuer_h.octs), DOT2_SHA_256_LEN); // 상위인증서(ICA) 해시
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_key_indicator, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN); // 상위인증서(ICA) 공개키
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret); // 상위인증서(ICA) 공개키
    ASSERT_TRUE(eck_pub_key != nullptr); // 상위인증서(ICA) 공개키
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_sig_r, sign.R_r.u.point.u.xy.x), DOT2_EC_256_KEY_LEN); // PCA 인증서 서명 r
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_sig_s, sign.s), DOT2_EC_256_KEY_LEN); // PCA 인증서 서명 s
  }

  /*
   * 테스트 : 서명 검증이 성공하는 것을 확인한다.
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), kDot2Result_Success);
  }

  /*
   * 테스트 : 데이터 변조 시 검증이 실패하는 것을 확인한다.
   */
  {
    tbs[0]++; // TBS 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    tbs[0]--; // TBS 원상복구

    pub_key.u.point.u.xy.x[0]++; // 상위인증서(ICA) 공개키 변조
    EC_KEY *eck_pub_key_invalid = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key_invalid != nullptr); // 상위인증서(ICA) 공개키
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key_invalid, &sign), -kDot2Result_SignatureVerificationFailed);
    EC_KEY_free(eck_pub_key_invalid);

    issuer_h.octs[0]++; // 상위인증서(ICA) 해시 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    issuer_h.octs[0]--; // 상위인증서(ICA) 해시 원상복구

    sign.R_r.u.point.u.xy.x[0]++; // 서명 r 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.R_r.u.point.u.xy.x[0]--; // 서명 r 원상복구

    sign.s[0]++; // 서명 s 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.s[0]--; // 서명 s 원상 복구
  }

  EC_KEY_free(eck_pub_key);

  Dot2_Release();
}


/**
 * @brief ECA 인증서 서명검증 테스트 (인증서 내 서명은 X-only 형식을 가진다)
 *
 * ECA 인증서의 서명이 ICA 공개키로 검증되는 것을 확인한다.
 */
TEST(VERIFY_CERT_SIGN, ECA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  uint8_t tbs[kDot2CertSize_Max];
  size_t tbs_size;
  struct Dot2SHA256 issuer_h;
  EC_KEY *eck_pub_key;
  struct Dot2ECPublicKey pub_key;
  struct Dot2Signature sign;

  /*
   * 준비 : 서명검증 입력 정보를 설정한다.
   */
  {
    tbs_size = Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_tbs, tbs); // ECA의 ToBeSignedCertificate
    ASSERT_EQ(tbs_size, g_tv_eca_cert_tbs_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, issuer_h.octs), DOT2_SHA_256_LEN); // 상위인증서(ICA) 해시
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_key_indicator, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN); // 상위인증서(ICA) 공개키
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret); // 상위인증서(ICA) 공개키
    ASSERT_TRUE(eck_pub_key != nullptr); // 상위인증서(ICA) 공개키
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_sig_r, sign.R_r.u.point.u.xy.x), DOT2_EC_256_KEY_LEN); // ECA 인증서 서명 r
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_sig_s, sign.s), DOT2_EC_256_KEY_LEN); // ECA 인증서 서명 s
  }

  /*
   * 테스트 : 서명 검증이 성공하는 것을 확인한다.
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), kDot2Result_Success);
  }

  /*
   * 테스트 : 데이터 변조 시 검증이 실패하는 것을 확인한다.
   */
  {
    tbs[0]++; // TBS 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    tbs[0]--; // TBS 원상복구

    pub_key.u.point.u.xy.x[0]++; // 상위인증서(ICA) 공개키 변조
    EC_KEY *eck_pub_key_invalid = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key_invalid != nullptr); // 상위인증서(ICA) 공개키
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key_invalid, &sign), -kDot2Result_SignatureVerificationFailed);
    EC_KEY_free(eck_pub_key_invalid);

    issuer_h.octs[0]++; // 상위인증서(ICA) 해시 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    issuer_h.octs[0]--; // 상위인증서(ICA) 해시 원상복구

    sign.R_r.u.point.u.xy.x[0]++; // 서명 r 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.R_r.u.point.u.xy.x[0]--; // 서명 r 원상복구

    sign.s[0]++; // 서명 s 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.s[0]--; // 서명 s 원상 복구
  }

  EC_KEY_free(eck_pub_key);

  Dot2_Release();
}


/**
 * @brief RA 인증서 서명검증 테스트 (인증서 내 서명은 X-only 형식을 가진다)
 *
 * RA 인증서의 서명이 ICA 공개키로 검증되는 것을 확인한다.
 */
TEST(VERIFY_CERT_SIGN, RA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  uint8_t tbs[kDot2CertSize_Max];
  size_t tbs_size;
  struct Dot2SHA256 issuer_h;
  EC_KEY *eck_pub_key;
  struct Dot2ECPublicKey pub_key;
  struct Dot2Signature sign;

  /*
   * 준비 : 서명검증 입력 정보를 설정한다.
   */
  {
    tbs_size = Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_tbs, tbs); // RA의 ToBeSignedCertificate
    ASSERT_EQ(tbs_size, g_tv_ra_cert_tbs_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_h, issuer_h.octs), DOT2_SHA_256_LEN); // 상위인증서(ICA) 해시
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_key_indicator, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN); // 상위인증서(ICA) 공개키
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret); // 상위인증서(ICA) 공개키
    ASSERT_TRUE(eck_pub_key != nullptr); // 상위인증서(ICA) 공개키
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_sig_r, sign.R_r.u.point.u.xy.x), DOT2_EC_256_KEY_LEN); // RA 인증서 서명 r
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_sig_s, sign.s), DOT2_EC_256_KEY_LEN); // RA 인증서 서명 s
  }

  /*
   * 테스트 : 서명 검증이 성공하는 것을 확인한다.
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), kDot2Result_Success);
  }

  /*
   * 테스트 : 데이터 변조 시 검증이 실패하는 것을 확인한다.
   */
  {
    tbs[0]++; // TBS 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    tbs[0]--; // TBS 원상복구

    pub_key.u.point.u.xy.x[0]++; // 상위인증서(ICA) 공개키 변조
    EC_KEY *eck_pub_key_invalid = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key_invalid != nullptr); // 상위인증서(ICA) 공개키
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key_invalid, &sign), -kDot2Result_SignatureVerificationFailed);
    EC_KEY_free(eck_pub_key_invalid);

    issuer_h.octs[0]++; // 상위인증서(ICA) 해시 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    issuer_h.octs[0]--; // 상위인증서(ICA) 해시 원상복구

    sign.R_r.u.point.u.xy.x[0]++; // 서명 r 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.R_r.u.point.u.xy.x[0]--; // 서명 r 원상복구

    sign.s[0]++; // 서명 s 변조
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs, tbs_size, &issuer_h, eck_pub_key, &sign), -kDot2Result_SignatureVerificationFailed);
    sign.s[0]--; // 서명 s 원상 복구
  }

  EC_KEY_free(eck_pub_key);

  Dot2_Release();
}
