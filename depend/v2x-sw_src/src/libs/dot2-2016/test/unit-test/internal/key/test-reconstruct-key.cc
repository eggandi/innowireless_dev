/** 
  * @file 
  * @brief 개인키/공개키 재구성 관련 테스트
  * @date 2022-08-01 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "sec-executer/openssl/dot2-openssl.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


/*
 * KISA v1.1 규격 "01-07.KCAC.V2X.IMPCERTSCH_암시적 인증서 스키마 규격_v1.1" 테스트벡터 0
 */
static const char *tv_key_reconstruct_kU_0 = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"; // 초기 개인키
static const char *tv_key_reconstruct_CertU_0 = "54686973206973206120746573742100024A1890E30A584208DAD3838D0C5CECB1ED6B01D48893C684C59908F5B38E3D82"; // CertU
static const char *tv_key_reconstruct_CertU_h_0 = "966eccce39e05b541be571055dc63f7df377e79847167e2b8e92f8327fac384d"; // CertU에 대해 online 계산기로 계산
static const char *tv_key_reconstruct_r_0 = "8A7966677B40674389118E269777451174564A3AD57FEC31F4EEFF07C641B4C8"; // 개인키 재구성값
static const char *tv_key_reconstruct_PU_0 = "024A1890E30A584208DAD3838D0C5CECB1ED6B01D48893C684C59908F5B38E3D82"; // 공개키 재구성값 (압축형식)
static const char *tv_key_reconstruct_QCA_0 = "043BB8FFD19B25EE1BB939CD4935FBFA8FBAADBA64843338A95595A70ED7479B70EB60DDC790E3CB05E85225F636D8A7C20DF3A8135C4B2AE5396367B4E86077F8"; // CA 공개키
static const char *tv_key_reconstruct_dU_0 = "EF6095F346D8DA2B95B88102C7D50B39FBDC1BD75EB56D556020B1EE0B9FA5A7"; // 재구성된 개인키
static const char *tv_key_reconstruct_QU_0 = "04E76F7751EEC099CCCF074927FB0C0E4BC9EF7434B70119B39A91D150A2CA69A9174C7CCA46F5D73439F79987CB613B229ABE3F1F8D163E3D677211A690A8EC31"; // 재구성된 공개키 (비압축형식)

/*
 * KISA v1.1 규격 "01-07.KCAC.V2X.IMPCERTSCH_암시적 인증서 스키마 규격_v1.1" 테스트벡터 1
 */
static const char *tv_key_reconstruct_kU_1 = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"; // 초기 개인키
static const char *tv_key_reconstruct_CertU_1 = "5468697320697320612074657374210002237B2D6610DA5B67E18AAEC0F09C99EE08D4F00852C7ED27C12963120F76A147"; // CertU
static const char *tv_key_reconstruct_CertU_h_1 = "66f73a02c6e1c4a2cd93ed2d60d8284a9450f5d1c6fd0aeb1e4be7557534e950"; // CertU에 대해 online 계산기로 계산
static const char *tv_key_reconstruct_r_1 = "06A8D6FCDC18AC05F6D9D88AB2C31B462E72C58C60555A3D9DF83DB6F2E3142B"; // 개인키 재구성값
static const char *tv_key_reconstruct_PU_1 = "02237B2D6610DA5B67E18AAEC0F09C99EE08D4F00852C7ED27C12963120F76A147"; // 공개키 재구성값 (압축형식)
static const char *tv_key_reconstruct_QCA_1 = "043BB8FFD19B25EE1BB939CD4935FBFA8FBAADBA64843338A95595A70ED7479B70EB60DDC790E3CB05E85225F636D8A7C20DF3A8135C4B2AE5396367B4E86077F8"; // CA 공개키
static const char *tv_key_reconstruct_dU_1 = "49FC4F116692225FEB26CC6366BB6D60CA6D6082DDFA980BD12FF7415AFD8439"; // 재구성된 개인키
static const char *tv_key_reconstruct_QU_1 = "046442A1639E68ACF735E3F30BDC02AC4A6AB4F8D7B497D03BE1B95F0F563424A0C5871A8F84A728DCD52835635CD53F47017B7FC6BE3CAF4052AE6D11D7F3D37C"; // 재구성된 공개키 (비압축형식)

// GHS rse-0/1AD2689A387D398D.*
static const char *tv_key_recon_init_priv_key_0 = "9E31CD518CD86BA8A0E4F8DD9BF35FCBE9E6820332AEA19DFA0355878036FC2F";
static const char *tv_key_recon_recon_priv_0 = "8693C4342127B52AC2B07AF6A219A2C3EF067A07E12FFD35543266736ADDBA65";
static const char *tv_key_recon_recon_pub_0 = "02DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F108897043544";
static const char *tv_key_recon_cert_0 = "000301802480E44BAB156FDA5083E30491000319E8D56F8400A983010180034801010001878182DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F108897043544";
static const char *tv_key_recon_priv_key_0 = "58E274349E0D4CED5E4E80E65EB7E9F907BF6A9CD6ADEC5DAB4584BF27CA3538";
static const char *tv_key_recon_pub_key_0 = "04AF67E87DD9099F988EE514AC0FE836A18C5349DCAC4A1DF18EDD7D39ACFEA9790C55FDF725663E60645C8994D3963B3036825518B4FE2CB6EAFA8E94D484F1C7";
static int tv_key_recon_cert_size_0 = 71;
static const char *tv_key_recon_tbs_cert_h_0 = "bbe95dd1b2544db6ca0ecda2a75e1f2277898d88522218925c0227bfcdfb8178";
// GHS pca
static const char *tv_key_recon_issuer_h_0 = "7D313C1146962D25B7EBD360FC988637534AC7F58F95A4282480E44BAB156FDA";
static const char *tv_key_recon_issuer_pub_key_0 = "02FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A";

// GHS rse-19/283D451144EA7F0B.cert
static const char *tv_key_recon_init_priv_key_1 = "B6B9BFAD4F083FD4D7FAA8E22DD7B850597768BCB3EB004F369DF10A99601CB6";
static const char *tv_key_recon_recon_priv_1 = "BC6C43B28E1BD972C462F9D6C36D16F5FC8795F715538C9CBD564FA97C977D8A";
static const char *tv_key_recon_recon_pub_1 = "034974B2A265AD4B697FAB2C55432C9A8AEA398FF11918C3B19BCF1FBF2854359E";
static const char *tv_key_recon_cert_1 = "000301802480E44BAB156FDA5083E3049100031A982D498400A9830101800348010100018781834974B2A265AD4B697FAB2C55432C9A8AEA398FF11918C3B19BCF1FBF2854359E";
static int tv_key_recon_cert_size_1 = 71;
static const char *tv_key_recon_tbs_cert_h_1 = "8e4ed629e494728ac7123200efbd747c64c72488934c7cba81a14cf304d2359b";
static const char *tv_key_recon_priv_key_1 = "5FA92F3D11FD9B049310214D75EAB88A3A6037CB35743E477E5AC94A40E2FA4F";
static const char *tv_key_recon_pub_key_1 = "04FF2838941D221C11C670EFA0936C00E9884DAFD212E13BEEC2D89E90A20E4D997D6688772FDAFD0579484045DC96FEB0FA210B107410466682AB0BC2B8620EBB";
// GHS pca
static const char *tv_key_recon_issuer_h_1 = "7D313C1146962D25B7EBD360FC988637534AC7F58F95A4282480E44BAB156FDA";
static const char *tv_key_recon_issuer_pub_key_1 = "02FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A";


/*
 * 키쌍 재구성 동작 확인
 */
TEST(RECONSTRUCT_KEY, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  EC_KEY *eck_priv_key, *eck_pub_key;
  int ret;
  struct Dot2ECPrivateKey init_priv_key, recon_priv, expected_priv_key, priv_key;
  struct Dot2ECPublicKey recon_pub, issuer_pub_key, expected_pub_key, pub_key;
  struct Dot2SHA256 h_input, issuer_h;
  struct Dot2Cert cert;
  struct Dot2SHA256 tbs_cert_h;

  /*
   * KISA 규격 테스트벡터 0 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_kU_0, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_r_0, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_PU_0, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_QCA_0, issuer_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_dU_0, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_QU_0, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_CertU_h_0, h_input.octs), DOT2_SHA_256_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_3(&init_priv_key, &recon_priv, &h_input, &priv_key, &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_3(&recon_pub,
                                                                 &h_input,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * KISA 규격 테스트벡터 1 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_kU_1, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_r_1, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_PU_1, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_QCA_1, issuer_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_dU_1, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_QU_1, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_CertU_h_1, h_input.octs), DOT2_SHA_256_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_3(&init_priv_key, &recon_priv, &h_input, &priv_key, &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_3(&recon_pub,
                                                                 &h_input,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * 테스트벡터 0 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_init_priv_key_0, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_recon_priv_0, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_recon_pub_0, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_key_recon_cert_0, cert.octs), (size_t)tv_key_recon_cert_size_0);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_tbs_cert_h_0, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_issuer_h_0, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_issuer_pub_key_0, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_priv_key_0, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_pub_key_0, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }


  /*
   * 테스트벡터 1 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_init_priv_key_1, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_recon_priv_1, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_recon_pub_1, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_key_recon_cert_1, cert.octs), (size_t)tv_key_recon_cert_size_1);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_tbs_cert_h_1, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_issuer_h_1, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_issuer_pub_key_1, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_priv_key_1, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_recon_pub_key_1, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * 테스트벡터 2 테스트 - g_tv_bundle_0_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0, cert.octs), g_tv_bundle_0_app_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_tbs_h, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_pub_key, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_pub_key, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * 테스트벡터 3 테스트 - g_tv_bundle_0_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1, cert.octs), g_tv_bundle_0_app_cert_1_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_tbs_h, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_pub_key, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_pub_key, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * 테스트벡터 4 테스트 - g_tv_bundle_1_enrol_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0, cert.octs), (size_t)g_tv_bundle_1_enrol_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_tbs_h, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca_pub_key, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_pub_key, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * 테스트 - g_tv_bundle_1_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0, cert.octs), (size_t)g_tv_bundle_1_app_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_tbs_h, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_pub_key, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_pub_key, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  /*
   * 테스트 - g_tv_bundle_1_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1, cert.octs), (size_t)g_tv_bundle_1_app_cert_1_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_tbs_h, tbs_cert_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_pub_key, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_pub_key, expected_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    }

    // 테스트 : 개인키/공개키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      // 개인키 재구성
      eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key,
                                                                   &recon_priv,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &priv_key,
                                                                   &ret);
      ASSERT_TRUE(eck_priv_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));

      // 공개키 재구성
      eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&recon_pub,
                                                                 &cert,
                                                                 &issuer_h,
                                                                 &issuer_pub_key,
                                                                 &pub_key,
                                                                 &ret);
      ASSERT_TRUE(eck_pub_key);
      ASSERT_TRUE(Dot2Test_CompareOctets(pub_key.u.octs, expected_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));

      // 키쌍 유효성 확인
      ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
      EC_KEY_free(eck_priv_key);
      EC_KEY_free(eck_pub_key);
    }
  }

  Dot2_Release();
}
