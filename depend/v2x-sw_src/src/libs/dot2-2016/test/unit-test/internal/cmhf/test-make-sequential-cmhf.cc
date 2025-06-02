/** 
  * @file 
  * @brief Sequential CMHF 생성 관련 테스트
  * @date 2022-08-01 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"
#include "certificate/cert-info/dot2-cert-info.h"


// GHS rse-0/1AD2689A387D398D.*
static const char *tv_init_priv_key_0 = "9E31CD518CD86BA8A0E4F8DD9BF35FCBE9E6820332AEA19DFA0355878036FC2F";
static const char *tv_recon_priv_0 = "8693C4342127B52AC2B07AF6A219A2C3EF067A07E12FFD35543266736ADDBA65";
static const char *tv_recon_pub_0 = "02DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F108897043544";
static const char *tv_cert_0 = "000301802480E44BAB156FDA5083E30491000319E8D56F8400A983010180034801010001878182DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F108897043544";
static int tv_cert_size_0 = 71;
static const char *tv_tbs_cert_h_0 = "bbe95dd1b2544db6ca0ecda2a75e1f2277898d88522218925c0227bfcdfb8178";
static const char *tv_priv_key_0 = "58E274349E0D4CED5E4E80E65EB7E9F907BF6A9CD6ADEC5DAB4584BF27CA3538";
static const char *tv_pub_key_0 = "04AF67E87DD9099F988EE514AC0FE836A18C5349DCAC4A1DF18EDD7D39ACFEA9790C55FDF725663E60645C8994D3963B3036825518B4FE2CB6EAFA8E94D484F1C7";

// GHS rse-19/283D451144EA7F0B.cert
static const char *tv_init_priv_key_1 = "B6B9BFAD4F083FD4D7FAA8E22DD7B850597768BCB3EB004F369DF10A99601CB6";
static const char *tv_recon_priv_1 = "BC6C43B28E1BD972C462F9D6C36D16F5FC8795F715538C9CBD564FA97C977D8A";
static const char *tv_recon_pub_1 = "034974B2A265AD4B697FAB2C55432C9A8AEA398FF11918C3B19BCF1FBF2854359E";
static const char *tv_cert_1 = "000301802480E44BAB156FDA5083E3049100031A982D498400A9830101800348010100018781834974B2A265AD4B697FAB2C55432C9A8AEA398FF11918C3B19BCF1FBF2854359E";
static int tv_cert_size_1 = 71;
static const char *tv_tbs_cert_h_1 = "8e4ed629e494728ac7123200efbd747c64c72488934c7cba81a14cf304d2359b";
static const char *tv_priv_key_1 = "5FA92F3D11FD9B049310214D75EAB88A3A6037CB35743E477E5AC94A40E2FA4F";
static const char *tv_pub_key_1 = "04FF2838941D221C11C670EFA0936C00E9884DAFD212E13BEEC2D89E90A20E4D997D6688772FDAFD0579484045DC96FEB0FA210B107410466682AB0BC2B8620EBB";

// GHS pca
static const char *tv_issuer = "80030080B7CBD0F79B969BD459811A7063612E70726570726F642E7632782E697373636D732E636F6DE30491000219D8D5DD86000A83010380007C8001E48003480101800123800385000101010081008082B0FF2F290F9E77FE940759C877B8F0516D411E44BC58F612615A26D726A0D79F808082FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A808066CB66CDF3DDFBD285521E187DE229EA9161C8D24C676B7C837C9FBE12A9CD20B8E45B5E81D5A55737FA17439D2F1FD3D59ABBF24987F61ABE6F9FFB9F14CFB7";
static int tv_issuer_size = 215;
static const char *tv_issuer_h = "7D313C1146962D25B7EBD360FC988637534AC7F58F95A4282480E44BAB156FDA";
static const char *tv_issuer_pub_key = "02FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A";

// CMHF 결과
static const char *tv_cmhf_name_0 = "a_135_171010.030306-171017.040306_key.cmhf2";
static int tv_cmhf_size_0 = 182;
static const char *tv_cmhf_0 = "4954454B012480E44BAB156FDAE30491000319E8D56F19F21DFF0201000000870103480047029AF2E88E0B439479EECD76BE56D04D2118F589986CF5C06C41F6BE070ECE81030058E274349E0D4CED5E4E80E65EB7E9F907BF6A9CD6ADEC5DAB4584BF27CA3538000301802480E44BAB156FDA5083E30491000319E8D56F8400A983010180034801010001878182DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F108897043544da44fdf3766973c8";
static const char *tv_cmhf_name_1 = "a_135_180220.030436-180227.040436_key.cmhf2";
static int tv_cmhf_size_1 = 182;
static const char *tv_cmhf_1 = "4954454B012480E44BAB156FDAE3049100031A982D491AA175D9020100000087010348004739EFB4330BF850FF32B62882202962680FD5255DF68E4864C1D264722FD9233A03005FA92F3D11FD9B049310214D75EAB88A3A6037CB35743E477E5AC94A40E2FA4F000301802480E44BAB156FDA5083E3049100031A982D498400A9830101800348010100018781834974B2A265AD4B697FAB2C55432C9A8AEA398FF11918C3B19BCF1FBF2854359Ec8fa4fc989c6f52b";


/**
 * @brief 기본 동작을 확인한다.
 */
TEST(MAKE_SEQ_CMHF, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2ECPrivateKey init_priv_key{}, recon_priv{}, expected_priv_key{};
  uint8_t expected_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize expected_cmhf_size;
  struct Dot2SHA256 issuer_h{};
  struct Dot2Cert cert{}, issuer{};

  /*
   * 테스트벡터 #1
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(tv_issuer, issuer.octs), (size_t)tv_issuer_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_cert_0, cert.octs), (size_t)tv_cert_size_0);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_init_priv_key_0, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_priv_0, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_priv_key_0, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(tv_cmhf_0, expected_cmhf), (size_t)tv_cmhf_size_0);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(tv_cmhf_name_0));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, tv_cmhf_name_0, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  /*
   * 테스트벡터 #2
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(tv_issuer, issuer.octs), (size_t)tv_issuer_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_cert_1, cert.octs), (size_t)tv_cert_size_1);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_init_priv_key_1, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_priv_1, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_priv_key_1, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(tv_cmhf_1, expected_cmhf), (size_t)tv_cmhf_size_1);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(tv_cmhf_name_1));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, tv_cmhf_name_1, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  /*
   * 테스트벡터 #3 - g_tv_bundle_0_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, issuer.octs), (size_t)g_tv_bundle_0_pca_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0, cert.octs), (size_t)g_tv_bundle_0_app_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, expected_cmhf), (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(g_tv_bundle_0_app_cert_0_cmhf_name));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_tv_bundle_0_app_cert_0_cmhf_name, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  /*
   * 테스트벡터 #4 - g_tv_bundle_0_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, issuer.octs), (size_t)g_tv_bundle_0_pca_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1, cert.octs), (size_t)g_tv_bundle_0_app_cert_1_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_cmhf, expected_cmhf), (size_t)g_tv_bundle_0_app_cert_1_cmhf_size);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(g_tv_bundle_0_app_cert_1_cmhf_name));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_tv_bundle_0_app_cert_1_cmhf_name, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  /*
   * 테스트벡터 #5 - g_tv_bundle_1_enrol_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca, issuer.octs), (size_t)g_tv_bundle_1_eca_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0, cert.octs), (size_t)g_tv_bundle_1_enrol_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_cmhf, expected_cmhf), (size_t)g_tv_bundle_1_enrol_cert_0_cmhf_size);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Enrollment,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(g_tv_bundle_1_enrol_cert_0_cmhf_name));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_tv_bundle_1_enrol_cert_0_cmhf_name, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  /*
   * 테스트벡터 #6 - g_tv_bundle_1_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca, issuer.octs), (size_t)g_tv_bundle_1_pca_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0, cert.octs), (size_t)g_tv_bundle_1_app_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_cmhf, expected_cmhf), (size_t)g_tv_bundle_1_app_cert_0_cmhf_size);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(g_tv_bundle_1_app_cert_0_cmhf_name));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_tv_bundle_1_app_cert_0_cmhf_name, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  /*
   * 테스트벡터 #6 - g_tv_bundle_1_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca, issuer.octs), (size_t)g_tv_bundle_1_pca_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1, cert.octs), (size_t)g_tv_bundle_1_app_cert_1_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_cmhf, expected_cmhf), (size_t)g_tv_bundle_1_app_cert_1_cmhf_size);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      struct Dot2ECPrivateKey priv_key{};
      ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                     &init_priv_key,
                                                     &recon_priv,
                                                     &cert,
                                                     &issuer,
                                                     &cmhf_name,
                                                     &cmhf,
                                                     &cmhf_size,
                                                     &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(g_tv_bundle_1_app_cert_1_cmhf_name));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_tv_bundle_1_app_cert_1_cmhf_name, strlen(cmhf_name)));
      ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
    }
  }

  // 테스트
  {
    memcpy(issuer.octs, g_sample_pca_cert, g_sample_pca_cert_size);
    issuer.size = g_sample_pca_cert_size;
    memcpy(cert.octs, g_sample_rse_4_cert, g_sample_rse_4_cert_size);
    cert.size = g_sample_rse_4_cert_size;
    memcpy(init_priv_key.octs, g_sample_rse_4_cr_priv_key, 32);
    memcpy(recon_priv.octs, g_sample_rse_4_recon_priv, 32);
    memcpy(expected_priv_key.octs, g_sample_rse_4_priv_key, 32);
    expected_cmhf_size = g_sample_rse_4_cmhf_size;
    memcpy(expected_cmhf, g_sample_rse_4_cmhf, g_sample_rse_4_cmhf_size);

    char *cmhf_name;
    uint8_t *cmhf;
    Dot2CMHFSize cmhf_size;
    struct Dot2ECPrivateKey priv_key{};
    ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                   &init_priv_key,
                                                   &recon_priv,
                                                   &cert,
                                                   &issuer,
                                                   &cmhf_name,
                                                   &cmhf,
                                                   &cmhf_size,
                                                   &priv_key);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_TRUE(cmhf_name != nullptr);
    ASSERT_TRUE(cmhf != nullptr);
    ASSERT_EQ(strlen(cmhf_name), strlen(g_sample_rse_4_key_cmhf_name));
    ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_sample_rse_4_key_cmhf_name, strlen(cmhf_name)));
    ASSERT_EQ((int)cmhf_size, (int)expected_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, sizeof(priv_key.octs)));
  }


  Dot2_Release();
}
