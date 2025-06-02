/** 
 * @file
 * @brief 개인키 재구성 관련 테스트
 * @date 2022-07-31
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "sec-executer/openssl/dot2-openssl.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


/*
 * KISA v1.1 규격 "01-07.KCAC.V2X.IMPCERTSCH_암시적 인증서 스키마 규격_v1.1" 테스트벡터 1
 */
static const char *tv_key_reconstruct_kU_1 = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"; // 초기 개인키
static const char *tv_key_reconstruct_CertU_1 = "54686973206973206120746573742100024A1890E30A584208DAD3838D0C5CECB1ED6B01D48893C684C59908F5B38E3D82"; // CertU
static const char *tv_key_reconstruct_CertU_h_1 = "966eccce39e05b541be571055dc63f7df377e79847167e2b8e92f8327fac384d"; // CertU에 대해 online 계산기로 계산
static const char *tv_key_reconstruct_r_1 = "8A7966677B40674389118E269777451174564A3AD57FEC31F4EEFF07C641B4C8"; // 개인키 재구성값
static const char *tv_key_reconstruct_PU_1 = "024A1890E30A584208DAD3838D0C5CECB1ED6B01D48893C684C59908F5B38E3D82"; // 공개키 재구성값 (압축형식)
static const char *tv_key_reconstruct_QCA_1 = "043BB8FFD19B25EE1BB939CD4935FBFA8FBAADBA64843338A95595A70ED7479B70EB60DDC790E3CB05E85225F636D8A7C20DF3A8135C4B2AE5396367B4E86077F8"; // CA 공개키
static const char *tv_key_reconstruct_dU_1 = "EF6095F346D8DA2B95B88102C7D50B39FBDC1BD75EB56D556020B1EE0B9FA5A7"; // 재구성된 개인키
static const char *tv_key_reconstruct_QU_1 = "04E76F7751EEC099CCCF074927FB0C0E4BC9EF7434B70119B39A91D150A2CA69A9174C7CCA46F5D73439F79987CB613B229ABE3F1F8D163E3D677211A690A8EC31"; // 재구성된 공개키 (비압축형식)

/*
 * KISA v1.1 규격 "01-07.KCAC.V2X.IMPCERTSCH_암시적 인증서 스키마 규격_v1.1" 테스트벡터 2
 */
static const char *tv_key_reconstruct_kU_2 = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"; // 초기 개인키
static const char *tv_key_reconstruct_CertU_2 = "5468697320697320612074657374210002237B2D6610DA5B67E18AAEC0F09C99EE08D4F00852C7ED27C12963120F76A147"; // CertU
static const char *tv_key_reconstruct_CertU_h_2 = "66f73a02c6e1c4a2cd93ed2d60d8284a9450f5d1c6fd0aeb1e4be7557534e950"; // CertU에 대해 online 계산기로 계산
static const char *tv_key_reconstruct_r_2 = "06A8D6FCDC18AC05F6D9D88AB2C31B462E72C58C60555A3D9DF83DB6F2E3142B"; // 개인키 재구성값
static const char *tv_key_reconstruct_PU_2 = "02237B2D6610DA5B67E18AAEC0F09C99EE08D4F00852C7ED27C12963120F76A147"; // 공개키 재구성값 (압축형식)
static const char *tv_key_reconstruct_QCA_2 = "043BB8FFD19B25EE1BB939CD4935FBFA8FBAADBA64843338A95595A70ED7479B70EB60DDC790E3CB05E85225F636D8A7C20DF3A8135C4B2AE5396367B4E86077F8"; // CA 공개키
static const char *tv_key_reconstruct_dU_2 = "49FC4F116692225FEB26CC6366BB6D60CA6D6082DDFA980BD12FF7415AFD8439"; // 재구성된 개인키
static const char *tv_key_reconstruct_QU_2 = "046442A1639E68ACF735E3F30BDC02AC4A6AB4F8D7B497D03BE1B95F0F563424A0C5871A8F84A728DCD52835635CD53F47017B7FC6BE3CAF4052AE6D11D7F3D37C"; // 재구성된 공개키 (비압축형식)

/*
 * GHS 인증서
 */
static const char *tv_key_reconstruct_init_priv_key_3 = "9E31CD518CD86BA8A0E4F8DD9BF35FCBE9E6820332AEA19DFA0355878036FC2F";
static const char *tv_key_reconstruct_recon_priv_3 = "8693C4342127B52AC2B07AF6A219A2C3EF067A07E12FFD35543266736ADDBA65";
static const char *tv_key_reconstruct_cert_3 = "000301802480E44BAB156FDA5083E30491000319E8D56F8400A983010180034801010001878182DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F108897043544";
static size_t tv_key_reconstruct_cert_size_3 = 71;
static const char *tv_key_reconstruct_recon_pub_3 = "04DA96FF5838A904158D726A1EA87D2BB5C019B8417E3785619D4F1088970435449B1175DED9F5AE34D719E99EF9F320807321AD541E628CF38D52C3E33C1272EC";
static const char *tv_key_reconstruct_issuer_cert_3 = "80030080B7CBD0F79B969BD459811A7063612E70726570726F642E7632782E697373636D732E636F6DE30491000219D8D5DD86000A83010380007C8001E48003480101800123800385000101010081008082B0FF2F290F9E77FE940759C877B8F0516D411E44BC58F612615A26D726A0D79F808082FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A808066CB66CDF3DDFBD285521E187DE229EA9161C8D24C676B7C837C9FBE12A9CD20B8E45B5E81D5A55737FA17439D2F1FD3D59ABBF24987F61ABE6F9FFB9F14CFB7";
static size_t tv_key_reconstruct_issuer_cert_size_3 = 215;
static const char *tv_key_reconstruct_issuer_cert_h_3 = "7D313C1146962D25B7EBD360FC988637534AC7F58F95A4282480E44BAB156FDA";
static const char *tv_key_reconstruct_issuer_pub_key_3 = "04FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A58A109D617F786BECEA4421759829E9C88A9E10146DD3E24ABCE9D984131341A";
static const char *tv_key_reconstruct_priv_key_3 = "58E274349E0D4CED5E4E80E65EB7E9F907BF6A9CD6ADEC5DAB4584BF27CA3538";
static const char *tv_key_reconstruct_pub_key_3 = "04AF67E87DD9099F988EE514AC0FE836A18C5349DCAC4A1DF18EDD7D39ACFEA9790C55FDF725663E60645C8994D3963B3036825518B4FE2CB6EAFA8E94D484F1C7";
static const char *tv_key_reconstruct_init_priv_key_4 = "5F95391CF69468FB91A1F16D435E4531782239385E7E03EDE4B0A6A3D82AFCFF";
static const char *tv_key_reconstruct_recon_priv_4 = "44AC54EE38A3F2F5B100A92448C5285FAE29CA00A5A144DB0511379001A3ABDD";
static const char *tv_key_reconstruct_cert_4 = "000301802480E44BAB156FDA5083E30491000319F20FF48400A9830101800348010100018781824079976DF871E5D06DE6453236060DC49E009C59DC14E539084135F5DB97E7C7";
static size_t tv_key_reconstruct_cert_size_4 = 71;
static const char *tv_key_reconstruct_recon_pub_4 = "044079976DF871E5D06DE6453236060DC49E009C59DC14E539084135F5DB97E7C75BA8AC5F17ECD3B1E7FBD8C4B6DF496967A8937173D9521A4EF9CB42ACC123DA";
static const char *tv_key_reconstruct_issuer_cert_4 = "80030080B7CBD0F79B969BD459811A7063612E70726570726F642E7632782E697373636D732E636F6DE30491000219D8D5DD86000A83010380007C8001E48003480101800123800385000101010081008082B0FF2F290F9E77FE940759C877B8F0516D411E44BC58F612615A26D726A0D79F808082FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A808066CB66CDF3DDFBD285521E187DE229EA9161C8D24C676B7C837C9FBE12A9CD20B8E45B5E81D5A55737FA17439D2F1FD3D59ABBF24987F61ABE6F9FFB9F14CFB7";
static size_t tv_key_reconstruct_issuer_cert_size_4 = 215;
static const char *tv_key_reconstruct_issuer_cert_h_4 = "7D313C1146962D25B7EBD360FC988637534AC7F58F95A4282480E44BAB156FDA";
static const char *tv_key_reconstruct_issuer_pub_key_4 = "04FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A58A109D617F786BECEA4421759829E9C88A9E10146DD3E24ABCE9D984131341A";
static const char *tv_key_reconstruct_priv_key_4 = "D47291ACE0CA5D337317F38914CFE11FF7753A1E3BF2097A7BD462EF11066417";
static const char *tv_key_reconstruct_pub_key_4 = "0464759C5A9947D82BCA983C52F296117C352276E62D880DBD04864039D1E149CB8E1B85B142C7FDE16B77EC52380233A7BE71C7C0F8A67AD68F43F84717DB3249";



/*
 * 개인키 재구성 동작 확인
 */
TEST(RECONSTRUCT_PRIV_KEY, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2ECPrivateKey init_priv_key, recon_priv, priv_key_expected, priv_key;
  struct Dot2SHA256 h_input, issuer_h;
  struct Dot2Cert cert;

  /*
   * 테스트벡터 1 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_kU_1, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_r_1, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_dU_1, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_CertU_h_1, h_input.octs), DOT2_SHA_256_LEN);
    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_3(&init_priv_key, &recon_priv, &h_input, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 2 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_kU_2, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_r_2, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_dU_2, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_CertU_h_2, h_input.octs), DOT2_SHA_256_LEN);
    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_3(&init_priv_key, &recon_priv, &h_input, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 3 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_init_priv_key_3, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_recon_priv_3, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_priv_key_3, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_cert_3, cert.octs), tv_key_reconstruct_cert_size_3);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_issuer_cert_h_3, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 4 테스트
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_init_priv_key_4, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_recon_priv_4, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_priv_key_4, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_cert_4, cert.octs), tv_key_reconstruct_cert_size_4);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_key_reconstruct_issuer_cert_h_4, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 - g_tv_bundle_0_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_priv_key, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0, cert.octs), g_tv_bundle_0_app_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 - g_tv_bundle_0_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_priv_key, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1, cert.octs), g_tv_bundle_0_app_cert_1_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 - g_tv_bundle_1_enrol_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_priv_key, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0, cert.octs), (size_t)g_tv_bundle_1_enrol_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca_h, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 - g_tv_bundle_1_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_priv_key, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0, cert.octs), (size_t)g_tv_bundle_1_app_cert_0_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  /*
   * 테스트벡터 - g_tv_bundle_1_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_priv_key, priv_key_expected.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(cert.size = (Dot2CertSize)Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1, cert.octs), (size_t)g_tv_bundle_1_app_cert_1_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);

    }

    // 테스트 : 개인키를 재구성하고 그 결과가 정확한지 확인한다.
    {
      EC_KEY *eck = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&init_priv_key, &recon_priv, &cert, &issuer_h, &priv_key, &ret);
      ASSERT_TRUE(eck != nullptr);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, priv_key_expected.octs, DOT2_EC_256_KEY_LEN));
      EC_KEY_free(eck);
    }
  }

  Dot2_Release();
}


#if 0
// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-funcs.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-key.h"
#include "../../test-common-funcs/test-common-funcs.h"


/// 샘플 테스트 벡터 개수
#define SAMPLE_TEST_VECTOR_NUM (5)


/// 샘플 테스트벡터
/// 출처 : GHS 발급 RSE 인증서
static const struct Dot2KeyReconstructTestVector g_sample_tv[SAMPLE_TEST_VECTOR_NUM] = {
  // Sample test vector #1 - GHS rse-0/1AD2689A387D398D.*
  {
    { // cr_priv_key
      0x9E, 0x31, 0xCD, 0x51, 0x8C, 0xD8, 0x6B, 0xA8, 0xA0, 0xE4, 0xF8, 0xDD, 0x9B, 0xF3, 0x5F, 0xCB,
      0xE9, 0xE6, 0x82, 0x03, 0x32, 0xAE, 0xA1, 0x9D, 0xFA, 0x03, 0x55, 0x87, 0x80, 0x36, 0xFC, 0x2F
    },
    { // recon_priv
      0x86, 0x93, 0xC4, 0x34, 0x21, 0x27, 0xB5, 0x2A, 0xC2, 0xB0, 0x7A, 0xF6, 0xA2, 0x19, 0xA2, 0xC3,
      0xEF, 0x06, 0x7A, 0x07, 0xE1, 0x2F, 0xFD, 0x35, 0x54, 0x32, 0x66, 0x73, 0x6A, 0xDD, 0xBA, 0x65
    },
    { // my_cert
      0x00, 0x03, 0x01, 0x80, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA, 0x50, 0x83, 0xE3, 0x04,
      0x91, 0x00, 0x03, 0x19, 0xE8, 0xD5, 0x6F, 0x84, 0x00, 0xA9, 0x83, 0x01, 0x01, 0x80, 0x03, 0x48,
      0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0xDA, 0x96, 0xFF, 0x58, 0x38, 0xA9, 0x04, 0x15, 0x8D,
      0x72, 0x6A, 0x1E, 0xA8, 0x7D, 0x2B, 0xB5, 0xC0, 0x19, 0xB8, 0x41, 0x7E, 0x37, 0x85, 0x61, 0x9D,
      0x4F, 0x10, 0x88, 0x97, 0x04, 0x35, 0x44
    },
    71, // my_cert_size
    { // recon_pub (인증서 내 compressed 형식 recon_pub 를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0xDA, 0x96, 0xFF, 0x58, 0x38, 0xA9, 0x04, 0x15, 0x8D, 0x72, 0x6A, 0x1E, 0xA8, 0x7D, 0x2B, 0xB5,
      0xC0, 0x19, 0xB8, 0x41, 0x7E, 0x37, 0x85, 0x61, 0x9D, 0x4F, 0x10, 0x88, 0x97, 0x04, 0x35, 0x44,
      0x9B, 0x11, 0x75, 0xDE, 0xD9, 0xF5, 0xAE, 0x34, 0xD7, 0x19, 0xE9, 0x9E, 0xF9, 0xF3, 0x20, 0x80,
      0x73, 0x21, 0xAD, 0x54, 0x1E, 0x62, 0x8C, 0xF3, 0x8D, 0x52, 0xC3, 0xE3, 0x3C, 0x12, 0x72, 0xEC
    },
    { // issuer_cert
      0x80, 0x03, 0x00, 0x80, 0xB7, 0xCB, 0xD0, 0xF7, 0x9B, 0x96, 0x9B, 0xD4, 0x59, 0x81, 0x1A, 0x70,
      0x63, 0x61, 0x2E, 0x70, 0x72, 0x65, 0x70, 0x72, 0x6F, 0x64, 0x2E, 0x76, 0x32, 0x78, 0x2E, 0x69,
      0x73, 0x73, 0x63, 0x6D, 0x73, 0x2E, 0x63, 0x6F, 0x6D, 0xE3, 0x04, 0x91, 0x00, 0x02, 0x19, 0xD8,
      0xD5, 0xDD, 0x86, 0x00, 0x0A, 0x83, 0x01, 0x03, 0x80, 0x00, 0x7C, 0x80, 0x01, 0xE4, 0x80, 0x03,
      0x48, 0x01, 0x01, 0x80, 0x01, 0x23, 0x80, 0x03, 0x85, 0x00, 0x01, 0x01, 0x01, 0x00, 0x81, 0x00,
      0x80, 0x82, 0xB0, 0xFF, 0x2F, 0x29, 0x0F, 0x9E, 0x77, 0xFE, 0x94, 0x07, 0x59, 0xC8, 0x77, 0xB8,
      0xF0, 0x51, 0x6D, 0x41, 0x1E, 0x44, 0xBC, 0x58, 0xF6, 0x12, 0x61, 0x5A, 0x26, 0xD7, 0x26, 0xA0,
      0xD7, 0x9F, 0x80, 0x80, 0x82, 0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3,
      0xB1, 0x2A, 0x38, 0x70, 0x91, 0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7,
      0x72, 0x5B, 0x89, 0xF5, 0x9A, 0x80, 0x80, 0x66, 0xCB, 0x66, 0xCD, 0xF3, 0xDD, 0xFB, 0xD2, 0x85,
      0x52, 0x1E, 0x18, 0x7D, 0xE2, 0x29, 0xEA, 0x91, 0x61, 0xC8, 0xD2, 0x4C, 0x67, 0x6B, 0x7C, 0x83,
      0x7C, 0x9F, 0xBE, 0x12, 0xA9, 0xCD, 0x20, 0xB8, 0xE4, 0x5B, 0x5E, 0x81, 0xD5, 0xA5, 0x57, 0x37,
      0xFA, 0x17, 0x43, 0x9D, 0x2F, 0x1F, 0xD3, 0xD5, 0x9A, 0xBB, 0xF2, 0x49, 0x87, 0xF6, 0x1A, 0xBE,
      0x6F, 0x9F, 0xFB, 0x9F, 0x14, 0xCF, 0xB7
    },
    215, // issuer_cert_size
    { // h_issuer (pca)
      0x7D, 0x31, 0x3C, 0x11, 0x46, 0x96, 0x2D, 0x25, 0xB7, 0xEB, 0xD3, 0x60, 0xFC, 0x98, 0x86, 0x37,
      0x53, 0x4A, 0xC7, 0xF5, 0x8F, 0x95, 0xA4, 0x28, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA
    },
    { // issuer_pub_key (인증서 내 compressed 형식 공개키를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3, 0xB1, 0x2A, 0x38, 0x70, 0x91,
      0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7, 0x72, 0x5B, 0x89, 0xF5, 0x9A,
      0x58, 0xA1, 0x09, 0xD6, 0x17, 0xF7, 0x86, 0xBE, 0xCE, 0xA4, 0x42, 0x17, 0x59, 0x82, 0x9E, 0x9C,
      0x88, 0xA9, 0xE1, 0x01, 0x46, 0xDD, 0x3E, 0x24, 0xAB, 0xCE, 0x9D, 0x98, 0x41, 0x31, 0x34, 0x1A
    },
    { // priv_key
      0x58, 0xE2, 0x74, 0x34, 0x9E, 0x0D, 0x4C, 0xED, 0x5E, 0x4E, 0x80, 0xE6, 0x5E, 0xB7, 0xE9, 0xF9,
      0x07, 0xBF, 0x6A, 0x9C, 0xD6, 0xAD, 0xEC, 0x5D, 0xAB, 0x45, 0x84, 0xBF, 0x27, 0xCA, 0x35, 0x38
    },
    { // pub_key (위 개인키로부터 libdot2 의 검증된 dot2_openssl_GeneratePublicKeyFromPrivateKey()를 이용하여 공개키 생성함)
      kDot2ECPointForm_Uncompressed,
      0xAF, 0x67, 0xE8, 0x7D, 0xD9, 0x09, 0x9F, 0x98, 0x8E, 0xE5, 0x14, 0xAC, 0x0F, 0xE8, 0x36, 0xA1,
      0x8C, 0x53, 0x49, 0xDC, 0xAC, 0x4A, 0x1D, 0xF1, 0x8E, 0xDD, 0x7D, 0x39, 0xAC, 0xFE, 0xA9, 0x79,
      0x0C, 0x55, 0xFD, 0xF7, 0x25, 0x66, 0x3E, 0x60, 0x64, 0x5C, 0x89, 0x94, 0xD3, 0x96, 0x3B, 0x30,
      0x36, 0x82, 0x55, 0x18, 0xB4, 0xFE, 0x2C, 0xB6, 0xEA, 0xFA, 0x8E, 0x94, 0xD4, 0x84, 0xF1, 0xC7
    }
  },

  // Sample test vector #2 - GHS rse-1/AF45F525FDBFF6F4.cert
  {
    { // cr_priv_key
      0x5F, 0x95, 0x39, 0x1C, 0xF6, 0x94, 0x68, 0xFB, 0x91, 0xA1, 0xF1, 0x6D, 0x43, 0x5E, 0x45, 0x31,
      0x78, 0x22, 0x39, 0x38, 0x5E, 0x7E, 0x03, 0xED, 0xE4, 0xB0, 0xA6, 0xA3, 0xD8, 0x2A, 0xFC, 0xFF
    },
    { // recon_priv
      0x44, 0xAC, 0x54, 0xEE, 0x38, 0xA3, 0xF2, 0xF5, 0xB1, 0x00, 0xA9, 0x24, 0x48, 0xC5, 0x28, 0x5F,
      0xAE, 0x29, 0xCA, 0x00, 0xA5, 0xA1, 0x44, 0xDB, 0x05, 0x11, 0x37, 0x90, 0x01, 0xA3, 0xAB, 0xDD
    },
    { // my_cert
      0x00, 0x03, 0x01, 0x80, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA, 0x50, 0x83, 0xE3, 0x04,
      0x91, 0x00, 0x03, 0x19, 0xF2, 0x0F, 0xF4, 0x84, 0x00, 0xA9, 0x83, 0x01, 0x01, 0x80, 0x03, 0x48,
      0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0x40, 0x79, 0x97, 0x6D, 0xF8, 0x71, 0xE5, 0xD0, 0x6D,
      0xE6, 0x45, 0x32, 0x36, 0x06, 0x0D, 0xC4, 0x9E, 0x00, 0x9C, 0x59, 0xDC, 0x14, 0xE5, 0x39, 0x08,
      0x41, 0x35, 0xF5, 0xDB, 0x97, 0xE7, 0xC7
    },
    71, // my_cert_size
    { // recon_pub (인증서 내 compressed 형식 recon_pub 를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0x40, 0x79, 0x97, 0x6D, 0xF8, 0x71, 0xE5, 0xD0, 0x6D, 0xE6, 0x45, 0x32, 0x36, 0x06, 0x0D, 0xC4,
      0x9E, 0x00, 0x9C, 0x59, 0xDC, 0x14, 0xE5, 0x39, 0x08, 0x41, 0x35, 0xF5, 0xDB, 0x97, 0xE7, 0xC7,
      0x5B, 0xA8, 0xAC, 0x5F, 0x17, 0xEC, 0xD3, 0xB1, 0xE7, 0xFB, 0xD8, 0xC4, 0xB6, 0xDF, 0x49, 0x69,
      0x67, 0xA8, 0x93, 0x71, 0x73, 0xD9, 0x52, 0x1A, 0x4E, 0xF9, 0xCB, 0x42, 0xAC, 0xC1, 0x23, 0xDA
    },
    { // issuer_cert
      0x80, 0x03, 0x00, 0x80, 0xB7, 0xCB, 0xD0, 0xF7, 0x9B, 0x96, 0x9B, 0xD4, 0x59, 0x81, 0x1A, 0x70,
      0x63, 0x61, 0x2E, 0x70, 0x72, 0x65, 0x70, 0x72, 0x6F, 0x64, 0x2E, 0x76, 0x32, 0x78, 0x2E, 0x69,
      0x73, 0x73, 0x63, 0x6D, 0x73, 0x2E, 0x63, 0x6F, 0x6D, 0xE3, 0x04, 0x91, 0x00, 0x02, 0x19, 0xD8,
      0xD5, 0xDD, 0x86, 0x00, 0x0A, 0x83, 0x01, 0x03, 0x80, 0x00, 0x7C, 0x80, 0x01, 0xE4, 0x80, 0x03,
      0x48, 0x01, 0x01, 0x80, 0x01, 0x23, 0x80, 0x03, 0x85, 0x00, 0x01, 0x01, 0x01, 0x00, 0x81, 0x00,
      0x80, 0x82, 0xB0, 0xFF, 0x2F, 0x29, 0x0F, 0x9E, 0x77, 0xFE, 0x94, 0x07, 0x59, 0xC8, 0x77, 0xB8,
      0xF0, 0x51, 0x6D, 0x41, 0x1E, 0x44, 0xBC, 0x58, 0xF6, 0x12, 0x61, 0x5A, 0x26, 0xD7, 0x26, 0xA0,
      0xD7, 0x9F, 0x80, 0x80, 0x82, 0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3,
      0xB1, 0x2A, 0x38, 0x70, 0x91, 0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7,
      0x72, 0x5B, 0x89, 0xF5, 0x9A, 0x80, 0x80, 0x66, 0xCB, 0x66, 0xCD, 0xF3, 0xDD, 0xFB, 0xD2, 0x85,
      0x52, 0x1E, 0x18, 0x7D, 0xE2, 0x29, 0xEA, 0x91, 0x61, 0xC8, 0xD2, 0x4C, 0x67, 0x6B, 0x7C, 0x83,
      0x7C, 0x9F, 0xBE, 0x12, 0xA9, 0xCD, 0x20, 0xB8, 0xE4, 0x5B, 0x5E, 0x81, 0xD5, 0xA5, 0x57, 0x37,
      0xFA, 0x17, 0x43, 0x9D, 0x2F, 0x1F, 0xD3, 0xD5, 0x9A, 0xBB, 0xF2, 0x49, 0x87, 0xF6, 0x1A, 0xBE,
      0x6F, 0x9F, 0xFB, 0x9F, 0x14, 0xCF, 0xB7
    },
    215, // issuer_cert_size
    { // h_issuer (pca)
      0x7D, 0x31, 0x3C, 0x11, 0x46, 0x96, 0x2D, 0x25, 0xB7, 0xEB, 0xD3, 0x60, 0xFC, 0x98, 0x86, 0x37,
      0x53, 0x4A, 0xC7, 0xF5, 0x8F, 0x95, 0xA4, 0x28, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA
    },
    { // issuer_pub_key (인증서 내 compressed 형식 공개키를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3, 0xB1, 0x2A, 0x38, 0x70, 0x91,
      0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7, 0x72, 0x5B, 0x89, 0xF5, 0x9A,
      0x58, 0xA1, 0x09, 0xD6, 0x17, 0xF7, 0x86, 0xBE, 0xCE, 0xA4, 0x42, 0x17, 0x59, 0x82, 0x9E, 0x9C,
      0x88, 0xA9, 0xE1, 0x01, 0x46, 0xDD, 0x3E, 0x24, 0xAB, 0xCE, 0x9D, 0x98, 0x41, 0x31, 0x34, 0x1A
    },
    { // priv_key
      0xD4, 0x72, 0x91, 0xAC, 0xE0, 0xCA, 0x5D, 0x33, 0x73, 0x17, 0xF3, 0x89, 0x14, 0xCF, 0xE1, 0x1F,
      0xF7, 0x75, 0x3A, 0x1E, 0x3B, 0xF2, 0x09, 0x7A, 0x7B, 0xD4, 0x62, 0xEF, 0x11, 0x06, 0x64, 0x17
    },
    { // pub_key (위 개인키로부터 libdot2 의 검증된 dot2_openssl_GeneratePublicKeyFromPrivateKey()를 이용하여 공개키 생성함)
      kDot2ECPointForm_Uncompressed,
      0x64, 0x75, 0x9C, 0x5A, 0x99, 0x47, 0xD8, 0x2B, 0xCA, 0x98, 0x3C, 0x52, 0xF2, 0x96, 0x11, 0x7C,
      0x35, 0x22, 0x76, 0xE6, 0x2D, 0x88, 0x0D, 0xBD, 0x04, 0x86, 0x40, 0x39, 0xD1, 0xE1, 0x49, 0xCB,
      0x8E, 0x1B, 0x85, 0xB1, 0x42, 0xC7, 0xFD, 0xE1, 0x6B, 0x77, 0xEC, 0x52, 0x38, 0x02, 0x33, 0xA7,
      0xBE, 0x71, 0xC7, 0xC0, 0xF8, 0xA6, 0x7A, 0xD6, 0x8F, 0x43, 0xF8, 0x47, 0x17, 0xDB, 0x32, 0x49
    }
  },

  // Sample test vector #3 - GHS rse-2/6B0DF91D83FA8FE6.cert
  {
    { // cr_priv_key
      0xF1, 0xDF, 0xFB, 0x2F, 0xDD, 0x1E, 0xDD, 0x97, 0x36, 0x53, 0xEC, 0xEB, 0xAC, 0x5E, 0xAE, 0x69,
      0xA5, 0xD6, 0x4A, 0x18, 0xB6, 0xB7, 0x3F, 0x72, 0x79, 0x81, 0xDF, 0x75, 0xA1, 0x7E, 0x83, 0xDB
    },
    { // recon_priv
      0x79, 0xFB, 0x43, 0xD4, 0x64, 0xD0, 0x23, 0xE2, 0xB0, 0x8E, 0xF6, 0x32, 0x40, 0xB3, 0xDB, 0x80,
      0xEF, 0xCD, 0x6C, 0x37, 0xA5, 0xC9, 0x4C, 0x30, 0xA0, 0x7F, 0x9A, 0x5D, 0x22, 0x30, 0xB7, 0xF8
    },
    { // my_cert
      0x00, 0x03, 0x01, 0x80, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA, 0x50, 0x83, 0xE3, 0x04,
      0x91, 0x00, 0x03, 0x19, 0xFB, 0x4A, 0x79, 0x84, 0x00, 0xA9, 0x83, 0x01, 0x01, 0x80, 0x03, 0x48,
      0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0x09, 0x1D, 0xFA, 0x4B, 0x51, 0x58, 0x11, 0xC0, 0xCE,
      0x50, 0x6C, 0x38, 0x2C, 0x96, 0x2C, 0x62, 0x25, 0x8B, 0x47, 0xD3, 0x6C, 0xF0, 0x68, 0xFC, 0x7C,
      0xFF, 0x06, 0x7F, 0x07, 0xC6, 0x73, 0xB7
    },
    71, // my_cert_size
    { // recon_pub (인증서 내 compressed 형식 recon_pub 를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0x09, 0x1D, 0xFA, 0x4B, 0x51, 0x58, 0x11, 0xC0, 0xCE, 0x50, 0x6C, 0x38, 0x2C, 0x96, 0x2C, 0x62,
      0x25, 0x8B, 0x47, 0xD3, 0x6C, 0xF0, 0x68, 0xFC, 0x7C, 0xFF, 0x06, 0x7F, 0x07, 0xC6, 0x73, 0xB7,
      0xF2, 0x9B, 0x27, 0xE6, 0xD7, 0xCE, 0x2D, 0xDC, 0x32, 0x38, 0xE9, 0x16, 0x70, 0x09, 0xE7, 0xE7,
      0xFA, 0x2C, 0x98, 0xBB, 0x57, 0x87, 0xEE, 0x91, 0xE4, 0xAA, 0xA1, 0xB6, 0xBE, 0xCC, 0x21, 0x78
    },
    { // issuer_cert
      0x80, 0x03, 0x00, 0x80, 0xB7, 0xCB, 0xD0, 0xF7, 0x9B, 0x96, 0x9B, 0xD4, 0x59, 0x81, 0x1A, 0x70,
      0x63, 0x61, 0x2E, 0x70, 0x72, 0x65, 0x70, 0x72, 0x6F, 0x64, 0x2E, 0x76, 0x32, 0x78, 0x2E, 0x69,
      0x73, 0x73, 0x63, 0x6D, 0x73, 0x2E, 0x63, 0x6F, 0x6D, 0xE3, 0x04, 0x91, 0x00, 0x02, 0x19, 0xD8,
      0xD5, 0xDD, 0x86, 0x00, 0x0A, 0x83, 0x01, 0x03, 0x80, 0x00, 0x7C, 0x80, 0x01, 0xE4, 0x80, 0x03,
      0x48, 0x01, 0x01, 0x80, 0x01, 0x23, 0x80, 0x03, 0x85, 0x00, 0x01, 0x01, 0x01, 0x00, 0x81, 0x00,
      0x80, 0x82, 0xB0, 0xFF, 0x2F, 0x29, 0x0F, 0x9E, 0x77, 0xFE, 0x94, 0x07, 0x59, 0xC8, 0x77, 0xB8,
      0xF0, 0x51, 0x6D, 0x41, 0x1E, 0x44, 0xBC, 0x58, 0xF6, 0x12, 0x61, 0x5A, 0x26, 0xD7, 0x26, 0xA0,
      0xD7, 0x9F, 0x80, 0x80, 0x82, 0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3,
      0xB1, 0x2A, 0x38, 0x70, 0x91, 0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7,
      0x72, 0x5B, 0x89, 0xF5, 0x9A, 0x80, 0x80, 0x66, 0xCB, 0x66, 0xCD, 0xF3, 0xDD, 0xFB, 0xD2, 0x85,
      0x52, 0x1E, 0x18, 0x7D, 0xE2, 0x29, 0xEA, 0x91, 0x61, 0xC8, 0xD2, 0x4C, 0x67, 0x6B, 0x7C, 0x83,
      0x7C, 0x9F, 0xBE, 0x12, 0xA9, 0xCD, 0x20, 0xB8, 0xE4, 0x5B, 0x5E, 0x81, 0xD5, 0xA5, 0x57, 0x37,
      0xFA, 0x17, 0x43, 0x9D, 0x2F, 0x1F, 0xD3, 0xD5, 0x9A, 0xBB, 0xF2, 0x49, 0x87, 0xF6, 0x1A, 0xBE,
      0x6F, 0x9F, 0xFB, 0x9F, 0x14, 0xCF, 0xB7
    },
    215, // issuer_cert_size
    { // h_issuer (pca)
      0x7D, 0x31, 0x3C, 0x11, 0x46, 0x96, 0x2D, 0x25, 0xB7, 0xEB, 0xD3, 0x60, 0xFC, 0x98, 0x86, 0x37,
      0x53, 0x4A, 0xC7, 0xF5, 0x8F, 0x95, 0xA4, 0x28, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA
    },
    { // issuer_pub_key (인증서 내 compressed 형식 공개키를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3, 0xB1, 0x2A, 0x38, 0x70, 0x91,
      0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7, 0x72, 0x5B, 0x89, 0xF5, 0x9A,
      0x58, 0xA1, 0x09, 0xD6, 0x17, 0xF7, 0x86, 0xBE, 0xCE, 0xA4, 0x42, 0x17, 0x59, 0x82, 0x9E, 0x9C,
      0x88, 0xA9, 0xE1, 0x01, 0x46, 0xDD, 0x3E, 0x24, 0xAB, 0xCE, 0x9D, 0x98, 0x41, 0x31, 0x34, 0x1A
    },
    { // priv_key
      0x32, 0x09, 0xC4, 0x60, 0xA3, 0xC2, 0x16, 0x75, 0x44, 0x32, 0xBA, 0xA8, 0xC0, 0xF7, 0x49, 0x0D,
      0x67, 0xCD, 0xCB, 0xD8, 0xEA, 0x65, 0x1F, 0x7B, 0x4F, 0x5A, 0x37, 0x2E, 0xF2, 0xB3, 0xA4, 0xC0
    },
    { // pub_key (위 개인키로부터 libdot2 의 검증된 dot2_openssl_GeneratePublicKeyFromPrivateKey()를 이용하여 공개키 생성함)
      kDot2ECPointForm_Uncompressed,
      0x4E, 0xB2, 0x26, 0xA4, 0xD8, 0xD9, 0x1F, 0x35, 0x04, 0xB7, 0x18, 0x03, 0x6E, 0xAD, 0xFE, 0xE8,
      0xFC, 0x3B, 0x3E, 0xAA, 0xD3, 0x5B, 0x95, 0x6C, 0x71, 0xC5, 0x0C, 0x36, 0xA1, 0xFF, 0x64, 0x2A,
      0xF0, 0xE4, 0xC9, 0x5F, 0x94, 0x23, 0x89, 0x00, 0x81, 0x4A, 0xE7, 0xC9, 0x5C, 0xEA, 0x54, 0xB5,
      0x05, 0xDA, 0x8D, 0x0E, 0x4B, 0x41, 0xEF, 0x0D, 0x76, 0x0D, 0x93, 0x8B, 0x4E, 0x1A, 0xDB, 0x1A
    }
  },

  // Sample test vector #4 - GHS rse-10/B03761AE4AACF49C.cert
  {
    { // cr_priv_key
      0x2F, 0xDA, 0x40, 0x24, 0xF5, 0x18, 0x83, 0xA7, 0x68, 0x91, 0xC7, 0x33, 0xAC, 0x0A, 0xD1, 0x58,
      0x5E, 0xC0, 0xDD, 0xA9, 0x36, 0x24, 0x0C, 0x8C, 0xE4, 0xCE, 0x96, 0xA8, 0x09, 0xF1, 0x64, 0xFC
    },
    { // recon_priv
      0xC5, 0xCC, 0xDA, 0x58, 0x36, 0x9C, 0x26, 0xBA, 0x18, 0x3D, 0xD2, 0x1E, 0x06, 0x48, 0xFC, 0x92,
      0x78, 0x6E, 0xEE, 0xB7, 0xA9, 0x68, 0xCE, 0x77, 0x3F, 0xF2, 0x67, 0xF0, 0xDE, 0xBA, 0xDF, 0xB6
    },
    { // my_cert
      0x00, 0x03, 0x01, 0x80, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA, 0x50, 0x83, 0xE3, 0x04,
      0x91, 0x00, 0x03, 0x1A, 0x45, 0x1E, 0x9F, 0x84, 0x00, 0xA9, 0x83, 0x01, 0x01, 0x80, 0x03, 0x48,
      0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0x29, 0x40, 0xDF, 0x41, 0xF9, 0x96, 0xAC, 0xC0, 0xF2,
      0xCE, 0xFB, 0x26, 0xFE, 0x58, 0xA9, 0x9B, 0xE7, 0x42, 0x24, 0xE5, 0x57, 0xA5, 0x40, 0xC4, 0x92,
      0x40, 0x7F, 0xCE, 0xB7, 0x38, 0x18, 0x88
    },
    71, // my_cert_size
    { // recon_pub (인증서 내 compressed 형식 recon_pub 를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0x29, 0x40, 0xDF, 0x41, 0xF9, 0x96, 0xAC, 0xC0, 0xF2, 0xCE, 0xFB, 0x26, 0xFE, 0x58, 0xA9, 0x9B,
      0xE7, 0x42, 0x24, 0xE5, 0x57, 0xA5, 0x40, 0xC4, 0x92, 0x40, 0x7F, 0xCE, 0xB7, 0x38, 0x18, 0x88,
      0x61, 0x3A, 0xBD, 0x99, 0x3A, 0x88, 0xD1, 0x0A, 0xAA, 0xE7, 0xD7, 0xAD, 0x95, 0x72, 0xA2, 0x4F,
      0x9C, 0x18, 0x66, 0x4B, 0x9C, 0x25, 0x81, 0x7F, 0x23, 0x74, 0x45, 0x7B, 0x61, 0x64, 0x9C, 0x38
    },
    { // issuer_cert
      0x80, 0x03, 0x00, 0x80, 0xB7, 0xCB, 0xD0, 0xF7, 0x9B, 0x96, 0x9B, 0xD4, 0x59, 0x81, 0x1A, 0x70,
      0x63, 0x61, 0x2E, 0x70, 0x72, 0x65, 0x70, 0x72, 0x6F, 0x64, 0x2E, 0x76, 0x32, 0x78, 0x2E, 0x69,
      0x73, 0x73, 0x63, 0x6D, 0x73, 0x2E, 0x63, 0x6F, 0x6D, 0xE3, 0x04, 0x91, 0x00, 0x02, 0x19, 0xD8,
      0xD5, 0xDD, 0x86, 0x00, 0x0A, 0x83, 0x01, 0x03, 0x80, 0x00, 0x7C, 0x80, 0x01, 0xE4, 0x80, 0x03,
      0x48, 0x01, 0x01, 0x80, 0x01, 0x23, 0x80, 0x03, 0x85, 0x00, 0x01, 0x01, 0x01, 0x00, 0x81, 0x00,
      0x80, 0x82, 0xB0, 0xFF, 0x2F, 0x29, 0x0F, 0x9E, 0x77, 0xFE, 0x94, 0x07, 0x59, 0xC8, 0x77, 0xB8,
      0xF0, 0x51, 0x6D, 0x41, 0x1E, 0x44, 0xBC, 0x58, 0xF6, 0x12, 0x61, 0x5A, 0x26, 0xD7, 0x26, 0xA0,
      0xD7, 0x9F, 0x80, 0x80, 0x82, 0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3,
      0xB1, 0x2A, 0x38, 0x70, 0x91, 0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7,
      0x72, 0x5B, 0x89, 0xF5, 0x9A, 0x80, 0x80, 0x66, 0xCB, 0x66, 0xCD, 0xF3, 0xDD, 0xFB, 0xD2, 0x85,
      0x52, 0x1E, 0x18, 0x7D, 0xE2, 0x29, 0xEA, 0x91, 0x61, 0xC8, 0xD2, 0x4C, 0x67, 0x6B, 0x7C, 0x83,
      0x7C, 0x9F, 0xBE, 0x12, 0xA9, 0xCD, 0x20, 0xB8, 0xE4, 0x5B, 0x5E, 0x81, 0xD5, 0xA5, 0x57, 0x37,
      0xFA, 0x17, 0x43, 0x9D, 0x2F, 0x1F, 0xD3, 0xD5, 0x9A, 0xBB, 0xF2, 0x49, 0x87, 0xF6, 0x1A, 0xBE,
      0x6F, 0x9F, 0xFB, 0x9F, 0x14, 0xCF, 0xB7
    },
    215, // issuer_cert_size
    { // h_issuer (pca)
      0x7D, 0x31, 0x3C, 0x11, 0x46, 0x96, 0x2D, 0x25, 0xB7, 0xEB, 0xD3, 0x60, 0xFC, 0x98, 0x86, 0x37,
      0x53, 0x4A, 0xC7, 0xF5, 0x8F, 0x95, 0xA4, 0x28, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA
    },
    { // issuer_pub_key (인증서 내 compressed 형식 공개키를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3, 0xB1, 0x2A, 0x38, 0x70, 0x91,
      0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7, 0x72, 0x5B, 0x89, 0xF5, 0x9A,
      0x58, 0xA1, 0x09, 0xD6, 0x17, 0xF7, 0x86, 0xBE, 0xCE, 0xA4, 0x42, 0x17, 0x59, 0x82, 0x9E, 0x9C,
      0x88, 0xA9, 0xE1, 0x01, 0x46, 0xDD, 0x3E, 0x24, 0xAB, 0xCE, 0x9D, 0x98, 0x41, 0x31, 0x34, 0x1A
    },
    { // priv_key
      0xCE, 0xF3, 0x64, 0x68, 0x7F, 0x76, 0xE4, 0x69, 0x62, 0xAF, 0x19, 0xC9, 0x97, 0x25, 0x29, 0xF4,
      0xFD, 0x22, 0xD5, 0xF3, 0x0D, 0xB8, 0xA2, 0x73, 0xD5, 0x38, 0x74, 0xB7, 0xA2, 0x75, 0x5E, 0x8F
    },
    { // pub_key (위 개인키로부터 libdot2 의 검증된 dot2_openssl_GeneratePublicKeyFromPrivateKey()를 이용하여 공개키 생성함)
      kDot2ECPointForm_Uncompressed,
      0x67, 0xF3, 0x5D, 0x6E, 0xE0, 0xA2, 0xDC, 0x6C, 0x53, 0x0F, 0x16, 0x88, 0xC7, 0x5D, 0x18, 0xD5,
      0xA2, 0xB1, 0xA2, 0xE5, 0x26, 0x40, 0xEB, 0x61, 0x7A, 0x93, 0xCA, 0x71, 0x62, 0x4B, 0x1F, 0x74,
      0x85, 0x39, 0xBA, 0x29, 0x55, 0x97, 0x1F, 0xFC, 0xEF, 0x97, 0xD3, 0xF7, 0xC9, 0xF8, 0x43, 0xE7,
      0xA7, 0xC0, 0xDA, 0x29, 0x5E, 0x19, 0x52, 0x12, 0xE2, 0xBF, 0x3C, 0x6D, 0x24, 0xBD, 0x62, 0xB6
    }
  },

  // Sample test vector #5 - GHS rse-19/283D451144EA7F0B.cert
  {
    { // cr_priv_key
      0xB6, 0xB9, 0xBF, 0xAD, 0x4F, 0x08, 0x3F, 0xD4, 0xD7, 0xFA, 0xA8, 0xE2, 0x2D, 0xD7, 0xB8, 0x50,
      0x59, 0x77, 0x68, 0xBC, 0xB3, 0xEB, 0x00, 0x4F, 0x36, 0x9D, 0xF1, 0x0A, 0x99, 0x60, 0x1C, 0xB6
    },
    { // recon_priv
      0xBC, 0x6C, 0x43, 0xB2, 0x8E, 0x1B, 0xD9, 0x72, 0xC4, 0x62, 0xF9, 0xD6, 0xC3, 0x6D, 0x16, 0xF5,
      0xFC, 0x87, 0x95, 0xF7, 0x15, 0x53, 0x8C, 0x9C, 0xBD, 0x56, 0x4F, 0xA9, 0x7C, 0x97, 0x7D, 0x8A
    },
    { // my_cert
      0x00, 0x03, 0x01, 0x80, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA, 0x50, 0x83, 0xE3, 0x04,
      0x91, 0x00, 0x03, 0x1A, 0x98, 0x2D, 0x49, 0x84, 0x00, 0xA9, 0x83, 0x01, 0x01, 0x80, 0x03, 0x48,
      0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x83, 0x49, 0x74, 0xB2, 0xA2, 0x65, 0xAD, 0x4B, 0x69, 0x7F,
      0xAB, 0x2C, 0x55, 0x43, 0x2C, 0x9A, 0x8A, 0xEA, 0x39, 0x8F, 0xF1, 0x19, 0x18, 0xC3, 0xB1, 0x9B,
      0xCF, 0x1F, 0xBF, 0x28, 0x54, 0x35, 0x9E
    },
    71, // my_cert_size
    { // recon_pub (인증서 내 compressed 형식 recon_pub 를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0x49, 0x74, 0xB2, 0xA2, 0x65, 0xAD, 0x4B, 0x69, 0x7F, 0xAB, 0x2C, 0x55, 0x43, 0x2C, 0x9A, 0x8A,
      0xEA, 0x39, 0x8F, 0xF1, 0x19, 0x18, 0xC3, 0xB1, 0x9B, 0xCF, 0x1F, 0xBF, 0x28, 0x54, 0x35, 0x9E,
      0x86, 0xF0, 0xDC, 0x4C, 0xA8, 0x04, 0x49, 0xB8, 0x45, 0xEC, 0xA2, 0xB8, 0x20, 0x9C, 0xFD, 0xE7,
      0x98, 0x4D, 0x77, 0x7D, 0xCE, 0x84, 0x77, 0x8F, 0xBB, 0xFA, 0x96, 0xD8, 0x4F, 0x1A, 0xAE, 0x23,
    },
    { // issuer_cert
      0x80, 0x03, 0x00, 0x80, 0xB7, 0xCB, 0xD0, 0xF7, 0x9B, 0x96, 0x9B, 0xD4, 0x59, 0x81, 0x1A, 0x70,
      0x63, 0x61, 0x2E, 0x70, 0x72, 0x65, 0x70, 0x72, 0x6F, 0x64, 0x2E, 0x76, 0x32, 0x78, 0x2E, 0x69,
      0x73, 0x73, 0x63, 0x6D, 0x73, 0x2E, 0x63, 0x6F, 0x6D, 0xE3, 0x04, 0x91, 0x00, 0x02, 0x19, 0xD8,
      0xD5, 0xDD, 0x86, 0x00, 0x0A, 0x83, 0x01, 0x03, 0x80, 0x00, 0x7C, 0x80, 0x01, 0xE4, 0x80, 0x03,
      0x48, 0x01, 0x01, 0x80, 0x01, 0x23, 0x80, 0x03, 0x85, 0x00, 0x01, 0x01, 0x01, 0x00, 0x81, 0x00,
      0x80, 0x82, 0xB0, 0xFF, 0x2F, 0x29, 0x0F, 0x9E, 0x77, 0xFE, 0x94, 0x07, 0x59, 0xC8, 0x77, 0xB8,
      0xF0, 0x51, 0x6D, 0x41, 0x1E, 0x44, 0xBC, 0x58, 0xF6, 0x12, 0x61, 0x5A, 0x26, 0xD7, 0x26, 0xA0,
      0xD7, 0x9F, 0x80, 0x80, 0x82, 0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3,
      0xB1, 0x2A, 0x38, 0x70, 0x91, 0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7,
      0x72, 0x5B, 0x89, 0xF5, 0x9A, 0x80, 0x80, 0x66, 0xCB, 0x66, 0xCD, 0xF3, 0xDD, 0xFB, 0xD2, 0x85,
      0x52, 0x1E, 0x18, 0x7D, 0xE2, 0x29, 0xEA, 0x91, 0x61, 0xC8, 0xD2, 0x4C, 0x67, 0x6B, 0x7C, 0x83,
      0x7C, 0x9F, 0xBE, 0x12, 0xA9, 0xCD, 0x20, 0xB8, 0xE4, 0x5B, 0x5E, 0x81, 0xD5, 0xA5, 0x57, 0x37,
      0xFA, 0x17, 0x43, 0x9D, 0x2F, 0x1F, 0xD3, 0xD5, 0x9A, 0xBB, 0xF2, 0x49, 0x87, 0xF6, 0x1A, 0xBE,
      0x6F, 0x9F, 0xFB, 0x9F, 0x14, 0xCF, 0xB7
    },
    215, // issuer_cert_size
    { // h_issuer (pca)
      0x7D, 0x31, 0x3C, 0x11, 0x46, 0x96, 0x2D, 0x25, 0xB7, 0xEB, 0xD3, 0x60, 0xFC, 0x98, 0x86, 0x37,
      0x53, 0x4A, 0xC7, 0xF5, 0x8F, 0x95, 0xA4, 0x28, 0x24, 0x80, 0xE4, 0x4B, 0xAB, 0x15, 0x6F, 0xDA
    },
    { // issuer_pub_key (인증서 내 compressed 형식 공개키를 libdot2 의 검증된 dot2_RecoverY()를 이용하여 Y 복원함)
      kDot2ECPointForm_Uncompressed,
      0xFF, 0x9B, 0x00, 0xCE, 0x42, 0xB2, 0x1A, 0xFF, 0xF2, 0xC1, 0xD3, 0xB1, 0x2A, 0x38, 0x70, 0x91,
      0xE4, 0xD2, 0xC8, 0x4B, 0x3A, 0xE2, 0x53, 0xB1, 0x12, 0x25, 0xF7, 0x72, 0x5B, 0x89, 0xF5, 0x9A,
      0x58, 0xA1, 0x09, 0xD6, 0x17, 0xF7, 0x86, 0xBE, 0xCE, 0xA4, 0x42, 0x17, 0x59, 0x82, 0x9E, 0x9C,
      0x88, 0xA9, 0xE1, 0x01, 0x46, 0xDD, 0x3E, 0x24, 0xAB, 0xCE, 0x9D, 0x98, 0x41, 0x31, 0x34, 0x1A
    },
    { // priv_key
      0x5F, 0xA9, 0x2F, 0x3D, 0x11, 0xFD, 0x9B, 0x04, 0x93, 0x10, 0x21, 0x4D, 0x75, 0xEA, 0xB8, 0x8A,
      0x3A, 0x60, 0x37, 0xCB, 0x35, 0x74, 0x3E, 0x47, 0x7E, 0x5A, 0xC9, 0x4A, 0x40, 0xE2, 0xFA, 0x4F
    },
    { // pub_key (위 개인키로부터 libdot2 의 검증된 dot2_openssl_GeneratePublicKeyFromPrivateKey()를 이용하여 공개키 생성함)
      kDot2ECPointForm_Uncompressed,
      0xFF, 0x28, 0x38, 0x94, 0x1D, 0x22, 0x1C, 0x11, 0xC6, 0x70, 0xEF, 0xA0, 0x93, 0x6C, 0x00, 0xE9,
      0x88, 0x4D, 0xAF, 0xD2, 0x12, 0xE1, 0x3B, 0xEE, 0xC2, 0xD8, 0x9E, 0x90, 0xA2, 0x0E, 0x4D, 0x99,
      0x7D, 0x66, 0x88, 0x77, 0x2F, 0xDA, 0xFD, 0x05, 0x79, 0x48, 0x40, 0x45, 0xDC, 0x96, 0xFE, 0xB0,
      0xFA, 0x21, 0x0B, 0x10, 0x74, 0x10, 0x46, 0x66, 0x82, 0xAB, 0x0B, 0xC2, 0xB8, 0x62, 0x0E, 0xBB,
    }
  }
};


/**
 * @brief Implicit 인증서 관련 개인키 재구성 기능의 정상 동작을 확인한다.
 */
TEST(dot2_ReconstructImplicitCertPrivateKey, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom"), kDot2Result_Success);

  int ret;
  struct Dot2ECKeyPair key;

  for (int i = 0; i < SAMPLE_TEST_VECTOR_NUM; i++)
  {
    /*
     * 개인키 재구성을 수행한다.
     */
    memset(&key, 0, sizeof(key));
    ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                                 g_sample_tv[i].cr_priv_key,
                                                 g_sample_tv[i].recon_priv,
                                                 g_sample_tv[i].my_cert,
                                                 g_sample_tv[i].my_cert_size,
                                                 g_sample_tv[i].h_issuer,
                                                 &key);
    ASSERT_EQ(ret, kDot2Result_Success);
    dot2_ClearECKeyPair(&key);

    /*
     * 재구성된 개인키가 정확한지 확인한다.
     */
    ASSERT_TRUE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[i].priv_key, DOT2_EC_256_KEY_LEN));
  }

  Dot2_Release();
}


/**
 * @brief Implicit 인증서 관련 개인키 재구성 기능의 파라미터 오류에 대한 동작을 확인한다.
 */
TEST(dot2_ReconstructImplicitCertPrivateKey, CHECK_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom"), kDot2Result_Success);

  int ret;
  struct Dot2ECKeyPair key;

  /*
   * 정상 동작을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  /*
   * 잘못된 ECC 커브 유형 전달 시 실패하는 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_Max + 1,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_InvalidECType);
  dot2_ClearECKeyPair(&key);

  /*
   * 지원되지 않는 ECC 커브 유형 전달 시 실패하는 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_Brainpoolp256r1,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_NotSupportedECType);
  dot2_ClearECKeyPair(&key);

  /*
   * Null 파라미터 전달 시 실패하는 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               nullptr,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  dot2_ClearECKeyPair(&key);

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               nullptr,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  dot2_ClearECKeyPair(&key);

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               nullptr,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  dot2_ClearECKeyPair(&key);

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               nullptr,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  dot2_ClearECKeyPair(&key);

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               nullptr);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  dot2_ClearECKeyPair(&key);

  /*
   * 잘못된 인증서 요청 개인키 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[1].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  /*
   * 잘못된 개인키 재구성값 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[1].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));


  /*
   * 잘못된 인증서 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[1].my_cert,
                                               g_sample_tv[1].my_cert_size,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  /*
   * 유효하지 않은 인증서 길이 전달 시 실패하는 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               kDot2CertSize_Min - 1,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_InvalidCertSize);
  dot2_ClearECKeyPair(&key);

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               kDot2CertSize_Max + 1,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, -kDot2Result_InvalidCertSize);
  dot2_ClearECKeyPair(&key);

  /*
   * 잘못된 인증서 길이 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               kDot2CertSize_Min,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size - 1,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size + 1,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               kDot2CertSize_Max,
                                               g_sample_tv[0].h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));

  /*
   * 유효하지 않은 상위인증서 해시 전달 시 결과가 부정확한 것을 확인한다.
   */
  uint8_t invalid_h_issuer[DOT2_SHA_256_LEN];
  memcpy(invalid_h_issuer, g_sample_tv[0].h_issuer, DOT2_SHA_256_LEN);
  invalid_h_issuer[0] += 1;
  memset(&key, 0, sizeof(key));
  ret = dot2_ReconstructImplicitCertPrivateKey(kDot2ECType_NISTp256,
                                               g_sample_tv[0].cr_priv_key,
                                               g_sample_tv[0].recon_priv,
                                               g_sample_tv[0].my_cert,
                                               g_sample_tv[0].my_cert_size,
                                               invalid_h_issuer,
                                               &key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&key);
  ASSERT_FALSE(Dot2Test_CompareOctets(key.priv_key.octets, g_sample_tv[0].priv_key, DOT2_EC_256_KEY_LEN));


  Dot2_Release();
}



/**
 * @brief Implicit 인증서 관련 공개키 재구성 API의 정상 동작을 확인한다.
 */
TEST(dot2_ReconstructImplicitCertPublicKey, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom"), kDot2Result_Success);

  int ret;
  struct Dot2ECKeyPair recon_pub;
  struct Dot2ECKeyPair issuer_key;
  struct Dot2ECKeyPair reconstructed_key;

  for (int i = 0; i < SAMPLE_TEST_VECTOR_NUM; i++)
  {
    memset(&recon_pub, 0, sizeof(recon_pub));
    memset(&issuer_key, 0, sizeof(issuer_key));
    memset(&reconstructed_key, 0, sizeof(reconstructed_key));
    memcpy(recon_pub.pub_key.u.octets, g_sample_tv[i].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
    memcpy(issuer_key.pub_key.u.octets, g_sample_tv[i].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
    ret = dot2_ReconstructImplicitCertPublicKey(true,
                                                kDot2ECType_NISTp256,
                                                g_sample_tv[i].my_cert,
                                                g_sample_tv[i].my_cert_size,
                                                g_sample_tv[i].h_issuer,
                                                &recon_pub,
                                                &issuer_key,
                                                &reconstructed_key);
    ASSERT_EQ(ret, kDot2Result_Success);
    dot2_ClearECKeyPair(&issuer_key);
    dot2_ClearECKeyPair(&reconstructed_key);
    ASSERT_TRUE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[i].pub_key, DOT2_EC_256_PUB_KEY_LEN));
  }

  Dot2_Release();
}


/**
 * @brief Implicit 인증서 관련 공개키 재구성 API의 파라미터 오류에 대한 동작을 확인한다.
 */
TEST(dot2_ReconstructImplicitCertPublicKey, CHECK_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom"), kDot2Result_Success);

  int ret;
  struct Dot2ECKeyPair recon_pub;
  struct Dot2ECKeyPair issuer_key;
  struct Dot2ECKeyPair reconstructed_key;

  /*
   * 정상 동작을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_TRUE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  /*
   * 잘못된 ECC 커브 유형 전달 시 실패하는 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_Max + 1,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_InvalidECType);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);

  /*
   * 지원되지 않는 ECC 커브 유형 전달 시 실패하는 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_Brainpoolp256r1,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_NotSupportedECType);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);

  /*
   * Null 파라미터 전달 시 실패하는 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              nullptr,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              nullptr,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              nullptr,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              nullptr,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              nullptr);
  ASSERT_EQ(ret, -kDot2Result_NullParameters);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);

  /*
   * 잘못된 공개키 재구성값 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[1].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  /*
   * 잘못된 인증서 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[1].my_cert,
                                              g_sample_tv[1].my_cert_size,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  /*
   * 유효하지 않은 인증서 길이 전달 시 실패하는 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              kDot2CertSize_Min - 1,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_InvalidCertSize);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);

  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              kDot2CertSize_Max + 1,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, -kDot2Result_InvalidCertSize);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);

  /*
   * 잘못된 인증서 길이 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              kDot2CertSize_Min,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size - 1,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size + 1,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              kDot2CertSize_Max,
                                              g_sample_tv[0].h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  /*
   * 잘못된 상위인증서 해시값 전달 시 결과가 부정확한 것을 확인한다.
   */
  memset(&recon_pub, 0, sizeof(recon_pub));
  memset(&issuer_key, 0, sizeof(issuer_key));
  memset(&reconstructed_key, 0, sizeof(reconstructed_key));
  memcpy(recon_pub.pub_key.u.octets, g_sample_tv[0].recon_pub, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(issuer_key.pub_key.u.octets, g_sample_tv[0].issuer_pub_key, DOT2_EC_256_PUB_KEY_LEN);
  uint8_t invalid_h_issuer[DOT2_SHA_256_LEN];
  memcpy(invalid_h_issuer, g_sample_tv[0].h_issuer, DOT2_SHA_256_LEN);
  invalid_h_issuer[0] += 1;
  ret = dot2_ReconstructImplicitCertPublicKey(true,
                                              kDot2ECType_NISTp256,
                                              g_sample_tv[0].my_cert,
                                              g_sample_tv[0].my_cert_size,
                                              invalid_h_issuer,
                                              &recon_pub,
                                              &issuer_key,
                                              &reconstructed_key);
  ASSERT_EQ(ret, kDot2Result_Success);
  dot2_ClearECKeyPair(&issuer_key);
  dot2_ClearECKeyPair(&reconstructed_key);
  ASSERT_FALSE(Dot2Test_CompareOctets(reconstructed_key.pub_key.u.octets, g_sample_tv[0].pub_key, DOT2_EC_256_PUB_KEY_LEN));

  Dot2_Release();
}
#endif
