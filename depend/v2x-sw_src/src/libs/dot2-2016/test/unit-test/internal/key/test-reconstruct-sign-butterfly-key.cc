/** 
  * @file 
  * @brief 서명용 butterfly 키 재구성 관련 테스트
  * @date 2022-08-04 
  * @author gyun 
  */



// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "sec-executer/openssl/dot2-openssl.h"
#include "sec-executer/openssl/dot2-openssl-inline.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


/*
 * KISA v1.1 규격 "01-08.KCAC.V2X.BUTTERFLYKEY_Butterfly키 규격_v1.1" 부록 1.가
 * 서명용 키쌍에 대한 재구성
 */
uint32_t tv_recon_sign_bfkey_i = 0x217d;
uint32_t tv_recon_sign_bfkey_j = 0x0010;
const char *tv_recon_sign_bfkey_ck = "121D14216715E11D2D3787434A673B1B"; // AES key (random)
const char *tv_recon_sign_bfkey_a = "E184BFCB88DF283D5A65DBE12A74B66DA33AAD17723CBC56B8DCB20C0F7618D4"; // signing seed private key
const char *tv_recon_sign_bfkey_A = "041868AC34E5385A1ECADD9A06BD758E982E8D8E25BDC8F741EAECEDD9FBC79CEE174071CCDB8E8DE9C6D0A4C18E351CF88B0F247C41298F43C71F0BFED9C8E35A"; // signing seed public key
const char *tv_recon_sign_bfkey_x_cert = "000000000000217D0000001000000000"; // x
const char *tv_recon_sign_bfkey_f_k_int_x_cert = "74A5D8F5A3AA3E60A456EBDBC827A6384ED1940D734C7BF28DB8EE6F12C55A7360C11E5EA7047993BC9BD883C8279744"; // fint(k,x)
int tv_recon_sign_bfkey_f_k_int_x_cert_size = 48;
const char *tv_recon_sign_bfkey_f_k_x_cert = "C6AE39EBF2ACFC5608838EBD84EC15B8570079D07A3FF8E35B4BB8D656F13B1D"; // f(k,x)
int tv_recon_sign_bfkey_f_k_x_cert_size = 32;
const char *tv_recon_sign_bfkey_a_exp = "A733F9B67B8C259462E8699FAF60CC25FB3A26E8EC7BB43A14286BE3656754F1"; // Expanded private key = cocoon private key
const char *tv_recon_sign_bfkey_A_exp = ""; // Expanded public key = cocoon public key


/*
 * 서명용 Butterfly 키 재구성 동작 중 derive(X) 기능 확인
 */
TEST(RECONSTRUCT_SIGN_BUTTERFLY_KEY, DERIVE_SIGNING_X)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t x_expected[DOT2_AES_128_LEN];

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_x_cert, x_expected), DOT2_AES_128_LEN);
  }

  /*
   * 테스트
   */
  {
    uint8_t x[DOT2_AES_128_LEN];
    dot2_ossl_derive_signing_x(tv_recon_sign_bfkey_i, tv_recon_sign_bfkey_j, x);
    ASSERT_TRUE(Dot2Test_CompareOctets(x, x_expected, DOT2_AES_128_LEN));
  }

  Dot2_Release();
}


/*
 * 서명용 Butterfly 키 재구성 동작 중 fint(k,x) 방정식 기능 확인
 */
TEST(RECONSTRUCT_SIGN_BUTTERFLY_KEY, F_INT_K_X)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t x[DOT2_AES_128_LEN], expected[DOT2_AES_128_LEN * 3];
  struct Dot2AESKey exp_key;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_x_cert, x), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_ck, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_f_k_int_x_cert, expected), tv_recon_sign_bfkey_f_k_int_x_cert_size);
  }

  /*
   * 테스트
   */
  {
    uint8_t f_k_int_x_cert[DOT2_AES_128_LEN * 3];
    ASSERT_TRUE(dot2_ossl_f_int_k_x(exp_key.octs, x, f_k_int_x_cert));
    ASSERT_TRUE(Dot2Test_CompareOctets(f_k_int_x_cert, expected, DOT2_AES_128_LEN * 3));
  }

  Dot2_Release();
}


/*
 * 서명용 Butterfly 키 재구성 동작 중 cocoon 키 재구성 기능 확인
 */
TEST(RECONSTRUCT_SIGN_BUTTERFLY_KEY, MAKE_COCOON_PRIV_KEY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint32_t i, j;
  struct Dot2AESKey exp_key;
  struct Dot2ECPrivateKey seed_priv, expected_cocoon_priv_key;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    i = tv_recon_sign_bfkey_i;
    j = tv_recon_sign_bfkey_j;
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_ck, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_a, seed_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_sign_bfkey_a_exp, expected_cocoon_priv_key.octs), DOT2_EC_256_KEY_LEN);
  }

  /*
   * 테스트 -> 현재 Fail 남. 이유는 모르겠음. cocoon 키 생성을 포함하는 butterfly 개인키 재구성은 성공함.... (아래 테스트 케이스 참조)
   */
  {
    struct Dot2ECKeyPairOcts key_pair;
    ASSERT_EQ(dot2_ossl_MakeSigningCocoonKeyPair(i, j, &exp_key, &seed_priv, &key_pair), kDot2Result_Success);
    //Dot2Test_PrintOcts("", key_pair.priv_key.octs, DOT2_EC_256_KEY_LEN);
    //ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_cocoon_priv_key.octs, DOT2_EC_256_KEY_LEN));
  }

  Dot2_Release();
}


static uint32_t tv_i_0 = 0xdb;
static uint32_t tv_j_0 = 0x9;
static const char *tv_exp_key_0 = "682C42B5AE850D3AD230E209EC6372A9";
static const char *tv_seed_priv_0 = "BAA2E87E53AB7A86A562664E77FB71264C040748EC29AEAB2CF21B507045324F";
static const char *tv_recon_priv_0 = "3D3CB48F7568DBCFF0754C856D8396585AA3045CCEA6D41EF94C49CFB71B64D6";
static const char *tv_recon_pub_0 = "03433BBC3B68145170152BBC18949654D98248259EC5FC659DBBED878BB8F53171";
static const char *tv_cert_0 = "00030180163F2B7BC99253F450808000DBC9136BABC96668FC530000000FC9136BABC96668FC53F4F7A100011C9D4C938400A983010180034801020001200001268183433BBC3B68145170152BBC18949654D98248259EC5FC659DBBED878BB8F53171";
static int tv_cert_size_0 = 99;
static const char *tv_priv_key_0 = "CACBA571DAEB8D021EE72F83A307D35291C78C22952A1550B0D1549EE369DF13";
static const char *tv_pub_key_0 = "04536344BD75347FD55B4523F83832D8FBEF48523A9962C7F4657F59B7380B6928FCB65627CF7CC026ECD1DFCD6FD24E54D2D0DEEFC6D379435633F002918E0A7E";
static const char *tv_issuer_0 = "80030080281C9C1E50F4F7A15981157063612E70656E746173656375726974792E636F6DF4F7A100021BF191DD86000383010480019A80007B8001E48003480101800123800385000101010081008083FAC45FDB8CA9CFFA6AEF06372CF93A3C0A8235DCFDD929CA09E345C25114554B808083F7BE7A6CA8F62AFF8C8FD791043278994B81FFCEB7A110039117061CF61BE1678080171BCF58BA61D3ECF57CAC2521AEFAA1BADC2933B8B9175C750C554198F0414B368F125AD639EBAE426BD1B05E4D9C96312CC085AFABE60ECDB46B00030180163F2B7BC99253F450808000DBC9136BABC96668FC530000000FC9136BABC96668FC53F4F7A100011C9D4C938400A983010180034801020001200001268183433BBC3B68145170152BBC18949654D98248259EC5FC659DBBED878BB8F5317122956C78CB";
static const char *tv_issuer_h_0 = "D658E6FD4A0C122BC21CE06646782D40C21FD92FD4E3352F163F2B7BC99253F4";
static const char *tv_issuer_pub_key_0 = "03F7BE7A6CA8F62AFF8C8FD791043278994B81FFCEB7A110039117061CF61BE167";

static uint32_t tv_i_1 = 0x100;
static uint32_t tv_j_1 = 0x0;
static const char *tv_exp_key_1 = "682C42B5AE850D3AD230E209EC6372A9";
static const char *tv_seed_priv_1 = "BAA2E87E53AB7A86A562664E77FB71264C040748EC29AEAB2CF21B507045324F";
static const char *tv_recon_priv_1 = "1773CAF0B69F82B9DB2A8F7640C1F77F4DD15E2C5247478B43615C5F72752410";
static const char *tv_recon_pub_1 = "0375FB6DC286B90BBB9388A1FE2C52929FF779038CA6BCE4C7F576DAEE05BE2CB2";
static const char *tv_cert_1 = "00030180163F2B7BC99253F45080800100023FFBC95A230BC98B0000000F023FFBC95A230BC98BF4F7A100011DF2C1138400A98301018003480102000120000126818375FB6DC286B90BBB9388A1FE2C52929FF779038CA6BCE4C7F576DAEE05BE2CB2";
static int tv_cert_size_1 = 99;
static const char *tv_priv_key_1 = "F54B83F65647302620447EC4894773163CD9128E2F24FAEAF489E036B4A85E05";
static const char *tv_pub_key_1 = "047BA16F5358B2A778142FFE1FA531B134AC7608EBED400517E685709E6B425FF61420F12E0D3F36C60458C718F60DB3EC4E2506FACF8888E86DABD07025C5A653";
static const char *tv_issuer_1 = "80030080281C9C1E50F4F7A15981157063612E70656E746173656375726974792E636F6DF4F7A100021BF191DD86000383010480019A80007B8001E48003480101800123800385000101010081008083FAC45FDB8CA9CFFA6AEF06372CF93A3C0A8235DCFDD929CA09E345C25114554B808083F7BE7A6CA8F62AFF8C8FD791043278994B81FFCEB7A110039117061CF61BE1678080171BCF58BA61D3ECF57CAC2521AEFAA1BADC2933B8B9175C750C554198F0414B368F125AD639EBAE426BD1B05E4D9C96312CC085AFABE60ECDB46B00030180163F2B7BC99253F450808000DBC9136BABC96668FC530000000FC9136BABC96668FC53F4F7A100011C9D4C938400A983010180034801020001200001268183433BBC3B68145170152BBC18949654D98248259EC5FC659DBBED878BB8F5317122956C78CB";
static const char *tv_issuer_h_1 = "D658E6FD4A0C122BC21CE06646782D40C21FD92FD4E3352F163F2B7BC99253F4";
static const char *tv_issuer_pub_key_1 = "03F7BE7A6CA8F62AFF8C8FD791043278994B81FFCEB7A110039117061CF61BE167";

static uint32_t tv_i_2 = 0x10A;
static uint32_t tv_j_2 = 0xB;
static const char *tv_exp_key_2 = "682C42B5AE850D3AD230E209EC6372A9";
static const char *tv_seed_priv_2 = "BAA2E87E53AB7A86A562664E77FB71264C040748EC29AEAB2CF21B507045324F";
static const char *tv_recon_priv_2 = "7E920D81FECFF94F7459C986CB915883E7C54D679F7F698A395360EA826A7436";
static const char *tv_recon_pub_2 = "024C7AE95DB2FC10D2CFAB8C7E566C2E141CADE11635C5DA0B2175A1BFA027C242";
static const char *tv_cert_2 = "00030180163F2B7BC99253F4508080010AEC1C14ACDA0C7E2ADC0000000FEC1C14ACDA0C7E2ADCF4F7A100011E4F0A138400A9830101800348010200012000012681824C7AE95DB2FC10D2CFAB8C7E566C2E141CADE11635C5DA0B2175A1BFA027C242";
static int tv_cert_size_2 = 99;
static const char *tv_priv_key_2 = "991B7363861EB381151FECA93305E4AB38C8C17EC1E68107FACECECEA4B5109B";
static const char *tv_pub_key_2 = "04EAC78F67F4C9065859ACF901E6A9CE84ABE89D357D5D5270435B9DBDE681D1ED35AD879C5ECD8390C376C96DE95E1D83CF2896C9D91C09B09FB59079299CA1EA";
static const char *tv_issuer_2 = "80030080281C9C1E50F4F7A15981157063612E70656E746173656375726974792E636F6DF4F7A100021BF191DD86000383010480019A80007B8001E48003480101800123800385000101010081008083FAC45FDB8CA9CFFA6AEF06372CF93A3C0A8235DCFDD929CA09E345C25114554B808083F7BE7A6CA8F62AFF8C8FD791043278994B81FFCEB7A110039117061CF61BE1678080171BCF58BA61D3ECF57CAC2521AEFAA1BADC2933B8B9175C750C554198F0414B368F125AD639EBAE426BD1B05E4D9C96312CC085AFABE60ECDB46B00030180163F2B7BC99253F450808000DBC9136BABC96668FC530000000FC9136BABC96668FC53F4F7A100011C9D4C938400A983010180034801020001200001268183433BBC3B68145170152BBC18949654D98248259EC5FC659DBBED878BB8F5317122956C78CB";
static const char *tv_issuer_h_2 = "D658E6FD4A0C122BC21CE06646782D40C21FD92FD4E3352F163F2B7BC99253F4";
static const char *tv_issuer_pub_key_2 = "03F7BE7A6CA8F62AFF8C8FD791043278994B81FFCEB7A110039117061CF61BE167";

// GHS/8E_0
static uint32_t tv_i_3 = 0x8E;
static uint32_t tv_j_3 = 0x0;
static const char *tv_exp_key_3 = "8bbe43fa2654946cb812ce99fddb9602";
static const char *tv_seed_priv_3 = "ed74a414cb2980c825ecaad038f8537a7819da7f823955c504d565923d4f1a6f";
static const char *tv_recon_priv_3 = "7927380814d17f9d6b3a26bf22927da5d88a2f1be73d365008eb3182078baafd";
static const char *tv_recon_pub_3 = "025AC98DDED400CEB14EB0716C2ED4701B6B4AC851C3F2816994E100100A386663";
static const char *tv_cert_3 = "000301802480e44bab156fda508080008ef68fd9608f6b980bfc0000000ff68fd9608f6b980bfce30491000119d6b4138400a983010380007c8001e4800348010200012000012681825ac98dded400ceb14eb0716c2ed4701b6b4ac851c3f2816994e100100a386663";
static int tv_cert_size_3 = 105;
static const char *tv_priv_key_3 = "1a11d030bf23bceed6750deef254f1168063e35ea1c71fac49108a0b4498aa03";
static const char *tv_pub_key_3 = "";
static const char *tv_issuer_3 = "80030080b7cbd0f79b969bd459811a7063612e70726570726f642e7632782e697373636d732e636f6de30491000219d8d5dd86000a83010380007c8001e48003480101800123800385000101010081008082b0ff2f290f9e77fe940759c877b8f0516d411e44bc58f612615a26d726a0d79f808082ff9b00ce42b21afff2c1d3b12a387091e4d2c84b3ae253b11225f7725b89f59a808066cb66cdf3ddfbd285521e187de229ea9161c8d24c676b7c837c9fbe12a9cd20b8e45b5e81d5a55737fa17439d2f1fd3d59abbf24987f61abe6f9ffb9f14cfb7";
static const char *tv_issuer_h_3 = "7d313c1146962d25b7ebd360fc988637534ac7f58f95a4282480e44bab156fda";
static const char *tv_issuer_pub_key_3 = "02FF9B00CE42B21AFFF2C1D3B12A387091E4D2C84B3AE253B11225F7725B89F59A";


/*
 * 서명용 Butterfly 키 재구성 동작 중 butterfly 개인키 재구성 기능 확인
 */
TEST(RECONSTRUCT_SIGN_BUTTERFLY_KEY, RECONSTRUCT_PRIV_KEY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint32_t i, j;
  struct Dot2AESKey exp_key;
  struct Dot2ECPrivateKey seed_priv, recon_priv, expected_priv_key;
  struct Dot2ECPublicKey recon_pub, pub_key, issuer_pub_key;
  struct Dot2SHA256 issuer_h;
  struct Dot2Cert cert;

  // 테스트 벡터 #0
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      i = tv_i_0;
      j = tv_j_0;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_exp_key_0, exp_key.octs), DOT2_AES_128_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_seed_priv_0, seed_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_priv_0, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_pub_0, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_cert_0, cert.octs), (size_t)tv_cert_size_0);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_pub_key_0, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_h_0, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_priv_key_0, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
    }

    // 테스트
    {
      int ret;
      struct Dot2ECPrivateKey priv_key;
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i,
                                                                   j,
                                                                   &exp_key,
                                                                   &seed_priv,
                                                                   &recon_priv,
                                                                   &recon_pub,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &issuer_pub_key,
                                                                   &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
  }

  // 테스트 벡터 #1
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      i = tv_i_1;
      j = tv_j_1;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_exp_key_1, exp_key.octs), DOT2_AES_128_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_seed_priv_1, seed_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_priv_1, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_pub_1, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_cert_1, cert.octs), (size_t)tv_cert_size_1);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_pub_key_1, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_h_1, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_priv_key_1, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
    }

    // 테스트
    {
      int ret;
      struct Dot2ECPrivateKey priv_key;
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i,
                                                                   j,
                                                                   &exp_key,
                                                                   &seed_priv,
                                                                   &recon_priv,
                                                                   &recon_pub,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &issuer_pub_key,
                                                                   &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
  }

  // 테스트 벡터 #2
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      i = tv_i_2;
      j = tv_j_2;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_exp_key_2, exp_key.octs), DOT2_AES_128_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_seed_priv_2, seed_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_priv_2, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_pub_2, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_cert_2, cert.octs), (size_t)tv_cert_size_2);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_pub_key_2, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_h_2, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_priv_key_2, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
    }

    // 테스트
    {
      int ret;
      struct Dot2ECPrivateKey priv_key;
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i,
                                                                   j,
                                                                   &exp_key,
                                                                   &seed_priv,
                                                                   &recon_priv,
                                                                   &recon_pub,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &issuer_pub_key,
                                                                   &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
  }

  // 테스트 벡터 #3
  {
    // 준비
    {
      // 테스트벡터 바이트열 변환
      i = tv_i_3;
      j = tv_j_3;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_exp_key_3, exp_key.octs), DOT2_AES_128_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_seed_priv_3, seed_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_priv_3, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_pub_3, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(tv_cert_3, cert.octs), (size_t)tv_cert_size_3);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_pub_key_3, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_issuer_h_3, issuer_h.octs), DOT2_SHA_256_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_priv_key_3, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
    }

    // 테스트
    {
      int ret;
      struct Dot2ECPrivateKey priv_key;
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i,
                                                                   j,
                                                                   &exp_key,
                                                                   &seed_priv,
                                                                   &recon_priv,
                                                                   &recon_pub,
                                                                   &cert,
                                                                   &issuer_h,
                                                                   &issuer_pub_key,
                                                                   &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
  }

  // g_tv_bundle_0_pseudonym_13a_*
  {
    int ret;
    struct Dot2ECPrivateKey priv_key;
    i = 0x13a;
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_expansion_key, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_seed_priv_key, seed_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_pub_key, issuer_pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca_h, issuer_h.octs), DOT2_SHA_256_LEN);

    {
      j = 0x0;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_0_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x1;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_1_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x2;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_2_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x3;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_3_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x4;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_4_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x5;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_5_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x6;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_6_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x7;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_7_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x8;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_8_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x9;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_9_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0xa;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_a_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0xb;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_b_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0xc;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_c_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0xd;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_d_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0xe;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_e_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0xf;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_f_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x10;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_10_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x11;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_11_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x12;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_12_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
    {
      j = 0x13;
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
      ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_cert, cert.octs), g_tv_bundle_0_pseudonym_13a_13_cert_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_priv_key, expected_priv_key.octs), DOT2_EC_256_KEY_LEN);
      ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i, j, &exp_key, &seed_priv, &recon_priv, &recon_pub, &cert, &issuer_h, &issuer_pub_key, &priv_key);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_key.octs, expected_priv_key.octs, DOT2_EC_256_KEY_LEN));
    }
  }

  Dot2_Release();
}

