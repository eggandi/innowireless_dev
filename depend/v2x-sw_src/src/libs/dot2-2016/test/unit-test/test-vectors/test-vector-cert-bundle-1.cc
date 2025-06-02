/** 
  * @file 
  * @brief 인증서 번들 #1(블루텍) 테스트벡터 정의
  * @date 2022-08-02 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"

// SCC
const char *g_tv_bundle_1_rca = "800300810018810e7263612e73636d732e636f2e6b72000000000014b8411386003c01028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc080808215690635b545c793cac8b4d8fc205646366df9a3abeca96b9d178ceb8a63321c8080294e8ccc6583d43c10ee88d87dcaad8b773a65ff95c9d739d465581d505cc0f964b5d7aaaa1a8cb7fc311904b46402c6826176b54e56244d54da69e52668cec8"; // rca
const char *g_tv_bundle_1_rca_h = "457676d9947ca73eb6f3aeeffc22d7b98069d93b956267a455f881a13f7e0361";
const char *g_tv_bundle_1_rca_pub_key = "0215690635B545C793CAC8B4D8FC205646366DF9A3ABECA96B9D178CEB8A63321C";
int g_tv_bundle_1_rca_size = 198;
const char *g_tv_bundle_1_ica = "8003008055f881a13f7e036158810e6963612e73636d732e636f2e6b727e0361000214b8411386001483010280019a800348010180012380038300010102a0810102c06080010280012381800201008101ffc0808083dd72ed0448b4172ad8fbcc9fd2e28fdd00b7e55f31c846badb876b30bcc637d480807b796e43e0d0cf0b1a850f23fb49c221711c8d0c58f23c3647d11f15bb687138afddd02abd4aff910ed1a287f1701f3cabcc8f4c66f9440b9eaceb16b6aa9df9"; // ica
const char *g_tv_bundle_1_ica_h = "e7d264edde031273eb14f7f3b6fb87f55ebe39acbd6577f20e8409a8e6535429";
const char *g_tv_bundle_1_ica_pub_key = "DD72ED0448B4172AD8FBCC9FD2E28FDD00B7E55F31C846BADB876B30BCC637D4";
int g_tv_bundle_1_ica_size = 184;
const char *g_tv_bundle_1_pca = "800300800e8409a8e653542959810e7063612e73636d732e636f2e6b72535429000214b8411386001483010280019a8003480101800123800385000101010081008082727dfbe9eb7672a31ed4d6da5581e48c44c5cd1090eedf9b746d095d17225a2f80808398156592c72729dad5d7e6beb1e3623c6da1e7d196ecc0a2c373a6795a4ff2bf80804fbc87b9e670db7d18c252674be6de3d4593eb96c41897bf4ac8e71bfe7d293b54fba3e4d6bc273d24c96eba9683912b56406151f57987c0887cfd82bf6138a6"; // pca
const char *g_tv_bundle_1_pca_h = "6ad2cb40f982554c0c3472413296fba7784ce7b1ddfe4f8c2abad5e80d25da1b";
const char *g_tv_bundle_1_pca_pub_key = "0398156592C72729DAD5D7E6BEB1E3623C6DA1E7D196ECC0A2C373A6795A4FF2BF";
int g_tv_bundle_1_pca_size = 200;
const char *g_tv_bundle_1_eca = "800300800e8409a8e653542959810e6563612e73636d732e636f2e6b72535429000214b8411386001483010280019a800348010180012380038400010101208140008082d244e2e02815288282fea552f1312b1b0f9bc8cbb6e736c54f39adfff01aa8e7808082bb1758b79dd99f54f31a605f3d9a0899f4a7c7e2e67d36bbb350f99db1c6b01980800e540bd30c67ff4e7775cb9c593681e5869324b8dd2d09772e51bc3c5b35b4224512b503e67de07e8ddca4bc20548bc46a3d2b3ec03a50ee57cacf6c188f7442"; // eca
const char *g_tv_bundle_1_eca_h = "ec5acca1cfa644d99dfd1ee8fff8e3e0b6b5d51899e0f88d1cbf30d82eb01ed6";
const char *g_tv_bundle_1_eca_pub_key = "02BB1758B79DD99F54F31A605F3D9A0899F4A7C7E2E67D36BBB350F99DB1C6B019";
int g_tv_bundle_1_eca_size = 201;
const char *g_tv_bundle_1_ra = "800300800e8409a8e653542959810d72612e73636d732e636f2e6b72535429000214b8411386001483010280019a800348010180012380038b0001010180810100008082ae8194b66aeaa0cd7606d9ad9f94b726b92c088632ad8718f074e9d49f730d11808082b916f666e009d964b0c56a5433fde1bbe240baba7980f10a7fa4005836eaef358080aea7f50d32c2cc37a5f270c914d18d990e9fa20b788d3ba8efc1ff5b3eaf1b1d47406ffc0fd9f2e4488a59d67082f01a9924405dcaeac01e4fb8a4c9d154465d"; // ra
const char *g_tv_bundle_1_ra_h = "2e51a6f78effd48156ece5d938d2ce65b97c9c208ddcc317170b34d8750a8ed7";
const char *g_tv_bundle_1_ra_pub_key = "02B916F666E009D964B0C56A5433FDE1BBE240BABA7980F10A7FA4005836EAEF35";
int g_tv_bundle_1_ra_size = 201;

// Enrollment certificate
const char *g_tv_bundle_1_enrol_cert_0_init_priv_key = "976ab996cc178c57b173d904afa85ee4253b3f89746d0ea5cde5b13cf92aa433";
const char *g_tv_bundle_1_enrol_cert_0_recon_priv = "9634967c2ec3a4d63da4ad2149d75114d90a8d73f27598d7c58703383e69ca26";
const char *g_tv_bundle_1_enrol_cert_0_recon_pub = "024F350D9E69715BA9C0F4AAE6A08D227453DF37857DCF8F58B341559CD91BFA9F";
const char *g_tv_bundle_1_enrol_cert_0_priv_key = "b41528368e9c3d63ad9ecba0f2d8c819e75a127acec81a32b8548fc933f8f9ab";
const char *g_tv_bundle_1_enrol_cert_0_pub_key = "04743C7050EC47C24EBB0BE662B694E9856CC0F17AFF62199428A137DCA8742EBDAFF38BB5CB7C9C375F2121CB3EAC7314658DC3171DA1C643FDE01DBF2165C42A";
const char *g_tv_bundle_1_enrol_cert_0 = "000301801cbf30d82eb01ed6448100b01ed6000422f5b5a58600068301028000b48001e0010180800103000120000123000187010081824f350d9e69715ba9c0f4aae6a08d227453df37857dcf8f58b341559cd91bfa9f";
const char *g_tv_bundle_1_enrol_cert_0_h = "99845f3a57d810a937539ab7e8c8f1fc93492ebabdae342268e188482c24424a";
const char *g_tv_bundle_1_enrol_cert_0_tbs_h = "7ba9359d2e441b7e77a772d4c7639e2216f43166cdeb02ff8a6470f4f867171b";
int g_tv_bundle_1_enrol_cert_0_size = 87;
const char *g_tv_bundle_1_enrol_cert_0_cmhf_name = "e_32_35_135_220802.122920-280731.122920_key.cmhf2";
const char *g_tv_bundle_1_enrol_cert_0_cmhf = "4954454B041CBF30D82EB01ED6B01ED6000422F5B5A52E3CEAA502030000002000000023000000870200B401E0005799845F3A57D810A937539AB7E8C8F1FC93492EBABDAE342268E188482C24424A0100B41528368E9C3D63AD9ECBA0F2D8C819E75A127ACEC81A32B8548FC933F8F9AB00000301801CBF30D82EB01ED6448100B01ED6000422F5B5A58600068301028000B48001E0010180800103000120000123000187010081824F350D9E69715BA9C0F4AAE6A08D227453DF37857DCF8F58B341559CD91BFA9Fc5030fe79832d382";
int g_tv_bundle_1_enrol_cert_0_cmhf_size = 209;

// application certificate
const char *g_tv_bundle_1_app_cert_0_init_priv_key = "fa88dd76000b22a5d55c6abc109005d731f3475ab73bccecf6577d7f2ae79ccd";
const char *g_tv_bundle_1_app_cert_0_recon_priv = "CC5FC913AC1D56B59B062AA36D1012D60A235A36223826C82D0064A634B4AF9E";
const char *g_tv_bundle_1_app_cert_0_recon_pub = "02524EEA0191D94D43D3395CE1DE65FA481885CA078000136DF2DE157B5F22AA3C";
const char *g_tv_bundle_1_app_cert_0_priv_key = "adaf7d2de7ba472c3200e6b310ce9e0ec62783e930675fcc4276e7b4cc1e2921";
const char *g_tv_bundle_1_app_cert_0_pub_key = "04215be772360460101dee0699bcc3c4a603051aeae7c5fc388f975f48b390a5ad90b008a00d2b84882c56080edf2879b1f51069de150c7a6866cb18b3d21139b8";
const char *g_tv_bundle_1_app_cert_0 = "000301802abad5e80d25da1b50820802524eea0191d94d25da1b000322f572448400a983010180019a01030001200001230001878182524eea0191d94d43d3395ce1de65fa481885ca078000136df2de157b5f22aa3c"; // 3639646433653465.cert
const char *g_tv_bundle_1_app_cert_0_h = "2cd1cef68fdabe62663de7b8ea5d94eb239cfda45bda06976746c1da0dcebf60";
const char *g_tv_bundle_1_app_cert_0_tbs_h = "d5853f06caae428782f42548cb17ac3ab0348ca050d863d41fdea759c055521d";
int g_tv_bundle_1_app_cert_0_size = 86;
const char *g_tv_bundle_1_app_cert_0_cmhf_name = "a_32_35_135_220802.074151-220809.084151_key.cmhf2";
const char *g_tv_bundle_1_app_cert_0_cmhf = "4954454B012ABAD5E80D25DA1B25DA1B000322F5724422FEBAD4020300000020000000230000008701019A00562CD1CEF68FDABE62663DE7B8EA5D94EB239CFDA45BDA06976746C1DA0DCEBF600200ADAF7D2DE7BA472C3200E6B310CE9E0EC62783E930675FCC4276E7B4CC1E29210802524EEA0191D94D000301802ABAD5E80D25DA1B50820802524EEA0191D94D25DA1B000322F572448400A983010180019A01030001200001230001878182524EEA0191D94D43D3395CE1DE65FA481885CA078000136DF2DE157B5F22AA3C36ec394116316df2";
int g_tv_bundle_1_app_cert_0_cmhf_size = 214;

const char *g_tv_bundle_1_app_cert_1_init_priv_key = "0159b5825672278843f71cf8a0b54ad07bef681b6217b22e72c9098905b8ecc6";
const char *g_tv_bundle_1_app_cert_1_recon_priv = "D8AEFAA4A277BA16F6CA343ED601B3E55E05F48114FC4314D5D0B4D285FA8E0A"; // 907f01f94d22d971.s
const char *g_tv_bundle_1_app_cert_1_recon_pub = "02EE9DAB78DC7B54560181033BAC44F39F9645991BBABA6751C3EDC9757AEF5D2D";
const char *g_tv_bundle_1_app_cert_1_priv_key = "A0B5F737E5C33FFE377CDA32336B8438CE0261E6CE9A62C5E40EA7F0B2058890"; // 907f01f94d22d971.privkey
const char *g_tv_bundle_1_app_cert_1_pub_key = "041E9E76B90B722DC34F23FE85D16B8B9AB1729B635506C08A2DBA6534494ED774DF7CC759D4EDC8B800E38124220CB16809073CA4E1809C3068DF4974CAFB2FDC";
const char *g_tv_bundle_1_app_cert_1 = "000301802ABAD5E80D25DA1B50820802EE9DAB78DC7B5425DA1B000322FD8DB28400A98301028000B48001E001030001200001230001878182EE9DAB78DC7B54560181033BAC44F39F9645991BBABA6751C3EDC9757AEF5D2D"; // 907f01f94d22d971.cert
const char *g_tv_bundle_1_app_cert_1_h = "5bf82a0b0b0d17363fd0c608027f75dc868ecd2f3d107419907f01f94d22d971";
const char *g_tv_bundle_1_app_cert_1_tbs_h = "463cb8f771e72f449eee2caba4fd64a0571d09809206fa0c3ac43dab763033a6";
int g_tv_bundle_1_app_cert_1_size = 89;
const char *g_tv_bundle_1_app_cert_1_cmhf_name = "a_32_35_135_220808.111701-220815.121701_key.cmhf2";
const char *g_tv_bundle_1_app_cert_1_cmhf = "4954454B012ABAD5E80D25DA1B25DA1B000322FD8DB22306D64202030000002000000023000000870200B401E000595BF82A0B0B0D17363FD0C608027F75DC868ECD2F3D107419907F01F94D22D9710200A0B5F737E5C33FFE377CDA32336B8438CE0261E6CE9A62C5E40EA7F0B20588900802EE9DAB78DC7B54000301802ABAD5E80D25DA1B50820802EE9DAB78DC7B5425DA1B000322FD8DB28400A98301028000B48001E001030001200001230001878182EE9DAB78DC7B54560181033BAC44F39F9645991BBABA6751C3EDC9757AEF5D2D896F01B257C2C40E";
int g_tv_bundle_1_app_cert_1_cmhf_size = 219;

// identification certificate
const char *g_tv_bundle_1_id_cert_0_seed_priv_key = "92f559902f48fbd85554382e1cb894f85da8f097612def109f798ce870119d27";
const char *g_tv_bundle_1_id_cert_0_expansion_key = "89e4d21e845c19509b6afc51e5660816";
const char *g_tv_bundle_1_id_cert_0_recon_priv = "c8a5b455e00abce2a02a03f5c2f7c77dbc778d040576a664a07c2c1753babfdf";
const char *g_tv_bundle_1_id_cert_0_recon_pub = "";
const char *g_tv_bundle_1_id_cert_0_priv_key = "77b77ae241e90ce70a8845839af56772acc9c2ab283d8ba8de57727b3f49479a";
const char *g_tv_bundle_1_id_cert_0_pub_key = "";
const char *g_tv_bundle_1_id_cert_0 = "000301802abad5e80d25da1b508208035254529020dc4d25da1b000314b841138400a983010180019a010300012000012300018781835254529020dc4da992087cc8b6d6daf0a480e2de36c53a0b6677f87c52a08d1a"; // 0_0.cert
const char *g_tv_bundle_1_id_cert_0_h = "4d8d026d021a53c2a9167281025b3ae3f38e55f0633f729ec88adbe6b9d1eaca";
const char *g_tv_bundle_1_id_cert_0_tbs_h = "d9b636b492cea6152946c1e5a67bac9decc63eb16d5e22b0f6008d428e3e4861";
int g_tv_bundle_1_id_cert_0_size = 86;
const char *g_tv_bundle_1_id_cert_0_cmhf_name = "i_32_35_135_150106.085958-150113.095958_key.cmhf2";
const char *g_tv_bundle_1_id_cert_0_cmhf = "4954454b022abad5e80d25da1b25da1b000314b8411314c189a3020300000020000000230000008701019a000000000100564d8d026d021a53c2a9167281025b3ae3f38e55f0633f729ec88adbe6b9d1eaca020077b77ae241e90ce70a8845839af56772acc9c2ab283d8ba8de57727b3f49479a08035254529020dc4d000301802abad5e80d25da1b508208035254529020dc4d25da1b000314b841138400a983010180019a010300012000012300018781835254529020dc4da992087cc8b6d6daf0a480e2de36c53a0b6677f87c52a08d1ab8a7287a32b6a07c";
int g_tv_bundle_1_id_cert_0_cmhf_size = 219;

const char *g_tv_bundle_1_id_cert_1_seed_priv_key = "92f559902f48fbd85554382e1cb894f85da8f097612def109f798ce870119d27";
const char *g_tv_bundle_1_id_cert_1_expansion_key = "89e4d21e845c19509b6afc51e5660816";
const char *g_tv_bundle_1_id_cert_1_recon_priv = "f87c9d362a10bdd7ba4410478fedc52aa5fa990fdc48cb245c71ddb3214e127d";
const char *g_tv_bundle_1_id_cert_1_recon_pub = "";
const char *g_tv_bundle_1_id_cert_1_priv_key = "599fdf58ab4a5a5cd8833a9441832e76806401bffec848d7934556fa088890ba";
const char *g_tv_bundle_1_id_cert_1_pub_key = "";
const char *g_tv_bundle_1_id_cert_1 = "000301802abad5e80d25da1b50820802ad86e93758cdd725da1b000314c17b938400a983010180019a01030001200001230001878182ad86e93758cdd79a590172547aa9499d6ce4bbc624457ca4605fce6c3ecdc38d";
const char *g_tv_bundle_1_id_cert_1_h = "a3f96f43d8e1dc7bb011880dd6a2be67996f0cdd811389c1b0ec43ec43683f21";
const char *g_tv_bundle_1_id_cert_1_tbs_h = "602333b95a8563b3bd874f7e1665eca3b1d4647e016c3165617258d43ff6baa4";
int g_tv_bundle_1_id_cert_1_size = 86;
const char *g_tv_bundle_1_id_cert_1_cmhf_name = "i_32_35_135_150113.085958-150120.095958_key.cmhf2";
const char *g_tv_bundle_1_id_cert_1_cmhf = "4954454b022abad5e80d25da1b25da1b000314c17b9314cac423020300000020000000230000008701019a00000001010056a3f96f43d8e1dc7bb011880dd6a2be67996f0cdd811389c1b0ec43ec43683f210200599fdf58ab4a5a5cd8833a9441832e76806401bffec848d7934556fa088890ba0802ad86e93758cdd7000301802abad5e80d25da1b50820802ad86e93758cdd725da1b000314c17b938400a983010180019a01030001200001230001878182ad86e93758cdd79a590172547aa9499d6ce4bbc624457ca4605fce6c3ecdc38d59a4cc2c25af7be3";
int g_tv_bundle_1_id_cert_1_cmhf_size = 219;


#if 0
const char *g_tv_bundle_1_app_cert_1_init_priv_key = ""; // rse-1/dwnl_sgn.priv
const char *g_tv_bundle_1_app_cert_1_recon_priv = ""; // rse-1/364c409476b5ffd0.s
const char *g_tv_bundle_1_app_cert_1_recon_pub = "";
const char *g_tv_bundle_1_app_cert_1_priv_key = "";
const char *g_tv_bundle_1_app_cert_1_pub_key = "";
const char *g_tv_bundle_1_app_cert_1 = ""; // rse-1/364c409476b5ffd0.cert
const char *g_tv_bundle_1_app_cert_1_h = "";
const char *g_tv_bundle_1_app_cert_1_tbs_h = "";
int g_tv_bundle_1_app_cert_1_size = ;
const char *g_tv_bundle_1_app_cert_1_cmhf_name = ".233534-210319.093534_key.cmhf2";
const char *g_tv_bundle_1_app_cert_1_cmhf = "";
int g_tv_bundle_1_app_cert_1_cmhf_size = ;
#endif

#if 0
// OBU (38DB109583949D23)
const char *g_tv_bundle_1_pseudonym_init_priv_key = ""; // dwnl_sgn.priv
const char *g_tv_bundle_1_pseudonym_expansion_key = ""; // sgn_expnsn.key
const char *g_tv_bundle_1_pseudonym_13a_0_recon_priv = ""; // 13A_0.s
const char *g_tv_bundle_1_pseudonym_13a_0_recon_pub = "";
const char *g_tv_bundle_1_pseudonym_13a_0_priv_key = "";
const char *g_tv_bundle_1_pseudonym_13a_0_pub_key = "";
const char *g_tv_bundle_1_pseudonym_13a_0_cert = ""; // 13A_0.cert
const char *g_tv_bundle_1_pseudonym_13a_0_cert_h = "";
const char *g_tv_bundle_1_pseudonym_13a_0_cert_tbs_h = "";
int g_tv_bundle_1_pseudonym_13a_0_cert_size = ;

const char *g_tv_bundle_1_pseudonym_13a_1_recon_priv = ""; // 13A_1.s
const char *g_tv_bundle_1_pseudonym_13a_1_recon_pub = "";
const char *g_tv_bundle_1_pseudonym_13a_1_priv_key = "";
const char *g_tv_bundle_1_pseudonym_13a_1_pub_key = "";
const char *g_tv_bundle_1_pseudonym_13a_1_cert = ""; // 13A_1.cert
const char *g_tv_bundle_1_pseudonym_13a_1_cert_h = "";
const char *g_tv_bundle_1_pseudonym_13a_1_cert_tbs_h = "";
int g_tv_bundle_1_pseudonym_13a_1_cert_size = ;
#endif



/**
 * @brief SCC 인증서들을 등록한다.
 */
void Dot2Test_Add_CertBundle_1_SCCCerts()
{
  uint8_t cert[kDot2CertSize_Max];
  Dot2CertSize cert_size;

  ASSERT_EQ((cert_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_rca, cert)), g_tv_bundle_1_rca_size);
  ASSERT_EQ(Dot2_AddSCCCert(cert, cert_size), kDot2Result_Success);
  ASSERT_EQ((cert_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_ica, cert)), g_tv_bundle_1_ica_size);
  ASSERT_EQ(Dot2_AddSCCCert(cert, cert_size), kDot2Result_Success);
  ASSERT_EQ((cert_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca, cert)), g_tv_bundle_1_pca_size);
  ASSERT_EQ(Dot2_AddSCCCert(cert, cert_size), kDot2Result_Success);
  ASSERT_EQ((cert_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca, cert)), g_tv_bundle_1_eca_size);
  ASSERT_EQ(Dot2_AddSCCCert(cert, cert_size), kDot2Result_Success);
  ASSERT_EQ((cert_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_ra, cert)), g_tv_bundle_1_ra_size);
  ASSERT_EQ(Dot2_AddSCCCert(cert, cert_size), kDot2Result_Success);
}


/**
 * @brief 등록 인증서의 CMHF를 등록한다.
 */
void Dot2Test_Load_CertBundle_1_EnrolCMHF()
{
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;
  ASSERT_EQ((cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_cmhf, cmhf)), g_tv_bundle_1_enrol_cert_0_cmhf_size);
  ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
}


/**
 * @brief App 인증서들의 CMHF를 등록한다.
 */
void Dot2Test_Load_CertBundle_1_AppCMHFs()
{
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;
  ASSERT_EQ((cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_cmhf, cmhf)), g_tv_bundle_1_app_cert_1_cmhf_size);
  ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
  ASSERT_EQ((cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_cmhf, cmhf)), g_tv_bundle_1_app_cert_1_cmhf_size);
  ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
}


/*
 * Enrollment cert 0 의 CMHEntry 정보 유효성을 체크한다.
 */
bool Dot2Test_Check_CertBundle_1_EnrolCert_0_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry)
{
  Dot2CertType cert_type = kDot2CertType_Implicit;
  Dot2CertIssuerIdentifierType issuer_type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  const char *issuer_h8_str = "1CBF30D82EB01ED6";
  Dot2CertIdType cert_id_type = kDot2CertIdType_Name;
  Dot2CertIdHostNameLen cert_id_len = 0;
  const char *craca_id_str = "B01ED6";
  Dot2CertCRLSeries crl_series = 4;
  Dot2Time64 valid_start = 586528165000000ULL;
  Dot2Time64 valid_end = 775744165000000ULL;
  Dot2CertValidRegionType region_type = kDot2CertValidRegionType_Identified;
  Dot2IdentifiedRegionNum region_id_num = 2;
  Dot2CountryCode region_id_0 = 180;
  Dot2CountryCode region_id_1 = 480;
  Dot2CertPermissionNum psid_num = 3;
  Dot2PSID psid_0 = 32;
  Dot2PSID psid_1 = 35;
  Dot2PSID psid_2 = 135;


  uint8_t cert[kDot2CertSize_Max], craca_id[DOT2_CRACA_ID_LEN], issuer_h8[8];
  struct Dot2SHA256 cert_h{};
  struct Dot2ECPrivateKey priv_key{};
  struct Dot2ECPublicKey pub_key{}, recon_pub{};

  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0, cert), g_tv_bundle_1_enrol_cert_0_size);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_h, cert_h.octs), DOT2_SHA_256_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_pub_key, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(issuer_h8_str, issuer_h8), 8);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(craca_id_str, craca_id), DOT2_CRACA_ID_LEN);

  EXPECT_EQ((int)cmh_entry->cert_size, g_tv_bundle_1_enrol_cert_0_size);
  EXPECT_TRUE(cmh_entry->cert);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->cert, cert, g_tv_bundle_1_enrol_cert_0_size));
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN));
  EXPECT_TRUE(cmh_entry->issuer);
  EXPECT_TRUE(cmh_entry->asn1_cert);
  struct Dot2SequentialCMHInfo *cmh_info = &(cmh_entry->info);
  EXPECT_TRUE(cmh_info->eck_priv_key);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
  struct Dot2EECertContents *contents = &(cmh_info->cert_contents);
  // EXPECT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // CMH/CMHF에 공개키는 저장되지 않음.
  EXPECT_FALSE(contents->eck_verify_pub_key);
  struct Dot2CertCommonContents *common = &(contents->common);
  EXPECT_EQ(common->type, cert_type);
  EXPECT_EQ(common->issuer.type, issuer_type);
  EXPECT_TRUE(Dot2Test_CompareOctets(common->issuer.h8, issuer_h8, 8));
  EXPECT_EQ(common->id.type, cert_id_type);
  EXPECT_EQ(common->id.u.name.len, cert_id_len);
  EXPECT_TRUE(Dot2Test_CompareOctets(common->craca_id, craca_id, sizeof(craca_id)));
  EXPECT_EQ(common->crl_series, crl_series);
  EXPECT_EQ(common->valid_start, valid_start);
  EXPECT_EQ(common->valid_end, valid_end);
  EXPECT_EQ(common->valid_region.type, region_type);
  EXPECT_EQ(common->valid_region.u.id.num, region_id_num);
  EXPECT_EQ(common->valid_region.u.id.country[0], region_id_0);
  EXPECT_EQ(common->valid_region.u.id.country[1], region_id_1);
  // EXPECT_EQ(common->verify_key_indicator.type, kDot2CertVerificationKeyIndicatorType_ReconstructValue); // CMH/CMHF에 공개키재구성값은 저장되지 않는다.
  // EXPECT_TRUE(Dot2Test_CompareOctets(common->verify_key_indicator.key.u.octs, recon_pub.u.octs, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  EXPECT_FALSE(common->enc_pub_key_present);
  struct Dot2EECertPermissions *perms = &(contents->app_perms);
  EXPECT_EQ(perms->psid_num, psid_num);
  EXPECT_EQ(perms->psid[0], psid_0);
  EXPECT_EQ(perms->psid[1], psid_1);
  EXPECT_EQ(perms->psid[2], psid_2);
  if ((int)cmh_entry->cert_size != g_tv_bundle_1_enrol_cert_0_size) { return false; }
  if (!cmh_entry->cert) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->cert, cert, g_tv_bundle_1_enrol_cert_0_size)) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN)) { return false; }
  if (!cmh_entry->issuer) { return false; }
  if (!cmh_entry->asn1_cert) { return false; }
  if (!cmh_info->eck_priv_key) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN)) { return false; }
  if (contents->eck_verify_pub_key) { return false; }
  if (common->type != cert_type) { return false; }
  if (common->issuer.type != issuer_type) { return false; }
  if (!Dot2Test_CompareOctets(common->issuer.h8, issuer_h8, 8)) { return false; }
  if (common->id.type != cert_id_type) { return false; }
  if (common->id.u.name.len != cert_id_len) { return false; }
  if (!Dot2Test_CompareOctets(common->craca_id, craca_id, sizeof(craca_id))) { return false; }
  if (common->crl_series != crl_series) { return false; }
  if (common->valid_start != valid_start) { return false; }
  if (common->valid_end != valid_end) { return false; }
  if (common->valid_region.type != region_type) { return false; }
  if (common->valid_region.u.id.num != region_id_num) { return false; }
  if (common->valid_region.u.id.country[0] != region_id_0) { return false; }
  if (common->valid_region.u.id.country[1] != region_id_1) { return false; }
  if (common->enc_pub_key_present) { return false; }
  if (perms->psid_num != psid_num) { return false; }
  if (perms->psid[0] != psid_0) { return false; }
  if (perms->psid[1] != psid_1) { return false; }
  if (perms->psid[2] != psid_2) { return false; }
  return true;
}


/*
 * App cert 0 의 CMHEntry 정보 유효성을 체크한다.
 */
bool Dot2Test_Check_CertBundle_1_AppCert_0_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry)
{
  Dot2CertType cert_type = kDot2CertType_Implicit;
  Dot2CertIssuerIdentifierType issuer_type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  const char *issuer_h8_str = "2ABAD5E80D25DA1B";
  const char *binary_id_str = "02524EEA0191D94D";
  Dot2CertIdType cert_id_type = kDot2CertIdType_BinaryId;
  Dot2CertBinaryIdLen cert_id_len = kDot2CertBinaryIdLen_Default;
  const char *craca_id_str = "25DA1B";
  Dot2CertCRLSeries crl_series = 3;
  Dot2Time64 valid_start = 586510916000000ULL;
  Dot2Time64 valid_end = 587119316000000ULL;
  Dot2CertValidRegionType region_type = kDot2CertValidRegionType_Identified;
  Dot2IdentifiedRegionNum region_id_num = 1;
  Dot2CountryCode region_id_0 = 410;
  Dot2CertPermissionNum psid_num = 3;
  Dot2PSID psid_0 = 32;
  Dot2PSID psid_1 = 35;
  Dot2PSID psid_2 = 135;

  uint8_t cert[kDot2CertSize_Max], binary_id[kDot2CertBinaryIdLen_Default], craca_id[DOT2_CRACA_ID_LEN], issuer_h8[8];
  struct Dot2SHA256 cert_h{};
  struct Dot2ECPrivateKey priv_key{};
  struct Dot2ECPublicKey pub_key{}, recon_pub{};

  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0, cert), g_tv_bundle_1_app_cert_0_size);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_h, cert_h.octs), DOT2_SHA_256_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_pub_key, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(issuer_h8_str, issuer_h8), 8);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(binary_id_str, binary_id), (int)cert_id_len);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(craca_id_str, craca_id), DOT2_CRACA_ID_LEN);

  EXPECT_EQ((int)cmh_entry->cert_size, g_tv_bundle_1_app_cert_0_size);
  EXPECT_TRUE(cmh_entry->cert);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->cert, cert, g_tv_bundle_1_app_cert_0_size));
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN));
  EXPECT_TRUE(cmh_entry->issuer);
  EXPECT_TRUE(cmh_entry->asn1_cert);
  struct Dot2SequentialCMHInfo *cmh_info = &(cmh_entry->info);
  EXPECT_TRUE(cmh_info->eck_priv_key);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
  struct Dot2EECertContents *contents = &(cmh_info->cert_contents);
  // EXPECT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // CMH/CMHF에 공개키는 저장되지 않음.
  EXPECT_FALSE(contents->eck_verify_pub_key);
  struct Dot2CertCommonContents *common = &(contents->common);
  EXPECT_EQ(common->type, cert_type);
  EXPECT_EQ(common->issuer.type, issuer_type);
  EXPECT_TRUE(Dot2Test_CompareOctets(common->issuer.h8, issuer_h8, 8));
  EXPECT_EQ(common->id.type, cert_id_type);
  EXPECT_EQ(common->id.u.binary_id.len, cert_id_len);
  EXPECT_TRUE(Dot2Test_CompareOctets(common->id.u.binary_id.id, binary_id, cert_id_len));
  EXPECT_TRUE(Dot2Test_CompareOctets(common->craca_id, craca_id, sizeof(craca_id)));
  EXPECT_EQ(common->crl_series, crl_series);
  EXPECT_EQ(common->valid_start, valid_start);
  EXPECT_EQ(common->valid_end, valid_end);
  EXPECT_EQ(common->valid_region.type, region_type);
  EXPECT_EQ(common->valid_region.u.id.num, region_id_num);
  EXPECT_EQ(common->valid_region.u.id.country[0], region_id_0);
  // EXPECT_EQ((int)common->verify_key_indicator.type, kDot2CertVerificationKeyIndicatorType_ReconstructValue); // CMH/CMHF에 공개키재구성값은 저장되지 않는다.
  // EXPECT_TRUE(Dot2Test_CompareOctets(common->verify_key_indicator.key.u.octs, recon_pub.u.octs, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  EXPECT_FALSE(common->enc_pub_key_present);
  struct Dot2EECertPermissions *perms = &(contents->app_perms);
  EXPECT_EQ(perms->psid_num, psid_num);
  EXPECT_EQ(perms->psid[0], psid_0);
  if ((int)cmh_entry->cert_size != g_tv_bundle_1_app_cert_0_size) { return false; }
  if (!cmh_entry->cert) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->cert, cert, g_tv_bundle_1_app_cert_0_size)) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN)) { return false; }
  if (!cmh_entry->issuer) { return false; }
  if (!cmh_entry->asn1_cert) { return false; }
  if (!cmh_info->eck_priv_key) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN)) { return false; }
  if (contents->eck_verify_pub_key) { return false; }
  if (common->type != cert_type) { return false; }
  if (common->issuer.type != issuer_type) { return false; }
  if (!Dot2Test_CompareOctets(common->issuer.h8, issuer_h8, 8)) { return false; }
  if (common->id.type != cert_id_type) { return false; }
  if (common->id.u.binary_id.len != cert_id_len) { return false; }
  if (!Dot2Test_CompareOctets(common->id.u.binary_id.id, binary_id, cert_id_len)) { return false; }
  if (!Dot2Test_CompareOctets(common->craca_id, craca_id, sizeof(craca_id))) { return false; }
  if (common->crl_series != crl_series) { return false; }
  if (common->valid_start != valid_start) { return false; }
  if (common->valid_end != valid_end) { return false; }
  if (common->valid_region.type != region_type) { return false; }
  if (common->valid_region.u.id.num != region_id_num) { return false; }
  if (common->valid_region.u.id.country[0] != region_id_0) { return false; }
  if (common->enc_pub_key_present) { return false; }
  if (perms->psid_num != psid_num) { return false; }
  if (perms->psid[0] != psid_0) { return false; }
  if (perms->psid[1] != psid_1) { return false; }
  if (perms->psid[2] != psid_2) { return false; }
  return true;
}


/*
 * App cert 1 의 CMHEntry 정보 유효성을 체크한다.
 */
bool Dot2Test_Check_CertBundle_1_AppCert_1_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry)
{
  Dot2CertSize cert_size = g_tv_bundle_1_app_cert_1_size;
  Dot2CertType cert_type = kDot2CertType_Implicit;
  Dot2CertIssuerIdentifierType issuer_type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  const char *issuer_h8_str = "2ABAD5E80D25DA1B";
  const char *binary_id_str = "02EE9DAB78DC7B54";
  Dot2CertIdType cert_id_type = kDot2CertIdType_BinaryId;
  Dot2CertBinaryIdLen cert_id_len = kDot2CertBinaryIdLen_Default;
  const char *craca_id_str = "25DA1B";
  Dot2CertCRLSeries crl_series = 3;
  Dot2Time64 valid_start = 587042226000000ULL;
  Dot2Time64 valid_end = 587650626000000ULL;
  Dot2CertValidRegionType region_type = kDot2CertValidRegionType_Identified;
  Dot2IdentifiedRegionNum region_id_num = 2;
  Dot2CountryCode region_id_0 = 180;
  Dot2CountryCode region_id_1 = 480;
  Dot2CertPermissionNum psid_num = 3;
  Dot2PSID psid_0 = 32;
  Dot2PSID psid_1 = 35;
  Dot2PSID psid_2 = 135;

  uint8_t cert[kDot2CertSize_Max], binary_id[kDot2CertBinaryIdLen_Default], craca_id[DOT2_CRACA_ID_LEN], issuer_h8[8];
  struct Dot2SHA256 cert_h{};
  struct Dot2ECPrivateKey priv_key{};
  struct Dot2ECPublicKey pub_key{}, recon_pub{};

  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1, cert), (int)cert_size);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_h, cert_h.octs), DOT2_SHA_256_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
  //EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_pub_key, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_recon_pub, recon_pub.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(issuer_h8_str, issuer_h8), 8);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(binary_id_str, binary_id), (int)cert_id_len);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(craca_id_str, craca_id), DOT2_CRACA_ID_LEN);

  EXPECT_EQ(cmh_entry->cert_size, cert_size);
  EXPECT_TRUE(cmh_entry->cert);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->cert, cert, cert_size));
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN));
  EXPECT_TRUE(cmh_entry->issuer);
  EXPECT_TRUE(cmh_entry->asn1_cert);
  struct Dot2SequentialCMHInfo *cmh_info = &(cmh_entry->info);
  EXPECT_TRUE(cmh_info->eck_priv_key);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
  struct Dot2EECertContents *contents = &(cmh_info->cert_contents);
  // EXPECT_TRUE(Dot2Test_CompareOctets(contents->verify_pub_key.u.octs, pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN)); // CMH/CMHF에 공개키는 저장되지 않음.
  EXPECT_FALSE(contents->eck_verify_pub_key);
  struct Dot2CertCommonContents *common = &(contents->common);
  EXPECT_EQ(common->type, cert_type);
  EXPECT_EQ(common->issuer.type, issuer_type);
  EXPECT_TRUE(Dot2Test_CompareOctets(common->issuer.h8, issuer_h8, 8));
  EXPECT_EQ(common->id.type, cert_id_type);
  EXPECT_EQ(common->id.u.binary_id.len, cert_id_len);
  EXPECT_TRUE(Dot2Test_CompareOctets(common->id.u.binary_id.id, binary_id, cert_id_len));
  EXPECT_TRUE(Dot2Test_CompareOctets(common->craca_id, craca_id, sizeof(craca_id)));
  EXPECT_EQ(common->crl_series, crl_series);
  EXPECT_EQ(common->valid_start, valid_start);
  EXPECT_EQ(common->valid_end, valid_end);
  EXPECT_EQ(common->valid_region.type, region_type);
  EXPECT_EQ(common->valid_region.u.id.num, region_id_num);
  EXPECT_EQ(common->valid_region.u.id.country[0], region_id_0);
  EXPECT_EQ(common->valid_region.u.id.country[1], region_id_1);
  // EXPECT_EQ((int)common->verify_key_indicator.type, kDot2CertVerificationKeyIndicatorType_ReconstructValue); // CMH/CMHF에 공개키재구성값은 저장되지 않는다.
  // EXPECT_TRUE(Dot2Test_CompareOctets(common->verify_key_indicator.key.u.octs, recon_pub.u.octs, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  EXPECT_FALSE(common->enc_pub_key_present);
  struct Dot2EECertPermissions *perms = &(contents->app_perms);
  EXPECT_EQ(perms->psid_num, psid_num);
  EXPECT_EQ(perms->psid[0], psid_0);
  if (cmh_entry->cert_size != cert_size) { return false; }
  if (!cmh_entry->cert) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->cert, cert, cert_size)) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN)) { return false; }
  if (!cmh_entry->issuer) { return false; }
  if (!cmh_entry->asn1_cert) { return false; }
  if (!cmh_info->eck_priv_key) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN)) { return false; }
  if (contents->eck_verify_pub_key) { return false; }
  if (common->type != cert_type) { return false; }
  if (common->issuer.type != issuer_type) { return false; }
  if (!Dot2Test_CompareOctets(common->issuer.h8, issuer_h8, 8)) { return false; }
  if (common->id.type != cert_id_type) { return false; }
  if (common->id.u.binary_id.len != cert_id_len) { return false; }
  if (!Dot2Test_CompareOctets(common->id.u.binary_id.id, binary_id, cert_id_len)) { return false; }
  if (!Dot2Test_CompareOctets(common->craca_id, craca_id, sizeof(craca_id))) { return false; }
  if (common->crl_series != crl_series) { return false; }
  if (common->valid_start != valid_start) { return false; }
  if (common->valid_end != valid_end) { return false; }
  if (common->valid_region.type != region_type) { return false; }
  if (common->valid_region.u.id.num != region_id_num) { return false; }
  if (common->valid_region.u.id.country[0] != region_id_0) { return false; }
  if (common->valid_region.u.id.country[1] != region_id_1) { return false; }
  if (common->enc_pub_key_present) { return false; }
  if (perms->psid_num != psid_num) { return false; }
  if (perms->psid[0] != psid_0) { return false; }
  if (perms->psid[1] != psid_1) { return false; }
  if (perms->psid[2] != psid_2) { return false; }
  return true;
}


/*
 * Identification cert 0 의 CMHSetEntry 정보 유효성을 체크한다.
 */
bool Dot2Test_Check_CertBundle_1_IdCert_0_CMHSetEntry(struct Dot2RotateCMHSetEntry *cmh_entry)
{
  uint32_t i = 0;
  Dot2RotateCMHInfoNum cmh_info_num = kDot2RotateCMHInfoNum_IdCertDefault;
  Dot2CertType cert_type = kDot2CertType_Implicit;
  Dot2CertIssuerIdentifierType issuer_type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  const char *issuer_h8_str = "2ABAD5E80D25DA1B";
  const char *binary_id_str = "035254529020DC4D";
  Dot2CertIdType cert_id_type = kDot2CertIdType_BinaryId;
  Dot2CertBinaryIdLen cert_id_len = kDot2CertBinaryIdLen_Default;
  const char *craca_id_str = "25DA1B";
  Dot2CertCRLSeries crl_series = 3;
  Dot2Time64 valid_start = 347619603000000ULL;
  Dot2Time64 valid_end = 348228003000000ULL;
  Dot2CertValidRegionType region_type = kDot2CertValidRegionType_Identified;
  Dot2IdentifiedRegionNum region_id_num = 1;
  Dot2CountryCode region_id_0 = 410;
  Dot2CertPermissionNum psid_num = 3;
  Dot2PSID psid_0 = 32;
  Dot2PSID psid_1 = 35;
  Dot2PSID psid_2 = 135;

  uint8_t cert[kDot2CertSize_Max], binary_id[kDot2CertBinaryIdLen_Default], craca_id[DOT2_CRACA_ID_LEN], issuer_h8[8];
  Dot2CertSize cert_size;
  struct Dot2SHA256 cert_h{};
  struct Dot2ECPrivateKey priv_key{};
  struct Dot2ECPublicKey pub_key{}, recon_pub{};
  struct Dot2RotateCMHInfo *cmh_info;

  // 테스트벡터 변환
  EXPECT_EQ(cert_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0, cert), g_tv_bundle_1_id_cert_0_size);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_h, cert_h.octs), DOT2_SHA_256_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(issuer_h8_str, issuer_h8), 8);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(craca_id_str, craca_id), DOT2_CRACA_ID_LEN);
  EXPECT_EQ(Dot2Test_ConvertHexStrToOctets(binary_id_str, binary_id), (int)cert_id_len);

  // 엔트리 정보 확인
  EXPECT_EQ(cmh_entry->info_num, cmh_info_num);
  EXPECT_EQ(cmh_entry->max_info_num, cmh_info_num);
  EXPECT_FALSE(cmh_entry->active_cmh);
  EXPECT_TRUE(cmh_entry->issuer);
  if (cmh_entry->info_num != cmh_info_num) { return false; }
  if (cmh_entry->max_info_num != cmh_info_num) { return false; }
  if (cmh_entry->active_cmh) { return false; }
  if (!cmh_entry->issuer) { return false; }

  // 공통정보 확인
  EXPECT_EQ(cmh_entry->common.i, i);
  EXPECT_EQ(cmh_entry->common.type, cert_type);
  EXPECT_EQ(cmh_entry->common.issuer.type, issuer_type);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->common.issuer.h8, issuer_h8, 8));
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_entry->common.craca_id, craca_id, sizeof(craca_id)));
  EXPECT_EQ(cmh_entry->common.crl_series, crl_series);
  EXPECT_EQ(cmh_entry->common.valid_start, valid_start);
  EXPECT_EQ(cmh_entry->common.valid_end, valid_end);
  EXPECT_EQ(cmh_entry->common.valid_region.type, region_type);
  EXPECT_EQ(cmh_entry->common.valid_region.u.id.num, region_id_num);
  EXPECT_EQ(cmh_entry->common.valid_region.u.id.country[0], region_id_0);
  EXPECT_EQ(cmh_entry->common.psid_num, psid_num);
  EXPECT_EQ(cmh_entry->common.psid[0], psid_0);
  EXPECT_EQ(cmh_entry->common.psid[1], psid_1);
  EXPECT_EQ(cmh_entry->common.psid[2], psid_2);
  if (cmh_entry->common.i != i) { return false; }
  if (cmh_entry->common.type != cert_type) { return false; }
  if (cmh_entry->common.issuer.type != issuer_type) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->common.issuer.h8, issuer_h8, 8)) { return false; }
  if (!Dot2Test_CompareOctets(cmh_entry->common.craca_id, craca_id, sizeof(craca_id))) { return false; }
  if (cmh_entry->common.crl_series != crl_series) { return false; }
  if (cmh_entry->common.valid_start != valid_start) { return false; }
  if (cmh_entry->common.valid_end != valid_end) { return false; }
  if (cmh_entry->common.valid_region.type != region_type) { return false; }
  if (cmh_entry->common.valid_region.u.id.num != region_id_num) { return false; }
  if (cmh_entry->common.valid_region.u.id.country[0] != region_id_0) { return false; }
  if (cmh_entry->common.psid_num != psid_num) { return false; }
  if (cmh_entry->common.psid[0] != psid_0) { return false; }
  if (cmh_entry->common.psid[1] != psid_1) { return false; }
  if (cmh_entry->common.psid[2] != psid_2) { return false; }

  // 개별 CMH 정보 확인
  cmh_info = &(cmh_entry->cmh[0]);
  EXPECT_TRUE(cmh_info->cert);
  EXPECT_EQ(cmh_info->cert_size, cert_size);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->cert, cert, cert_size));
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN));
  EXPECT_TRUE(cmh_info->asn1_cert);
  EXPECT_EQ(cmh_info->info.id.type, cert_id_type);
  EXPECT_EQ(cmh_info->info.id.u.binary_id.len, cert_id_len);
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->info.id.u.binary_id.id, binary_id, cert_id_len));
  EXPECT_TRUE(Dot2Test_CompareOctets(cmh_info->info.priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
  EXPECT_TRUE(cmh_info->info.eck_priv_key);

  if (!cmh_info->cert) { return false; }
  if (cmh_info->cert_size != cert_size) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->cert, cert, cert_size)) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->cert_h.octs, cert_h.octs, DOT2_SHA_256_LEN)) { return false; }
  if (!cmh_info->asn1_cert) { return false; }
  if (cmh_info->info.id.type != cert_id_type) { return false; }
  if (cmh_info->info.id.u.binary_id.len != cert_id_len) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->info.id.u.binary_id.id, binary_id, cert_id_len)) { return false; }
  if (!Dot2Test_CompareOctets(cmh_info->info.priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN)) { return false; }
  if (!cmh_info->info.eck_priv_key) { return false; }

  return true;
}

