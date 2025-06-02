/** 
  * @file 
  * @brief 단위테스트에서 사용되는 SCC 인증서 테스트벡터 정의
  * @date 2022-07-02 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stddef.h>
#include <stdint.h>


/* RCA(RootCA) 인증서 테스트벡터
rec1value CertificateBase ::= {
  version 3,
  type explicit,
  issuer self : sha256,
  toBeSigned {
    id name : "rootca.scms.tta.or.kr",
    cracaId '000000'H,
    crlSeries 0,
    validityPeriod {
      start 545377686,
      duration years : 70
    },
    appPermissions {
      {
        psid 35,
        ssp opaque : '810001'H
      },
      {
        psid 256,
        ssp opaque : '00010001010100'H
      }
    },
    certIssuePermissions {
      {
        subjectPermissions all : NULL,
        minChainLength 3,
        chainLengthRange -1,
        eeType '11000000'B
      },
      {
        subjectPermissions explicit : {
          {
            psid 35
          }
        },
        minChainLength 1,
        chainLengthRange -1,
        eeType '11000000'B
      },
      {
        subjectPermissions explicit : {
          {
            psid 38
          }
        },
        minChainLength 1,
        chainLengthRange -1,
        eeType '11000000'B
      },
      {
        subjectPermissions explicit : {
          {
            psid 256
          }
        },
        minChainLength 1,
        chainLengthRange -1,
        eeType '11000000'B
      }
    },
    verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-1 : 'C2E054303D4ACBB7DF2F7104A713A1C59727CE8B0725F87AB691F23307702142'H
  },
  signature ecdsaNistP256Signature : {
    rSig x-only : '60C63464E0AD4F81C55D2B09E5FA7468C920FEFBEFEA50FE6B9A5D9FB14A6470'H,
    sSig '22726F3A1F0022F2001F5F402B9D99A565D3DA5E397734BF01321E9E324CFE54'H
  }
}
 */
const char *g_tv_rca_cert = "8003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe54";
size_t g_tv_rca_cert_size = 205; // 바이트열 길이 (문자열 길이 X)
unsigned int g_tv_rca_cert_type = 0; // = Explicit
unsigned int g_tv_rca_cert_issuer_id_type = 1; // = Self
unsigned int g_tv_rca_cert_id_type = 1; // = name
const char *g_tv_rca_cert_id_name = "rootca.scms.tta.or.kr";
const char *g_tv_rca_cert_craca_id = "000000";
unsigned int g_tv_rca_cert_crl_series = 0;
uint64_t g_tv_rca_cert_valid_start = 545377686000000ull;
uint64_t g_tv_rca_cert_valid_end = 2752897686000000ull;
unsigned int g_tv_rca_cert_valid_region_type = 0; // = None
bool g_tv_rca_cert_enc_pub_key_present = false;
unsigned int g_tv_rca_cert_key_indicator_type = 0; // 공개키
const char *g_tv_rca_cert_key_indicator = "03C2E054303D4ACBB7DF2F7104A713A1C59727CE8B0725F87AB691F23307702142"; // 맨앞에 형식정보(0x03=compressed-y-1) 추가
const char *g_tv_rca_cert_pub_key_uncomp = "04C2E054303D4ACBB7DF2F7104A713A1C59727CE8B0725F87AB691F23307702142C124E8D59978BF0262B2C1092E67E00F3A2F1A92C2314DE7887D8B5556C8CA1D"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
const char *g_tv_rca_cert_sig_r = "60C63464E0AD4F81C55D2B09E5FA7468C920FEFBEFEA50FE6B9A5D9FB14A6470";
const char *g_tv_rca_cert_sig_s = "22726F3A1F0022F2001F5F402B9D99A565D3DA5E397734BF01321E9E324CFE54";
const char *g_tv_rca_cert_h = "215e3166522662ef49e8836427a391d247575e3adf624a9129cb66724dd2776c"; // from https://emn178.github.io/online-tools/sha256.html
const char *g_tv_rca_cert_tbs = "188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142";
size_t g_tv_rca_cert_tbs_size = 134;


/* ICA 인증서 테스트벡터
rec1value CertificateBase ::= {
  version 3,
  type explicit,
  issuer sha256AndDigest : '29CB66724DD2776C'H,
  toBeSigned {
    id name : "ica.scms.tta.or.kr",
    cracaId 'D2776C'H,
    crlSeries 2,
    validityPeriod {
      start 545377686,
      duration years : 20
    },
    region identifiedRegion : {
      countryOnly : 410,
      countryOnly : 124,
      countryOnly : 484,
      countryOnly : 840,
      countryOnly : 724,
      countryOnly : 276,
      countryOnly : 826
    },
    appPermissions {
      {
        psid 35,
        ssp opaque : '830001'H
      }
    },
    certIssuePermissions {
      {
        subjectPermissions all : NULL,
        minChainLength 2,
        chainLengthRange 0,
        eeType '11000000'B
      },
      {
        subjectPermissions explicit : {
          {
            psid 35,
            sspRange all : NULL
          },
          {
            psid 256,
            sspRange all : NULL
          }
        },
        minChainLength 1,
        chainLengthRange -1,
        eeType '11000000'B
      }
    },
    verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : '6E39058A1016DA43241E1BB0DA487C70800FEBEFB293DAB5C43760EA58B425C7'H
  },
  signature ecdsaNistP256Signature : {
    rSig x-only : 'CF7EA3E91A5C539141EF0D5A7F3BA2E75FAF8C438EF51B4659E8EDF1E505C7D3'H,
    sSig '79D35262F8F80FA3D32EC5BC4A70F4F63ECD467700757D1FAC260778ADF6256F'H
  }
}
*/
const char *g_tv_ica_cert = "8003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f";
size_t g_tv_ica_cert_size = 203; // 바이트열 길이 (문자열 길이 X)
unsigned int g_tv_ica_cert_type = 0; // = Explicit
unsigned int g_tv_ica_cert_issuer_id_type = 0; // = Issuer's H8
const char *g_tv_ica_cert_issuer_h8 = "29CB66724DD2776C";
unsigned int g_tv_ica_cert_id_type = 1; // = name
const char *g_tv_ica_cert_id_name = "ica.scms.tta.or.kr";
const char *g_tv_ica_cert_craca_id = "D2776C";
unsigned int g_tv_ica_cert_crl_series = 2;
uint64_t g_tv_ica_cert_valid_start = 545377686000000ull;
uint64_t g_tv_ica_cert_valid_end = 1176097686000000ull;
unsigned int g_tv_ica_cert_valid_region_type = 2; // = Identified
unsigned int g_tv_ica_cert_valid_region_num = 7;
uint16_t g_tv_ica_cert_valid_region[7] = {410,124,484,840,724,276,826};
bool g_tv_ica_cert_enc_pub_key_present = false;
unsigned int g_tv_ica_cert_key_indicator_type = 0; // 공개키
const char *g_tv_ica_cert_key_indicator = "026E39058A1016DA43241E1BB0DA487C70800FEBEFB293DAB5C43760EA58B425C7"; // 맨앞에 형식정보(0x02=compressed-y-0) 추가
const char *g_tv_ica_cert_pub_key_uncomp = "046E39058A1016DA43241E1BB0DA487C70800FEBEFB293DAB5C43760EA58B425C7D5827A8C7131BCC8281B325FBE9A51FC4F39A37E3882C3E4F565746B79F8D52A"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
const char *g_tv_ica_cert_sig_r = "CF7EA3E91A5C539141EF0D5A7F3BA2E75FAF8C438EF51B4659E8EDF1E505C7D3";
const char *g_tv_ica_cert_sig_s = "79D35262F8F80FA3D32EC5BC4A70F4F63ECD467700757D1FAC260778ADF6256F";
const char *g_tv_ica_cert_h = "dafba8c3fea7d16df40b2cddd2b69e62a78f65b6ffbf723f9d195826018fbb38"; // from https://emn178.github.io/online-tools/sha256.html
const char *g_tv_ica_cert_tbs = "5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c7";
size_t g_tv_ica_cert_tbs_size = 125;


/* PCA/ACA 인증서 테스트벡터
rec1value CertificateBase ::= {
  version 3,
  type explicit,
  issuer sha256AndDigest : '9D195826018FBB38'H,
  toBeSigned {
    id name : "pca.scms.tta.or.kr",
    cracaId 'D2776C'H,
    crlSeries 2,
    validityPeriod {
      start 545377689,
      duration years : 6
    },
    region identifiedRegion : {
      countryOnly : 410,
      countryOnly : 124,
      countryOnly : 484,
      countryOnly : 840,
      countryOnly : 724,
      countryOnly : 276,
      countryOnly : 826
    },
    appPermissions {
      {
        psid 35,
        ssp opaque : '850001'H
      }
    },
    certIssuePermissions {
      {
        subjectPermissions all : NULL,
        minChainLength 1,
        chainLengthRange 0,
        eeType '10000000'B
      }
    },
    encryptionKey {
      supportedSymmAlg aes128Ccm,
      publicKey eciesNistP256 : compressed-y-1 : '0194606EC293A217FD120A52D4EB26A525439D570BCD4DD8F4B033447DA98877'H
    },
    verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : '2B9BCCBA5FB35168EA829A8C55C959CDDD1A8DF6E96A22566ED4E3066388D1FC'H
  },
  signature ecdsaNistP256Signature : {
    rSig x-only : 'C7D9E9D504A4ED3ED0ACFDFEEFC2294D2EB5E239123DDE6FA6E587788D0FF5D7'H,
    sSig 'DE326E46F419EF5A53367D806138531D3E36C85A647EB3CE9F65F4BDA8B02ECD'H
  }
}
 */
const char *g_tv_pca_cert = "800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd";
size_t g_tv_pca_cert_size = 219; // 바이트열 길이 (문자열 길이 X)
unsigned int g_tv_pca_cert_type = 0; // = Explicit
unsigned int g_tv_pca_cert_issuer_id_type = 0; // = Issuer's H8
const char *g_tv_pca_cert_issuer_h8 = "9D195826018FBB38";
unsigned int g_tv_pca_cert_id_type = 1; // = name
const char *g_tv_pca_cert_id_name = "pca.scms.tta.or.kr";
const char *g_tv_pca_cert_craca_id = "D2776C";
unsigned int g_tv_pca_cert_crl_series = 2;
uint64_t g_tv_pca_cert_valid_start = 545377689000000ull;
uint64_t g_tv_pca_cert_valid_end = 734593689000000ull;
unsigned int g_tv_pca_cert_valid_region_type = 2; // = Identified
unsigned int g_tv_pca_cert_valid_region_num = 7;
uint16_t g_tv_pca_cert_valid_region[7] = {410,124,484,840,724,276,826};
bool g_tv_pca_cert_enc_pub_key_present = true;
const char *g_tv_pca_cert_enc_pub_key = "030194606EC293A217FD120A52D4EB26A525439D570BCD4DD8F4B033447DA98877"; // 맨앞에 형식정보(0x03=compressed-y-1) 추가
const char *g_tv_pca_cert_enc_pub_key_uncomp = "040194606EC293A217FD120A52D4EB26A525439D570BCD4DD8F4B033447DA988774C41DD59499D1F7C4FD5A3C38464B64412E15E7D34CD4DEB7AC388A55C8148CB"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
unsigned int g_tv_pca_cert_key_indicator_type = 0; // 공개키
const char *g_tv_pca_cert_key_indicator = "022B9BCCBA5FB35168EA829A8C55C959CDDD1A8DF6E96A22566ED4E3066388D1FC"; // 맨앞에 형식정보(0x02=compressed-y-0) 추가
const char *g_tv_pca_cert_pub_key_uncomp = "042B9BCCBA5FB35168EA829A8C55C959CDDD1A8DF6E96A22566ED4E3066388D1FC74F41469609AB7CB317DDCC470EB4F582EF20CE4B650E2723815D805F51A1702"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
const char *g_tv_pca_cert_sig_r = "C7D9E9D504A4ED3ED0ACFDFEEFC2294D2EB5E239123DDE6FA6E587788D0FF5D7";
const char *g_tv_pca_cert_sig_s = "DE326E46F419EF5A53367D806138531D3E36C85A647EB3CE9F65F4BDA8B02ECD";
const char *g_tv_pca_cert_h = "4f6e03271b2b76721ecfb7bac3e2ff114176dc9ac42023f0d2ebc6a2ce83fc16"; // from https://emn178.github.io/online-tools/sha256.html
const char *g_tv_pca_cert_tbs = "5981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc";
size_t g_tv_pca_cert_tbs_size = 141;


/* ECA 인증서 테스트벡터
rec1value CertificateBase ::= {
  version 3,
  type explicit,
  issuer sha256AndDigest : '9D195826018FBB38'H,
  toBeSigned {
    id name : "eca.scms.tta.or.kr",
    cracaId 'D2776C'H,
    crlSeries 2,
    validityPeriod {
      start 545377690,
      duration years : 10
    },
    region identifiedRegion : {
      countryOnly : 410,
      countryOnly : 124,
      countryOnly : 484,
      countryOnly : 840,
      countryOnly : 724,
      countryOnly : 276,
      countryOnly : 826
    },
    appPermissions {
      {
        psid 35,
        ssp opaque : '840001'H
      }
    },
    certIssuePermissions {
      {
        subjectPermissions all : NULL,
        minChainLength 1,
        chainLengthRange 0,
        eeType '01000000'B
      }
    },
    encryptionKey {
      supportedSymmAlg aes128Ccm,
      publicKey eciesNistP256 : compressed-y-0 : '689493F5C0653F08AF01059D7A30DB52F89B849D2FFC7D090B8E8859A482E245'H
    },
    verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : '2A4056DC0C33B7E64CC29CF95EE74CD6012F6BA162A40F72652713DB97D4B98C'H
  },
  signature ecdsaNistP256Signature : {
    rSig x-only : '65CAD5AA1EBAC67C8456C01A4231621CA76F16834963AA4DA616EFD7630C35D9'H,
    sSig '0025A9E8DE74EA479AA40A2E0672DF31D9A003BF3D9F565992797391D430AF47'H
  }
}
 */
const char *g_tv_eca_cert = "800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47";
size_t g_tv_eca_cert_size = 220; // 바이트열 길이 (문자열 길이 X)
unsigned int g_tv_eca_cert_type = 0; // = Explicit
unsigned int g_tv_eca_cert_issuer_id_type = 0; // = Issuer's H8
const char *g_tv_eca_cert_issuer_h8 = "9D195826018FBB38";
unsigned int g_tv_eca_cert_id_type = 1; // = name
const char *g_tv_eca_cert_id_name = "eca.scms.tta.or.kr";
const char *g_tv_eca_cert_craca_id = "D2776C";
unsigned int g_tv_eca_cert_crl_series = 2;
uint64_t g_tv_eca_cert_valid_start = 545377690000000ull;
uint64_t g_tv_eca_cert_valid_end = 860737690000000ull;
unsigned int g_tv_eca_cert_valid_region_type = 2; // = Identified
unsigned int g_tv_eca_cert_valid_region_num = 7;
uint16_t g_tv_eca_cert_valid_region[7] = {410,124,484,840,724,276,826};
bool g_tv_eca_cert_enc_pub_key_present = true;
const char *g_tv_eca_cert_enc_pub_key = "02689493F5C0653F08AF01059D7A30DB52F89B849D2FFC7D090B8E8859A482E245"; // 맨앞에 형식정보(0x02=compressed-y-0) 추가
const char *g_tv_eca_cert_enc_pub_key_uncomp = "04689493F5C0653F08AF01059D7A30DB52F89B849D2FFC7D090B8E8859A482E2454D7E9B100F8E9E452CCEE0DA862D414B80EFF96AD8CE0FDEB6B155B3E8956AEE"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
unsigned int g_tv_eca_cert_key_indicator_type = 0; // 공개키
const char *g_tv_eca_cert_key_indicator = "022A4056DC0C33B7E64CC29CF95EE74CD6012F6BA162A40F72652713DB97D4B98C"; // 맨앞에 형식정보(0x02=compressed-y-0) 추가
const char *g_tv_eca_cert_pub_key_uncomp = "042A4056DC0C33B7E64CC29CF95EE74CD6012F6BA162A40F72652713DB97D4B98CABF216ECEAFAB3D416ED74579F832913F64AFBEE5ADB203351DAD523527C6088"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
const char *g_tv_eca_cert_sig_r = "65CAD5AA1EBAC67C8456C01A4231621CA76F16834963AA4DA616EFD7630C35D9";
const char *g_tv_eca_cert_sig_s = "0025A9E8DE74EA479AA40A2E0672DF31D9A003BF3D9F565992797391D430AF47";
const char *g_tv_eca_cert_h = "1eecc7746b61e0a065103349a4f7a76b00f19cc2e34cf8b36eb4e93ea62b3181"; // from https://emn178.github.io/online-tools/sha256.html
const char *g_tv_eca_cert_tbs = "5981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c";
size_t g_tv_eca_cert_tbs_size = 142;


/* RA 인증서 테스트벡터
rec1value CertificateBase ::= {
  version 3,
  type explicit,
  issuer sha256AndDigest : '9D195826018FBB38'H,
  toBeSigned {
    id name : "ra.scms.tta.or.kr",
    cracaId 'D2776C'H,
    crlSeries 2,
    validityPeriod {
      start 545377690,
      duration years : 3
    },
    region identifiedRegion : {
      countryOnly : 410,
      countryOnly : 124,
      countryOnly : 484,
      countryOnly : 840,
      countryOnly : 724,
      countryOnly : 276,
      countryOnly : 826
    },
    appPermissions {
      {
        psid 35,
        ssp opaque : '8B0001'H
      }
    },
    certRequestPermissions {
      {
        subjectPermissions all : NULL,
        minChainLength 0,
        chainLengthRange 0,
        eeType '10000000'B
      }
    },
    encryptionKey {
      supportedSymmAlg aes128Ccm,
      publicKey eciesNistP256 : compressed-y-0 : 'D7B33F85D4293F67AD43D3AE217864EDA5FF5E91A9586B0E070439DE0D0017B9'H
    },
    verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : 'A2283219090EE0EC99A98C06F88273F421DCEEF3361CDF22B3F56BB22E1CED49'H
  },
  signature ecdsaNistP256Signature : {
    rSig x-only : '0FF5A3913F4F52605D4B6A202C364901215F33096E9AD829ABE4DF1EB2D6B97B'H,
    sSig 'D06F5C12072079627483B9F70B0AD421AFF68A159516060C5CB318EAC17E2F3A'H
  }
}
 */
const char *g_tv_ra_cert = "800300809d195826018fbb3855811172612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000383010780019a80007c8001e48003488002d480011480033a010180012380038b0001010180810100008082d7b33f85d4293f67ad43d3ae217864eda5ff5e91a9586b0e070439de0d0017b9808082a2283219090ee0ec99a98c06f88273f421dceef3361cdf22b3f56bb22e1ced4980800ff5a3913f4f52605d4b6a202c364901215f33096e9ad829abe4df1eb2d6b97bd06f5c12072079627483b9f70b0ad421aff68a159516060c5cb318eac17e2f3a";
size_t g_tv_ra_cert_size = 220; // 바이트열 길이 (문자열 길이 X)
unsigned int g_tv_ra_cert_type = 0; // = Explicit
unsigned int g_tv_ra_cert_issuer_id_type = 0; // = Issuer's H8
const char *g_tv_ra_cert_issuer_h8 = "9D195826018FBB38";
unsigned int g_tv_ra_cert_id_type = 1; // = name
const char *g_tv_ra_cert_id_name = "ra.scms.tta.or.kr";
const char *g_tv_ra_cert_craca_id = "D2776C";
unsigned int g_tv_ra_cert_crl_series = 2;
uint64_t g_tv_ra_cert_valid_start = 545377690000000ull;
uint64_t g_tv_ra_cert_valid_end = 639985690000000ull;
unsigned int g_tv_ra_cert_valid_region_type = 2; // = Identified
unsigned int g_tv_ra_cert_valid_region_num = 7;
uint16_t g_tv_ra_cert_valid_region[7] = {410,124,484,840,724,276,826};
bool g_tv_ra_cert_enc_pub_key_present = true;
const char *g_tv_ra_cert_enc_pub_key = "02D7B33F85D4293F67AD43D3AE217864EDA5FF5E91A9586B0E070439DE0D0017B9"; // 맨앞에 형식정보(0x02=compressed-y-0) 추가
const char *g_tv_ra_cert_enc_pub_key_uncomp = "04D7B33F85D4293F67AD43D3AE217864EDA5FF5E91A9586B0E070439DE0D0017B9000987ADE24D00D3D90F0C36783860D3345324711055DD00E697DD2BFE38C8BA"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
unsigned int g_tv_ra_cert_key_indicator_type = 0; // 공개키
const char *g_tv_ra_cert_key_indicator = "02A2283219090EE0EC99A98C06F88273F421DCEEF3361CDF22B3F56BB22E1CED49"; // 맨앞에 형식정보(0x02=compressed-y-0) 추가
const char *g_tv_ra_cert_pub_key_uncomp = "04A2283219090EE0EC99A98C06F88273F421DCEEF3361CDF22B3F56BB22E1CED498360D65DFFFDC02FBAA95D1643A55B5C2B6BEA2E1C0588C7C41BC6972A5E7320"; // 검증된 dot2 라이브러리의 y-recovery 기능을 통해 생성
const char *g_tv_ra_cert_sig_r = "0FF5A3913F4F52605D4B6A202C364901215F33096E9AD829ABE4DF1EB2D6B97B";
const char *g_tv_ra_cert_sig_s = "D06F5C12072079627483B9F70B0AD421AFF68A159516060C5CB318EAC17E2F3A";
const char *g_tv_ra_cert_h = "a1dbd18e6476e08ba7a2c5d1ef6271028269357f3e872678077c211c5c49e2d4"; // from https://emn178.github.io/online-tools/sha256.html
const char *g_tv_ra_cert_tbs = "55811172612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000383010780019a80007c8001e48003488002d480011480033a010180012380038b0001010180810100008082d7b33f85d4293f67ad43d3ae217864eda5ff5e91a9586b0e070439de0d0017b9808082a2283219090ee0ec99a98c06f88273f421dceef3361cdf22b3f56bb22e1ced49";
size_t g_tv_ra_cert_tbs_size = 142;
