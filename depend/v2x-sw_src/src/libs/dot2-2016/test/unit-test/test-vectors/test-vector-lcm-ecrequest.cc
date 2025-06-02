/** 
  * @file 
  * @brief 등록인증서 발급요청문 관련 테스트벡터
  * @date 2022-05-01 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stddef.h>
#include <stdint.h>


/*
 * 등록인증서 발급 테스트벡터 #1 (TTA가 보유한 아우토크립트 서버)
 */

/*
rec1value SignedEeEnrollmentCertRequest ::= {
  protocolVersion 3,
  content signedCertificateRequest : CONTAINING {
    hashId sha256,
    tbsRequest {
      version 1,
      content eca-ee : eeEcaCertRequest : {
        version 1,
        currentTime 581219273,
        tbsData {
          id name : "",
          cracaId '000000'H,
          crlSeries 4,
          validityPeriod {
            start 581219273,
            duration years : 6
          },
          region identifiedRegion : {
            countryOnly : 410
          },
          certRequestPermissions {
            {
              subjectPermissions explicit : {
                {
                  psid 32
                },
                {
                  psid 35
                },
                {
                  psid 135
                }
              },
              minChainLength 0,
              chainLengthRange 0,
              eeType '10000000'B
            }
          },
          verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-1 : '5B1DB3F8652600A66CE1159608AC85A271DED805D7CF4BB8D34137323C4D0F77'H
        }
      }
    },
    signer self : NULL,
    signature ecdsaNistP256Signature : {
      rSig compressed-y-1 : 'EC94655D8D5210D23B7ADC9CE6D9E54A6C71721DC3EDB963BAEACBD58EC5B971'H,
      sSig '8CCA34F8B069692D27E43980FADA2A7090EE7F295531EE81677044B0CA8E2D7A'H
    }
  }
}
 */
const char *g_tv_ecreq_1 = "0383819600018180000122a4b3c9448100000000000422a4b3c986000683010180019a01018080010300012000012300018701008080835b1db3f8652600a66ce1159608ac85a271ded805d7cf4bb8d34137323c4d0f77828083ec94655d8d5210d23b7adc9ce6d9e54a6c71721dc3edb963baeacbd58ec5b9718cca34f8b069692d27e43980fada2a7090ee7f295531ee81677044b0ca8e2d7a";
size_t g_tv_ecreq_size_1 = 154;
const char *g_tv_ecreq_init_priv_key_1 = "f37cf1b7a3f163a9ce7efdf09228b1fbe4a7ebe7daf89295b45da49f7bbc5ea2";
const char *g_tv_ecreq_init_pub_key_1 = "045b1db3f8652600a66ce1159608ac85a271ded805d7cf4bb8d34137323c4d0f777004d65c666cc248fa74b7110537eccb0e3320a4aa52e1df69e53b632d3b9453";
const char *g_tv_ecreq_h8_1 = "ada6a74d1fd0aa12"; // 현재 아우토크립트 서버가 response 메시지에 넣은 requestHash는 잘못된 값이 들어 있다.

/*
rec1value SignedEeEnrollmentCertResponse ::= {
  protocolVersion 3,
  content signedData : {
    hashId sha256,
    tbsData {
      payload {
        data {
          protocolVersion 3,
          content unsecuredData : CONTAINING {
            version 1,
            content eca-ee : ecaEeCertResponse : {
              version 1,
              requestHash 'F910416EA9D27287'H,
              ecaCert {
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
              },
              enrollmentCert {
                version 3,
                type implicit,
                issuer sha256AndDigest : '6EB4E93EA62B3181'H,
                toBeSigned {
                  id name : "",
                  cracaId 'D2776C'H,
                  crlSeries 4,
                  validityPeriod {
                    start 581219273,
                    duration years : 6
                  },
                  region identifiedRegion : {
                    countryOnly : 410
                  },
                  certRequestPermissions {
                    {
                      subjectPermissions explicit : {
                        {
                          psid 32
                        },
                        {
                          psid 35
                        },
                        {
                          psid 135
                        }
                      },
                      minChainLength 0,
                      chainLengthRange 0,
                      eeType '10000000'B
                    }
                  },
                  verifyKeyIndicator reconstructionValue : compressed-y-0 : '8C35433470E7E5A7084B976E6150931150E4ABED46B258D5E974C377DCFC7AB4'H
                }
              },
              privKeyReconstruction '455BF0E3A8D8FA6D6BF6482253FCF45ABCF0527FEA600426341D7F447EE6F293'H
            }
          }
        }
      },
      headerInfo {
        psid 35
      }
    },
    signer certificate : {
      {
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
    },
    signature ecdsaNistP256Signature : {
      rSig x-only : 'FC388ED5EA0A1601C3650BE40B2C82D73C88B5CEF5136CD2B1225D4C3EBFBACF'H,
      sSig 'F33964D32D55BBB42B739D77863A5284820C3CCEDFCE2F75F9B4F1CEF308BAA1'H
    }
  }
}
 */
const char *g_tv_ecresp_1 = "03810040038082015d0181810001f910416ea9d27287800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47000301806eb4e93ea62b3181448100d2776c000422a4b3c986000683010180019a010180800103000120000123000187010081828c35433470e7e5a7084b976e6150931150e4abed46b258d5e974c377dcfc7ab4455bf0e3a8d8fa6d6bf6482253fcf45abcf0527fea600426341d7f447ee6f293000123810101800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af478080fc388ed5ea0a1601c3650be40b2c82d73c88b5cef5136cd2b1225d4c3ebfbacff33964d32d55bbb42b739d77863a5284820c3ccedfce2f75f9b4f1cef308baa1";
size_t g_tv_ecresp_size_1 = 650;
const char *g_tv_ecresp_enroll_cert_1 = "000301806eb4e93ea62b3181448100d2776c000422a4b3c986000683010180019a010180800103000120000123000187010081828c35433470e7e5a7084b976e6150931150e4abed46b258d5e974c377dcfc7ab4";
size_t g_tv_ecresp_enroll_cert_size_1 = 84;
const char *g_tv_ecresp_recon_priv_1 = "455BF0E3A8D8FA6D6BF6482253FCF45ABCF0527FEA600426341D7F447EE6F293";
const char *g_tv_ecresp_eca_cert_1 = "800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47";
size_t g_tv_ecresp_eca_cert_size_1 = 220;
const char *g_tv_ecresp_ra_cert_1 = "800300809d195826018fbb3855811172612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000383010780019a80007c8001e48003488002d480011480033a010180012380038b0001010180810100008082d7b33f85d4293f67ad43d3ae217864eda5ff5e91a9586b0e070439de0d0017b9808082a2283219090ee0ec99a98c06f88273f421dceef3361cdf22b3f56bb22e1ced4980800ff5a3913f4f52605d4b6a202c364901215f33096e9ad829abe4df1eb2d6b97bd06f5c12072079627483b9f70b0ad421aff68a159516060c5cb318eac17e2f3a";
size_t g_tv_ecresp_ra_cert_size_1 = 220;
const char *g_tv_ecresp_rca_cert_1 = "8003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe54";
size_t g_tv_ecresp_rca_cert_size_1 = 205;

/*
rec1value ScopedLocalCertificateChainFile ::= {
  version 1,
  content cert-chain : localCertificateChainFile : {
    version {
      gccfVersion 1,
      lccfVersion 1,
      raHostname "ra.scms.tta.or.kr"
    },
    requiredCertStore {
      rootCAEndorsements {
      },
      electorEndorsements {
      },
      maCertificate {
        version 3,
        type explicit,
        issuer sha256AndDigest : '29CB66724DD2776C'H,
        toBeSigned {
          id name : "ma.scms.tta.or.kr",
          cracaId 'D2776C'H,
          crlSeries 256,
          validityPeriod {
            start 545377687,
            duration hours : 35208
          },
          appPermissions {
            {
              psid 35,
              ssp opaque : '8A000100'H
            }
          },
          encryptionKey {
            supportedSymmAlg aes128Ccm,
            publicKey eciesNistP256 : compressed-y-0 : 'D41F3564F1CE28F3C431FD57C54FF33D13EB3DB0E4F68B59511D5DEC0B7FE26E'H
          },
          verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : '8F71F6DA0CC82CF5124BFED8A147F109324E56C93740A7DB0EB77BF1CB9B1EE4'H
        },
        signature ecdsaNistP256Signature : {
          rSig x-only : 'F9747697AF125A7A090F97803A5AE4D815986D5474A88481CE6F199A660F8E3E'H,
          sSig '4A25207D2ACBDD9B2AD8CE4864A7BC91A70E5D6CFC57F1FABFB62C86D78D8745'H
        }
      },
      certs {
        {
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
        },
        {
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
        },
        {
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
      }
    },
    optionalCertList {
    }
  }
}
 */
const char *g_tv_ecresp_lccf_1 = "01808100000100011172612e73636d732e7474612e6f722e6b7200010001008003008029cb66724dd2776c1181116d612e73636d732e7474612e6f722e6b72d2776c01002081cd97848988010180012380048a000100008082d41f3564f1ce28f3c431fd57c54ff33d13eb3db0e4f68b59511d5dec0b7fe26e8080828f71f6da0cc82cf5124bfed8a147f109324e56c93740a7db0eb77bf1cb9b1ee48080f9747697af125a7a090f97803a5ae4d815986d5474a88481ce6f199a660f8e3e4a25207d2acbdd9b2ad8ce4864a7bc91a70e5d6cfc57f1fabfb62c86d78d874501038003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe548003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd0100";
size_t g_tv_ecresp_lccf_size_1 = 853;
const char *g_tv_ecresp_ica_cert_1 = "8003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f";
size_t g_tv_ecresp_ica_cert_size_1 = 203;
const char *g_tv_ecresp_pca_cert_1 = "800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd";
size_t g_tv_ecresp_pca_cert_size_1 = 219;
const char *g_tv_ecresp_enroll_priv_key_1 = "1af8c480d6cb323245534469b15d777dabd4cfb354dc93403343bdabb1acd572";
const char *g_tv_ecresp_enroll_pub_key_1 = "04d312b7c2a1b44f4a523c125cc1731b17abdf3bff89ced6ac1a4a88c05f5b77f77014727abca99ae855257f1a646899f2dab50b76bec341524b308a0e066fc476";


/*
 * 등록인증서 발급 테스트벡터 #2 (TTA가 보유한 아우토크립트 서버)
 */

/*
rec1value SignedEeEnrollmentCertRequest ::= {
  protocolVersion 3,
  content signedCertificateRequest : CONTAINING {
    hashId sha256,
    tbsRequest {
      version 1,
      content eca-ee : eeEcaCertRequest : {
        version 1,
        currentTime 581230081,
        tbsData {
          id name : "",
          cracaId '000000'H,
          crlSeries 4,
          validityPeriod {
            start 581230081,
            duration years : 6
          },
          region identifiedRegion : {
            countryOnly : 410
          },
          certRequestPermissions {
            {
              subjectPermissions explicit : {
                {
                  psid 32
                },
                {
                  psid 35
                },
                {
                  psid 135
                }
              },
              minChainLength 0,
              chainLengthRange 0,
              eeType '10000000'B
            }
          },
          verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-1 : '19071F1292F76058FB92FFC19A3CE60606116096B3C5AEF905417094947EF118'H
        }
      }
    },
    signer self : NULL,
    signature ecdsaNistP256Signature : {
      rSig compressed-y-1 : '46660AE0482ED3E645AAC0F16C37F87B2A1AA67CD8859D9072CEC929E28A57D9'H,
      sSig 'CCFB3535C00D8144174477B09D6156B84B80D998BB6FCD0CE8523406F6B88B78'H
    }
  }
}
 */
const char *g_tv_ecreq_2 = "0383819600018180000122a4de01448100000000000422a4de0186000683010180019a010180800103000120000123000187010080808319071f1292f76058fb92ffc19a3ce60606116096b3c5aef905417094947ef11882808346660ae0482ed3e645aac0f16c37f87b2a1aa67cd8859d9072cec929e28a57d9ccfb3535c00d8144174477b09d6156b84b80d998bb6fcd0ce8523406f6b88b78";
size_t g_tv_ecreq_size_2 = 154;
const char *g_tv_ecreq_init_priv_key_2 = "e733f87137c3ca7c4faa066a9055d72747190bae6e1861a51823a065649dbb28";
const char *g_tv_ecreq_init_pub_key_2 = "0419071f1292f76058fb92ffc19a3ce60606116096b3c5aef905417094947ef118a9db7892f4291a374a8243bed30af6d24c129425dd06b58d09298216562ccc29";
const char *g_tv_ecreq_h8_2 = "ca821d4eaf3b2e54"; // 현재 아우토크립트 서버가 response 메시지에 넣은 requestHash는 잘못된 값이 들어 있다.

/*
rec1value SignedEeEnrollmentCertResponse ::= {
  protocolVersion 3,
  content signedData : {
    hashId sha256,
    tbsData {
      payload {
        data {
          protocolVersion 3,
          content unsecuredData : CONTAINING {
            version 1,
            content eca-ee : ecaEeCertResponse : {
              version 1,
              requestHash '703DFD03B239C451'H,
              ecaCert {
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
              },
              enrollmentCert {
                version 3,
                type implicit,
                issuer sha256AndDigest : '6EB4E93EA62B3181'H,
                toBeSigned {
                  id name : "",
                  cracaId 'D2776C'H,
                  crlSeries 4,
                  validityPeriod {
                    start 581230081,
                    duration years : 6
                  },
                  region identifiedRegion : {
                    countryOnly : 410
                  },
                  certRequestPermissions {
                    {
                      subjectPermissions explicit : {
                        {
                          psid 32
                        },
                        {
                          psid 35
                        },
                        {
                          psid 135
                        }
                      },
                      minChainLength 0,
                      chainLengthRange 0,
                      eeType '10000000'B
                    }
                  },
                  verifyKeyIndicator reconstructionValue : compressed-y-1 : '3FA7F9AB490A22DA43D227914CFD78FF8AD79640BDCDE6427233C2DE02839914'H
                }
              },
              privKeyReconstruction 'FABCF8D99512EA9BF31561C09077B65D010C49F9DB26E4D46D4DADC07B07B292'H
            }
          }
        }
      },
      headerInfo {
        psid 35
      }
    },
    signer certificate : {
      {
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
    },
    signature ecdsaNistP256Signature : {
      rSig x-only : '7A15D87EABF16080222D2EC877C882303D7668700DEEBD4D93E1A987FD2A2CFB'H,
      sSig 'B7EB4F2B91C04F62075C5BABFD06DF4DF65B041C17416F506CA5F5761530898C'H
    }
  }
}
 */
const char *g_tv_ecresp_2 = "03810040038082015d0181810001703dfd03b239c451800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47000301806eb4e93ea62b3181448100d2776c000422a4de0186000683010180019a010180800103000120000123000187010081833fa7f9ab490a22da43d227914cfd78ff8ad79640bdcde6427233c2de02839914fabcf8d99512ea9bf31561c09077b65d010c49f9db26e4d46d4dadc07b07b292000123810101800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af4780807a15d87eabf16080222d2ec877c882303d7668700deebd4d93e1a987fd2a2cfbb7eb4f2b91c04f62075c5babfd06df4df65b041c17416f506ca5f5761530898c";
size_t g_tv_ecresp_size_2 = 650;
const char *g_tv_ecresp_enroll_cert_2 = "000301806eb4e93ea62b3181448100d2776c000422a4de0186000683010180019a010180800103000120000123000187010081833fa7f9ab490a22da43d227914cfd78ff8ad79640bdcde6427233c2de02839914";
size_t g_tv_ecresp_enroll_cert_size_2 = 84;
const char *g_tv_ecresp_recon_priv_2 = "FABCF8D99512EA9BF31561C09077B65D010C49F9DB26E4D46D4DADC07B07B292";
const char *g_tv_ecresp_eca_cert_2 = "800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47";
size_t g_tv_ecresp_eca_cert_size_2 = 220;
const char *g_tv_ecresp_ra_cert_2 = "800300809d195826018fbb3855811172612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000383010780019a80007c8001e48003488002d480011480033a010180012380038b0001010180810100008082d7b33f85d4293f67ad43d3ae217864eda5ff5e91a9586b0e070439de0d0017b9808082a2283219090ee0ec99a98c06f88273f421dceef3361cdf22b3f56bb22e1ced4980800ff5a3913f4f52605d4b6a202c364901215f33096e9ad829abe4df1eb2d6b97bd06f5c12072079627483b9f70b0ad421aff68a159516060c5cb318eac17e2f3a";
size_t g_tv_ecresp_ra_cert_size_2 = 220;
const char *g_tv_ecresp_rca_cert_2 = "8003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe54";
size_t g_tv_ecresp_rca_cert_size_2 = 205;

/*
rec1value ScopedLocalCertificateChainFile ::= {
  version 1,
  content cert-chain : localCertificateChainFile : {
    version {
      gccfVersion 1,
      lccfVersion 1,
      raHostname "ra.scms.tta.or.kr"
    },
    requiredCertStore {
      rootCAEndorsements {
      },
      electorEndorsements {
      },
      maCertificate {
        version 3,
        type explicit,
        issuer sha256AndDigest : '29CB66724DD2776C'H,
        toBeSigned {
          id name : "ma.scms.tta.or.kr",
          cracaId 'D2776C'H,
          crlSeries 256,
          validityPeriod {
            start 545377687,
            duration hours : 35208
          },
          appPermissions {
            {
              psid 35,
              ssp opaque : '8A000100'H
            }
          },
          encryptionKey {
            supportedSymmAlg aes128Ccm,
            publicKey eciesNistP256 : compressed-y-0 : 'D41F3564F1CE28F3C431FD57C54FF33D13EB3DB0E4F68B59511D5DEC0B7FE26E'H
          },
          verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : '8F71F6DA0CC82CF5124BFED8A147F109324E56C93740A7DB0EB77BF1CB9B1EE4'H
        },
        signature ecdsaNistP256Signature : {
          rSig x-only : 'F9747697AF125A7A090F97803A5AE4D815986D5474A88481CE6F199A660F8E3E'H,
          sSig '4A25207D2ACBDD9B2AD8CE4864A7BC91A70E5D6CFC57F1FABFB62C86D78D8745'H
        }
      },
      certs {
        {
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
        },
        {
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
        },
        {
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
      }
    },
    optionalCertList {
    }
  }
}
 */
const char *g_tv_ecresp_lccf_2 = "01808100000100011172612e73636d732e7474612e6f722e6b7200010001008003008029cb66724dd2776c1181116d612e73636d732e7474612e6f722e6b72d2776c01002081cd97848988010180012380048a000100008082d41f3564f1ce28f3c431fd57c54ff33d13eb3db0e4f68b59511d5dec0b7fe26e8080828f71f6da0cc82cf5124bfed8a147f109324e56c93740a7db0eb77bf1cb9b1ee48080f9747697af125a7a090f97803a5ae4d815986d5474a88481ce6f199a660f8e3e4a25207d2acbdd9b2ad8ce4864a7bc91a70e5d6cfc57f1fabfb62c86d78d874501038003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe548003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd0100";
size_t g_tv_ecresp_lccf_size_2 = 853;
const char *g_tv_ecresp_ica_cert_2 = "8003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f";
size_t g_tv_ecresp_ica_cert_size_2 = 203;
const char *g_tv_ecresp_pca_cert_2 = "800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd";
size_t g_tv_ecresp_pca_cert_size_2 = 219;
const char *g_tv_ecresp_enroll_priv_key_2 = "6fb1a870562275b840c1e3cac897b7d657c235bf5b589e97d41e7345c827ac0f";
const char *g_tv_ecresp_enroll_pub_key_2 = "04c0522782e711e889938a5cdbeca83ddef4c801ecf40460fbde1162415aea5415bff8ae71a2f7083935eabd406cbac2e9b8a9ddc6c6e83a9c26f7bd99ca9d96fe";

/*
 * 등록인증서 발급 테스트벡터 #3 (TTA가 보유한 아우토크립트 서버)
 */

/*
rec1value SignedEeEnrollmentCertRequest ::= {
  protocolVersion 3,
  content signedCertificateRequest : CONTAINING {
    hashId sha256,
    tbsRequest {
      version 1,
      content eca-ee : eeEcaCertRequest : {
        version 1,
        currentTime 581227071,
        tbsData {
          id name : "",
          cracaId '000000'H,
          crlSeries 4,
          validityPeriod {
            start 581227071,
            duration years : 6
          },
          region identifiedRegion : {
            countryOnly : 410
          },
          certRequestPermissions {
            {
              subjectPermissions explicit : {
                {
                  psid 32
                },
                {
                  psid 35
                },
                {
                  psid 135
                }
              },
              minChainLength 0,
              chainLengthRange 0,
              eeType '10000000'B
            }
          },
          verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-1 : '1691CFC874B737AD28002498C691782E059B1B345E2E1AD99464D1D021DDACE3'H
        }
      }
    },
    signer self : NULL,
    signature ecdsaNistP256Signature : {
      rSig compressed-y-0 : 'EA36FA191CAEB4931ED59C650C040F7DB5CCE7D090FF57B58BED989497562D91'H,
      sSig '8A490C9097F20B55158B81C2A9EAEE6431380A2F01CB226E3E7CE56DA1337070'H
    }
  }
}
 */
const char *g_tv_ecreq_3 = "0383819600018180000122a4d23f448100000000000422a4d23f86000683010180019a01018080010300012000012300018701008080831691cfc874b737ad28002498c691782e059b1b345e2e1ad99464d1d021ddace3828082ea36fa191caeb4931ed59c650c040f7db5cce7d090ff57b58bed989497562d918a490c9097f20b55158b81c2a9eaee6431380a2f01cb226e3e7ce56da1337070";
size_t g_tv_ecreq_size_3 = 154;
const char *g_tv_ecreq_init_priv_key_3 = "89b8675d09d4707075fbf7898087c536fe96441918f6434396500f592509a79e";
const char *g_tv_ecreq_init_pub_key_3 = "041691cfc874b737ad28002498c691782e059b1b345e2e1ad99464d1d021ddace319df11600d956a864059217f752a793c7666e764e72b5df81ed71304f8abc7ad";
const char *g_tv_ecreq_h8_3 = "8ceb28d74ed65270"; // 현재 아우토크립트 서버가 response 메시지에 넣은 requestHash는 잘못된 값이 들어 있다.

/*
rec1value SignedEeEnrollmentCertResponse ::= {
  protocolVersion 3,
  content signedData : {
    hashId sha256,
    tbsData {
      payload {
        data {
          protocolVersion 3,
          content unsecuredData : CONTAINING {
            version 1,
            content eca-ee : ecaEeCertResponse : {
              version 1,
              requestHash 'E5BE7991AD941901'H,
              ecaCert {
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
              },
              enrollmentCert {
                version 3,
                type implicit,
                issuer sha256AndDigest : '6EB4E93EA62B3181'H,
                toBeSigned {
                  id name : "",
                  cracaId 'D2776C'H,
                  crlSeries 4,
                  validityPeriod {
                    start 581227071,
                    duration years : 6
                  },
                  region identifiedRegion : {
                    countryOnly : 410
                  },
                  certRequestPermissions {
                    {
                      subjectPermissions explicit : {
                        {
                          psid 32
                        },
                        {
                          psid 35
                        },
                        {
                          psid 135
                        }
                      },
                      minChainLength 0,
                      chainLengthRange 0,
                      eeType '10000000'B
                    }
                  },
                  verifyKeyIndicator reconstructionValue : compressed-y-1 : '693680A59EBD0603A9EBB8925718ED7D46B02CD1DE772326B778C2D3043C83B0'H
                }
              },
              privKeyReconstruction '1DC92358477AD8B924D514095E0165A60FDD183C2675C4E27967DE3B9A82A51B'H
            }
          }
        }
      },
      headerInfo {
        psid 35
      }
    },
    signer certificate : {
      {
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
    },
    signature ecdsaNistP256Signature : {
      rSig x-only : 'B8F9698C2E88D2C56EE2F2AAB6839EE4ECFE7B3947C308DCF019BB3D704A3B8B'H,
      sSig '63ECB58FCD48FD3FB0DCCD90E091AC135671F0C24A149896662DEEC733D695B8'H
    }
  }
}
 */
const char *g_tv_ecresp_3 = "03810040038082015d0181810001e5be7991ad941901800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47000301806eb4e93ea62b3181448100d2776c000422a4d23f86000683010180019a01018080010300012000012300018701008183693680a59ebd0603a9ebb8925718ed7d46b02cd1de772326b778c2d3043c83b01dc92358477ad8b924d514095e0165a60fdd183c2675c4e27967de3b9a82a51b000123810101800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af478080b8f9698c2e88d2c56ee2f2aab6839ee4ecfe7b3947c308dcf019bb3d704a3b8b63ecb58fcd48fd3fb0dccd90e091ac135671f0c24a149896662deec733d695b8";
size_t g_tv_ecresp_size_3 = 650;
const char *g_tv_ecresp_enroll_cert_3 = "000301806eb4e93ea62b3181448100d2776c000422a4d23f86000683010180019a01018080010300012000012300018701008183693680a59ebd0603a9ebb8925718ed7d46b02cd1de772326b778c2d3043c83b0";
size_t g_tv_ecresp_enroll_cert_size_3 = 84;
const char *g_tv_ecresp_recon_priv_3 = "1DC92358477AD8B924D514095E0165A60FDD183C2675C4E27967DE3B9A82A51B";
const char *g_tv_ecresp_eca_cert_3 = "800300809d195826018fbb385981126563612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000a83010780019a80007c8001e48003488002d480011480033a010180012380038400010101208140008082689493f5c0653f08af01059d7a30db52f89b849d2ffc7d090b8e8859a482e2458080822a4056dc0c33b7e64cc29cf95ee74cd6012f6ba162a40f72652713db97d4b98c808065cad5aa1ebac67c8456c01a4231621ca76f16834963aa4da616efd7630c35d90025a9e8de74ea479aa40a2e0672df31d9a003bf3d9f565992797391d430af47";
size_t g_tv_ecresp_eca_cert_size_3 = 220;
const char *g_tv_ecresp_ra_cert_3 = "800300809d195826018fbb3855811172612e73636d732e7474612e6f722e6b72d2776c00022081cd9a86000383010780019a80007c8001e48003488002d480011480033a010180012380038b0001010180810100008082d7b33f85d4293f67ad43d3ae217864eda5ff5e91a9586b0e070439de0d0017b9808082a2283219090ee0ec99a98c06f88273f421dceef3361cdf22b3f56bb22e1ced4980800ff5a3913f4f52605d4b6a202c364901215f33096e9ad829abe4df1eb2d6b97bd06f5c12072079627483b9f70b0ad421aff68a159516060c5cb318eac17e2f3a";
size_t g_tv_ecresp_ra_cert_size_3 = 220;
const char *g_tv_ecresp_rca_cert_3 = "8003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe54";
size_t g_tv_ecresp_rca_cert_size_3 = 205;

/*
rec1value ScopedLocalCertificateChainFile ::= {
  version 1,
  content cert-chain : localCertificateChainFile : {
    version {
      gccfVersion 1,
      lccfVersion 1,
      raHostname "ra.scms.tta.or.kr"
    },
    requiredCertStore {
      rootCAEndorsements {
      },
      electorEndorsements {
      },
      maCertificate {
        version 3,
        type explicit,
        issuer sha256AndDigest : '29CB66724DD2776C'H,
        toBeSigned {
          id name : "ma.scms.tta.or.kr",
          cracaId 'D2776C'H,
          crlSeries 256,
          validityPeriod {
            start 545377687,
            duration hours : 35208
          },
          appPermissions {
            {
              psid 35,
              ssp opaque : '8A000100'H
            }
          },
          encryptionKey {
            supportedSymmAlg aes128Ccm,
            publicKey eciesNistP256 : compressed-y-0 : 'D41F3564F1CE28F3C431FD57C54FF33D13EB3DB0E4F68B59511D5DEC0B7FE26E'H
          },
          verifyKeyIndicator verificationKey : ecdsaNistP256 : compressed-y-0 : '8F71F6DA0CC82CF5124BFED8A147F109324E56C93740A7DB0EB77BF1CB9B1EE4'H
        },
        signature ecdsaNistP256Signature : {
          rSig x-only : 'F9747697AF125A7A090F97803A5AE4D815986D5474A88481CE6F199A660F8E3E'H,
          sSig '4A25207D2ACBDD9B2AD8CE4864A7BC91A70E5D6CFC57F1FABFB62C86D78D8745'H
        }
      },
      certs {
        {
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
        },
        {
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
        },
        {
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
      }
    },
    optionalCertList {
    }
  }
}
 */
const char *g_tv_ecresp_lccf_3 = "01808100000100011172612e73636d732e7474612e6f722e6b7200010001008003008029cb66724dd2776c1181116d612e73636d732e7474612e6f722e6b72d2776c01002081cd97848988010180012380048a000100008082d41f3564f1ce28f3c431fd57c54ff33d13eb3db0e4f68b59511d5dec0b7fe26e8080828f71f6da0cc82cf5124bfed8a147f109324e56c93740a7db0eb77bf1cb9b1ee48080f9747697af125a7a090f97803a5ae4d815986d5474a88481ce6f199a660f8e3e4a25207d2acbdd9b2ad8ce4864a7bc91a70e5d6cfc57f1fabfb62c86d78d874501038003008100188115726f6f7463612e73636d732e7474612e6f722e6b7200000000002081cd9686004601028001238003810001800201008007000100010101000104e081010301ffc06080010100012301ffc06080010100012601ffc0608001010002010001ffc0808083c2e054303d4acbb7df2f7104a713a1c59727ce8b0725f87ab691f23307702142808060c63464e0ad4f81c55d2b09e5fa7468c920fefbefea50fe6b9a5d9fb14a647022726f3a1f0022f2001f5f402b9d99a565d3da5e397734bf01321e9e324cfe548003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd0100";
size_t g_tv_ecresp_lccf_size_3 = 853;
const char *g_tv_ecresp_ica_cert_3 = "8003008029cb66724dd2776c5881126963612e73636d732e7474612e6f722e6b72d2776c00022081cd9686001483010780019a80007c8001e48003488002d480011480033a010180012380038300010102a0810102c06080010280012381800201008101ffc08080826e39058a1016da43241e1bb0da487c70800febefb293dab5c43760ea58b425c78080cf7ea3e91a5c539141ef0d5a7f3ba2e75faf8c438ef51b4659e8edf1e505c7d379d35262f8f80fa3d32ec5bc4a70f4f63ecd467700757d1fac260778adf6256f";
size_t g_tv_ecresp_ica_cert_size_3 = 203;
const char *g_tv_ecresp_pca_cert_3 = "800300809d195826018fbb385981127063612e73636d732e7474612e6f722e6b72d2776c00022081cd9986000683010780019a80007c8001e48003488002d480011480033a01018001238003850001010100810080830194606ec293a217fd120a52d4eb26a525439d570bcd4dd8f4b033447da988778080822b9bccba5fb35168ea829a8c55c959cddd1a8df6e96a22566ed4e3066388d1fc8080c7d9e9d504a4ed3ed0acfdfeefc2294d2eb5e239123dde6fa6e587788d0ff5d7de326e46f419ef5a53367d806138531d3e36c85a647eb3ce9f65f4bda8b02ecd";
size_t g_tv_ecresp_pca_cert_size_3 = 219;
const char *g_tv_ecresp_enroll_priv_key_3 = "11233adea3d987c5684139e5fbdbe0d81bec998e2cb94cee68f0271c0e801e1f";
const char *g_tv_ecresp_enroll_pub_key_3 = "049548098cd1d77fc9d432934453f7d05c1749eb1d03131bfa4cc6dfc4d52a1107a36b8d3b56effc6ec86395d63c07c6a19329949b1172661f67d6705e01f62702";
