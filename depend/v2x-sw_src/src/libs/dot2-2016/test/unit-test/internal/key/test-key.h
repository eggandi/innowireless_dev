/** 
 * @file
 * @brief 키 관련 단위테스트에 사용되는 정의를 포함한 헤더 파일
 * @date 2020-03-11
 * @author gyun
 */


#ifndef V2X_SW_TEST_KEY_H
#define V2X_SW_TEST_KEY_H


/**
 * @brief 키 재구성 테스트벡터 구조체
 */
struct Dot2KeyReconstructTestVector
{
  /// 인증서 요청 개인키. 예: dwnl_sgn.priv 파일
  uint8_t cr_priv_key[DOT2_EC_256_KEY_LEN];
  /// 개인키 재구성 값. 예: *.s 파일
  uint8_t recon_priv[DOT2_EC_256_KEY_LEN];
  /// 내 인증서. 예: *.cert 파일
  uint8_t my_cert[kDot2CertSize_Max];
  /// 내 인증서 크기
  size_t my_cert_size;
  /// 공개키 재구성 값 (내 인증서 내에 포함)
  uint8_t recon_pub[DOT2_EC_256_PUB_KEY_LEN];
  /// 상위 인증서. 예: pca 파일
  uint8_t issuer_cert[kDot2CertSize_Max];
  /// 상위 인증서 크기
  size_t issuer_cert_size;
  /// 상위 인증서 해시
  uint8_t h_issuer[DOT2_SHA_256_LEN];
  /// 상위 인증서 공개키
  uint8_t issuer_pub_key[DOT2_EC_256_PUB_KEY_LEN];
  /// 재구성된 개인키 결과. 예: *.key 파일
  uint8_t priv_key[DOT2_EC_256_KEY_LEN];
  /// 재구성된 공개키 결과
  uint8_t pub_key[DOT2_EC_256_PUB_KEY_LEN];
};


/**
 * @brief 버터플라이 확장 기반 키 재구성 테스트벡터 구조체
 */
struct Dot2BfKeyReconstructTestVector
{
  /// i 값. 예: 10A_B.cert 파일의 10A
  uint32_t i;
  /// j 값. 예: 10A_B.cert 파일의 B
  uint32_t j;
  /// ck: AES key for signing (서명 관련 키쌍을 확장하기 위한 AES 키). 예: sgn_expnsn.key 파일
  uint8_t expansion[DOT2_AES_128_LEN];
  /// a: Signing seed private key (서명 관련 키쌍 확장을 위한 시드 개인키). 예: dwnl_sgn.priv 파일
  uint8_t seed_priv[DOT2_EC_256_KEY_LEN];

  /// Cert: 내 인증서. 예: 10A_B.cert 파일
  uint8_t my_cert[kDot2CertSize_Max];
  /// 내 인증서의 길이
  size_t my_cert_size;
  /// s: 개인키 재구성 값 (reconstruction priv key). 예: 10A_B.s
  uint8_t recon_priv[DOT2_EC_256_KEY_LEN];
  /// C: 공개키 재구성 값 (reconstruction pub key). 예: 10A_B.cert 파일 내 reconstruction value 영역 값.
  uint8_t recon_pub[DOT2_EC_256_PUB_KEY_LEN];
  /// 공개키 재구성값의 유형
  Dot2EcCurvePointType recon_pub_type;

  /// 상위인증서. 예: pca 파일
  uint8_t issuer_cert[kDot2CertSize_Max];
  /// 상위인증서 길이
  size_t issuer_cert_size;
  /// 상위인증서 해시
  uint8_t h_issuer[DOT2_SHA_256_LEN];

  /// 확장된 개인키 결과
  uint8_t exp_priv_key[DOT2_EC_256_KEY_LEN];
  /// 확장된 공개키 결과
  uint8_t exp_pub_key[DOT2_EC_256_PUB_KEY_LEN];
  /// 재구성된 개인키 결과
  uint8_t priv_key[DOT2_EC_256_KEY_LEN];
  /// 재구성된 공개키 결과
  uint8_t pub_key[DOT2_EC_256_PUB_KEY_LEN];
};


/**
 * @brief 키쌍 테스트벡터 구조체
 */
struct Dot2KeyPairTestVector
{
  /// 개인키
  uint8_t priv_key[DOT2_EC_256_KEY_LEN];
  /// 공개키
  uint8_t pub_key[DOT2_EC_256_PUB_KEY_LEN];
};


#endif //V2X_SW_TEST_KEY_H
