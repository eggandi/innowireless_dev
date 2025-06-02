/** 
 * @file
 * @brief OpenSSL 기반 서명검증 기능을 구현한 파일
 * @date 2020-04-11
 * @author gyun
 */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-executer/openssl/dot2-openssl-inline.h"


/**
 * @brief 서명바이트열로부터 ECDSA_SIG 형식 서명정보를 생성하여 반환한다.
 * @param[in] sign 서명
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return ECDSA_SIG ECDSA_SIGN 형식 서명정보 구조체 포인터
 * @retval NULL: 실패
 *
 * 반환된 ECDSA_SIG 형식정보는 사용 후 ECDSA_SIG_free()로 해제되어야 한다.
 */
static inline ECDSA_SIG * dot2_ossl_MakeECDSASIGfromSignatureOcts(const struct Dot2Signature *sign, int *err)
{
  /*
   * 서명 값 r,s를 ECDSA_SIG 형식으로 변환한다(r이 아닌 R 값을 갖는 경우에도 동일하게 처리한다 - Rx = r이므로).
   */
  const uint8_t *r = sign->R_r.u.point.u.xy.x;
  const uint8_t *s = sign->s;
  ECDSA_SIG *ec_sign = ECDSA_SIG_new();
  if (ec_sign) {
    int ret = ECDSA_SIG_set0(ec_sign, BN_bin2bn(r, DOT2_EC_256_KEY_LEN, NULL), BN_bin2bn(s, DOT2_EC_256_KEY_LEN, NULL));
    if (ret == DOT2_OSSL_FAIL) {
      ECDSA_SIG_free(ec_sign);
      *err = -kDot2Result_OSSL_MakeECDSASIGfromSignatureOcts;
      return NULL;
    }
  }
  return ec_sign;
}


/**
 * @brief 서명을 ECDSA_SIG 형식으로 변환한 후 검증한다.
 * @param[in] h_input 서명계산을 위해 사용되는 해시 입력
 * @param[in] eck_pub_key 서명검증용 공개키 (EC_KEY 형식)
 * @param[in] sign 검증할 서명정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int
dot2_ossl_VerifyECDSASIG(const struct Dot2SHA256 *h_input, EC_KEY *eck_pub_key, const struct Dot2Signature *sign)
{
  /*
   * 바이트열 형식의 서명 값을 ECDSA_SIG 형식으로 변환한 후 검증한다.
   */
  int ret;
  ECDSA_SIG *ecdsa_sig = dot2_ossl_MakeECDSASIGfromSignatureOcts(sign, &ret);
  if (ecdsa_sig) {
    ret = ECDSA_do_verify(h_input->octs, sizeof(h_input->octs), ecdsa_sig, eck_pub_key);
    ECDSA_SIG_free(ecdsa_sig);
    if (ret == DOT2_OSSL_SUCCESS) {
      ret = kDot2Result_Success; // 서명검증 성공
    } else if (ret == DOT2_OSSL_FAIL) {
      ret = -kDot2Result_SignatureVerificationFailed; // 서명검증 실패 (유효하지 않은 서명)
    } else {
      ret = -kDot2Result_OSSL_ECDSA_do_verify; // 동작 오류
    }
  }
  return ret;
}


/**
 * @brief 서명을 검증한다.
 * @param[in] tbs 서명계산을 위해 사용되는 ToBeSignedData 또는 ToBeSignedCert 인코딩 데이터
 * @param[in] tbs_size tbs 데이터의 길이
 * @param[in] signer_h 서명 인증서 해시값 (NULL 가능)
 * @param[in] key 서명검증용 공개키(EC_KEY 형식))
 * @param[in] sign 검증할 서명정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_VerifySignature_1(
  const uint8_t *tbs,
  size_t tbs_size,
  const struct Dot2SHA256 *signer_h,
  EC_KEY *eck_pub_key,
  const struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Verify signature\n");

  /*
   * 서명검증 계산에 입력될 해시값을 계산한다.
   */
  struct Dot2SHA256 h_input;
  dot2_ossl_CalculateSignatureHashInput(tbs, tbs_size, signer_h, &h_input);

  /*
   * 바이트열 형식의 서명 값을 ECDSA_SIG 형식으로 변환한 후 검증한다.
   */
  int ret = dot2_ossl_VerifyECDSASIG(&h_input, eck_pub_key, sign);
  if (ret == kDot2Result_Success) {
    Log(kDot2LogLevel_Event, "Success to verify signature\n");
  } else {
    Err("Fail to verify signature\n");
  }
  return ret;
}


/**
 * @brief 서명을 검증한다. (ToBeSignedData 해시값을 사용한다)
 * @param[in] tbs_h 서명계산을 위해 사용되는 ToBeSignedData 해시
 * @param[in] signer_h 서명 인증서 해시값 (NULL 가능)
 * @param[in] key 서명검증용 공개키(EC_KEY 형식))
 * @param[in] sign 검증할 서명정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_VerifySignature_2(
  const struct Dot2SHA256 *tbs_h,
  const struct Dot2SHA256 *signer_h,
  EC_KEY *eck_pub_key,
  const struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Verify signature using H(ToBeSignedData)\n");

  /*
   * 서명검증 계산에 입력될 해시값을 계산한다.
   */
  struct Dot2SHA256 h_input;
  dot2_ossl_CalculateSignatureHashInput_H(tbs_h, signer_h, &h_input);

  /*
   * 바이트열 형식의 서명 값을 ECDSA_SIG 형식으로 변환한 후 검증한다.
   */
  int ret = dot2_ossl_VerifyECDSASIG(&h_input, eck_pub_key, sign);
  if (ret == kDot2Result_Success) {
    Log(kDot2LogLevel_Event, "Success to verify signature\n");
  } else {
    Err("Fail to verify signature\n");
  }
  return ret;
}
