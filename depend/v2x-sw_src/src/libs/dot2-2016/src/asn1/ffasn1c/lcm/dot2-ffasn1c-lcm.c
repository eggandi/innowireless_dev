/** 
  * @file 
  * @brief LCM 관련 구현
  * @date 2022-07-24 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "asn1/ffasn1c/dot2-ffasn1c-inline.h"
#include "encrypt/dot2-encrypt.h"
#include "lcm/dot2-lcm.h"


/**
 * @brief RecipientInfo 필드를 채운다.
 * @param[in] recipient_h 수신자인증서 H8 바이트열
 * @param[in] V 임시(ephmeral) 공개키 바이트열
 * @param[in] C 암호화된 암호화키 바이트열
 * @param[in] T Authentication tag 바이트열
 * @param[out] asn1_info 정보를 채울 asn.1 정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_FillRecipientInfo(
  const uint8_t *recipient_h,
  struct Dot2ECPublicKey *V,
  struct Dot2AESKey *C,
  struct Dot2AESAuthTag *T,
  dot2RecipientInfo *asn1_info)
{
  Log(kDot2LogLevel_Event, "Fill RecipientInfo\n");

  asn1_info->choice = dot2RecipientInfo_certRecipInfo;

  /*
   * recpientId(수신자인증서의 H8)를 채운다.
   */
  int ret = dot2_ffasn1c_FillASN1String(recipient_h, 8, &(asn1_info->u.certRecipInfo.recipientId));
  if (ret < 0) {
    Err("Fail to fill RecipientInfo - dot2_ffasn1c_FillASN1String(recipient_h) failed\n");
    return ret;
  }

  /*
   * encKey(ECIES 암호화된 데이터암호화키 정보)를 채운다.
   */
  asn1_info->u.certRecipInfo.encKey.choice = dot2EncryptedDataEncryptionKey_eciesNistP256;
  ASN1String *to;
  // V(임시(ephemeral) 공개키)를 채운다.
  if (V->u.octs[DOT2_EC_256_PUB_KEY_LEN - 1] & 1) {
    asn1_info->u.certRecipInfo.encKey.u.eciesNistP256.v.choice = dot2EccP256CurvePoint_compressed_y_1;
    to = &(asn1_info->u.certRecipInfo.encKey.u.eciesNistP256.v.u.compressed_y_1);
  } else {
    asn1_info->u.certRecipInfo.encKey.u.eciesNistP256.v.choice = dot2EccP256CurvePoint_compressed_y_0;
    to = &(asn1_info->u.certRecipInfo.encKey.u.eciesNistP256.v.u.compressed_y_0);
  }
  ret = dot2_ffasn1c_FillASN1String(V->u.point.u.xy.x, DOT2_EC_256_KEY_LEN, to);
  if (ret < 0) {
    Err("Fail to fill RecipientInfo - dot2_ffasn1c_FillASN1String(encKey.x) failed\n");
    return ret;
  }
  // C(암호화된 암호화키)를 채운다.
  to = &(asn1_info->u.certRecipInfo.encKey.u.eciesNistP256.c);
  ret = dot2_ffasn1c_FillASN1String(C->octs, DOT2_AES_128_LEN, to);
  if (ret < 0) {
    Err("Fail to fill RecipientInfo - dot2_ffasn1c_FillASN1String(C) failed\n");
    return ret;
  }
  // T(Authentication tag)를 채운다.
  to = &(asn1_info->u.certRecipInfo.encKey.u.eciesNistP256.t);
  ret = dot2_ffasn1c_FillASN1String(T->octs, DOT2_AUTH_TAG_LEN, to);
  if (ret < 0) {
    Err("Fail to fill RecipientInfo - dot2_ffasn1c_FillASN1String(T) failed\n");
    return ret;
  }

  Log(kDot2LogLevel_Event, "Success to fill RecipientInfo\n");
  return kDot2Result_Success;
}


/**
 * @brief SymmetricCiphertext 정보를 채운다.
 * @param[in] data 암호화된 데이터(Ciphertext || tag)
 * @param[in] data_size 암호화된 데이터 바이트열의 길이
 * @param[in] nonce AES nonce 바이트열
 * @param[out] asn1_text 정보를 채울 asn.1 정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_FillSymmetricCiphertext(
  uint8_t *data,
  size_t data_size,
  const struct Dot2AESNonce *nonce,
  dot2SymmetricCiphertext *asn1_ctext)
{
  Log(kDot2LogLevel_Event, "Fill SymmetricCiphertext\n");

  /*
   * 암호화된 데이터(Ciphertext || tag)를 채운다.
   * data는 동적할당된 데이터이다.
   */
 asn1_ctext->choice = dot2SymmetricCiphertext_aes128ccm;
 asn1_ctext->u.aes128ccm.ccmCiphertext.len = data_size;
 asn1_ctext->u.aes128ccm.ccmCiphertext.buf = data;

  /*
   * nonce를 채운다.
   */
  return dot2_ffasn1c_FillASN1String(nonce->octs, DOT2_AES_128_NONCE_LEN, &(asn1_ctext->u.aes128ccm.nonce));
}


/**
 * @brief EncryptedData 필드를 채운다.
 * @param[in] data 암호화할 데이터 바이트열
 * @param[in] data_size 암호화할 데이터 바이트열의 길이
 * @param[in] key_input_h 키 파생함수(KDF2) 입력 해시 (수신자인증서에대한 해시값이 사용된다)
 * @param[in] pubkey_r 상대방 공개키 바이트열
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_FillEncryptedData(
  uint8_t *data,
  size_t data_size,
  const struct Dot2SHA256 *key_input_h,
  struct Dot2ECPublicKey *pubkey_r,
  dot2EncryptedData *asn1_enc)
{
  Log(kDot2LogLevel_Event, "Fill EncryptedData\n");
  uint8_t *enc  = NULL;

  /*
   * 데이터와 암호화키를 암호화한다.
   * 수행 결과
   *  - 암호화된 데이터 (Ciphertext || tag)
   *  - 수신자 인증서 H8
   *  - V: 임시(ephemeral) 공개키
   *  - C: 암호화된 AES 키
   *  - T: Authentication tag
   *  - nonce: AES nonce
   */
  int ret;
  struct Dot2ECPublicKey V;
  struct Dot2AESKey C;
  struct Dot2AESAuthTag T;
  struct Dot2AESNonce nonce;
  enc = dot2_EncryptData_2(data, data_size, key_input_h, pubkey_r, &V, &C, &T, &nonce, &ret);
  if (!enc) {
    return ret;
  }
  size_t enc_size = (size_t)ret;

  /*
   * RecipientInfo 정보를 채운다 (certRecipientInfo 형식을 사용한다)
   *  - hashedId: 수신자인증서에 대한 H8
   *  - V: 임시(ephemeral) 공개키
   *  - C: 암호화된 AES 키
   *  - T: Authentication tag
   */
  asn1_enc->recipients.count = 1;
  asn1_enc->recipients.tab = (dot2RecipientInfo *)asn1_mallocz_value(asn1_type_dot2RecipientInfo);
  if (asn1_enc->recipients.tab == NULL) {
    ret = -kDot2Result_NoMemory;
    goto err;
  }
  ret = dot2_ffasn1c_FillRecipientInfo(DOT2_GET_SHA256_H8(key_input_h->octs), &V, &C, &T, asn1_enc->recipients.tab);
  if (ret < 0) {
    goto err;
  }

  /*
   * SymmetricCiphertext 정보를 채운다.
   *  - 암호화된 데이터 (Ciphertext || tag)
   *  - nonce
   */
  ret = dot2_ffasn1c_FillSymmetricCiphertext(enc, enc_size, &nonce, &(asn1_enc->ciphertext));
  if (ret < 0) {
    goto err;
  }

  Log(kDot2LogLevel_Event, "Success to fill EncryptedData\n");
  return kDot2Result_Success;

err:
  free(enc);
  return ret;
}



/**
 * @brief 인증서요청문(SignedCertificateRequest) 내 signer 필드를 채운다.
 * @param[in] asn1_ec 등록인증서 asn.1 디코딩 정보 (signer 필드에 수납된다)
 * @param[out] asn1_signer 정보를 채울 signer 필드
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL
dot2_ffasn1c_FillSignedCertificateReqeust_Signer(dot2Certificate *asn1_ec, dot2SignerIdentifier *asn1_signer)
{
  Log(kDot2LogLevel_Event, "Fill SignedCertificateRequest.Signer - %p, %p\n", asn1_ec, asn1_signer);
  asn1_signer->choice = dot2SignerIdentifier_certificate;
  asn1_signer->u.certificate.count = 1;
  asn1_signer->u.certificate.tab = asn1_clone_value(asn1_type_dot2Certificate, asn1_ec);
  if (asn1_signer->u.certificate.tab == NULL) {
    return -kDot2Result_ASN1_EncodeSignedCertificateRequest;
  }
  /*
   * 등록인증서 정보 중 certRequestPermission 내 eeType은 BIT STRING 형식이며,
   * ffasn1c는 BIT STRING에 대한 COER 인코딩을 지원하지 않으므로(Default값일 경우 메시지에 넣지 않는다는 규칙),
   * eeType을 강제로 부재 처리한다.
   */
  dot2PsidGroupPermissions *asn1_perms = asn1_signer->u.certificate.tab->toBeSigned.certRequestPermissions.tab;
  asn1_perms->eeType_option = false;

  Log(kDot2LogLevel_Event, "Success to fill SignedCertificateRequest.Signer\n");
  return kDot2Result_Success;
}


/**
 * @brief 인증서요청문(SignedCertificateRequest) 내 Signature 필드를 채운다.
 * @param[in] ec_h 등록인증서 해시값 (메시지 서명 생성에 사용된다)
 * @param[in] eck_ec_priv_key 등록인증서 개인키 (메시지 서명 생성에 사용된다)
 * @param[in] asn1_tbs 서명 입력에 사용되는 ToBeSigned 필드 asn.1 정보 구조체
 * @param[out] asn1_sign 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_FillSignedCertificateReqeust_Signature(
  const struct Dot2SHA256 *ec_h,
  EC_KEY *eck_ec_priv_key,
  dot2ScopedCertificateRequest *asn1_tbs,
  dot2Signature *asn1_sign)
{
  Log(kDot2LogLevel_Event, "Fill SignedCertificateRequest.Signature\n");

  /*
   * 서명 입력에 사용될 ToBeSigned 필드를 인코딩한다.
   */
  uint8_t *encoded;
  asn1_ssize_t encoded_size = asn1_oer_encode(&encoded, asn1_type_dot2ScopedCertificateRequest, asn1_tbs);
  if ((!encoded) ||
      (encoded_size < 0)) {
    return -kDot2Result_ASN1_EncodeToBeSignedForSignature;
  }

  /*
   * 서명을 생성한다.
   */
  struct Dot2Signature sign;
  Dot2ECPointForm form = kDot2ECPointForm_Compressed;
  int ret = dot2_ossl_GenerateSignature(form, encoded, (size_t)encoded_size, ec_h, eck_ec_priv_key, &sign);
  free(encoded);
  if (ret < 0) {
    return ret;
  }

  /*
   * rSig 필드를 채운다.
   */
  asn1_sign->choice = dot2Signature_ecdsaNistP256Signature;
  uint8_t *R_y = sign.R_r.u.point.u.xy.y;
  if (R_y[DOT2_EC_256_KEY_LEN - 1] & 1) {
    asn1_sign->u.ecdsaNistP256Signature.rSig.choice = dot2EccP256CurvePoint_compressed_y_1;
    ASN1String *to = &(asn1_sign->u.ecdsaNistP256Signature.rSig.u.compressed_y_1);
    ret = dot2_ffasn1c_FillASN1String(sign.R_r.u.point.u.xy.x, DOT2_EC_256_KEY_LEN, to);
  } else {
    asn1_sign->u.ecdsaNistP256Signature.rSig.choice = dot2EccP256CurvePoint_compressed_y_0;
    ASN1String *to = &(asn1_sign->u.ecdsaNistP256Signature.rSig.u.compressed_y_0);
    ret = dot2_ffasn1c_FillASN1String(sign.R_r.u.point.u.xy.x, DOT2_EC_256_KEY_LEN, to);
  }
  if (ret < 0) {
    return ret;
  }

  /*
   * sSig 필드를 채운다.
   */
  ASN1String *to = &(asn1_sign->u.ecdsaNistP256Signature.sSig);
  return dot2_ffasn1c_FillASN1String(sign.s, DOT2_EC_256_KEY_LEN, to);
}

