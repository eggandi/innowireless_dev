/** 
 * @file
 * @brief ffasn1c 라이브러리를 이용한 데이터(수신메시지) 처리 기능 구현 파일
 * @date 2020-05-17
 * @author gyun
 */

// 시스템 헤더 파일
#include <assert.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "dot2-ffasn1c.h"
#include "dot2-ffasn1c-inline.h"
#include "certificate/cert-info/dot2-cert-info-inline.h"


/**
 * @brief ToBeSignedData 필드에 대한 해시값(서명 연산의 입력으로 사용)을 계산하여 반환한다.
 * @param[in] asn1_tbs ToBeSignedData 필드 asn.1 디코딩 정보
 * @param[out] tbs_h 계산된 해시값이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_CalculateToBeSignedDataHash(const dot2ToBeSignedData *asn1_tbs, struct Dot2SHA256 *tbs_h)
{
  Log(kDot2LogLevel_Event, "Calculate H(ToBeSignedData)\n");

  /*
   * ToBeSigneData 필드를 OER 인코딩한다.
   */
  uint8_t *buf = NULL;
  asn1_ssize_t encoded_size = asn1_oer_encode(&buf, asn1_type_dot2ToBeSignedData, asn1_tbs);
  if ((encoded_size < 0) ||
      (buf == NULL)) {
    Err("Fail to calculate H(ToBeSignedData) - dot2_ffasn1c_EncodeToBeSignedData() failed\n");
    return -kDot2Result_SPDU_EncodeSPDU;
  }

  /*
   * 인코딩된 데이터에 대한 해시값을 계산한다.
   */
  SHA256(buf, encoded_size, tbs_h->octs);

  /*
   * 인코딩 데이터를 해제한다.
  */
  free(buf);

  Log(kDot2LogLevel_Event, "Success to calculate H(ToBeSignedData)\n");
  return kDot2Result_Success;
}


/**
 * @brief digest 형식의 SignerIdentifier 필드를 처리하고, 서명검증에 필요한 정보를 SPDU 처리 작업 정보에 반환한다.
 * @param[in] h8 HashedId8(다이제스트) 형식의 signer_id (= 서명자(인증서)의 H8값)
 * @param[out] work SPDU 처리 작업 정보
 * @retval kDot2Result_SPDUProcess_RequestSignatureVerification: 성공 (서명검증 요청)
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_ProcessSignerIdentifier_Digest(const uint8_t *h8, struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process digest signer id("H8_FMT")\n", H8_FMT_ARGS(h8));

  /*
   * 인증서정보테이블에서 해당 signer_id와 동일한 hashedid8값을 갖는 인증서정보를 찾아,
   * 인증서정보에 저장된 H(서명자인증서)와 서명자 공개키 정보를 SPDU 처리작업정보에 저장한다(서명검증에 사용하기 위해)
   * 서명자인증서가 폐기되었으면 실패를 반환한다.
   */
  int ret = -kDot2Result_SPDU_NoSignerIdCertInTable;
  struct Dot2EECertCacheEntry *signer_entry = dot2_FindEECertCacheWithH8(h8);
  if (signer_entry) {
    if (signer_entry->revoked) {
      Err("Fail to process digest signer id - signer is revoked\n");
      ret = -kDot2Result_SPDUProcess_SignerRevoked;
    } else {
      signer_entry->expiry = work->data.params.rx_time + DOT2_EE_CERT_CACHE_VALID_USEC;
      work->data.signer_entry = signer_entry;
      memcpy(work->data.signer_h.octs, signer_entry->cert_h.octs, DOT2_SHA_256_LEN);
#if defined(_SIGN_VERIFY_OPENSSL_)
      assert(signer_entry->contents.eck_verify_pub_key);
      work->data.eck_signer_pub_key = EC_KEY_dup(signer_entry->contents.eck_verify_pub_key);
      assert(work->data.eck_signer_pub_key);
      return kDot2Result_SPDUProcess_RequestSignatureVerification;
#elif defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
      memcpy(&(work->data.signer_pub_key), &(signer_entry->contents.verify_pub_key), sizeof(struct Dot2ECPublicKey));
      ret = kDot2Result_SPDUProcess_RequestSignatureVerification;
#else
#error "Signature verification method is not defined"
#endif
    }
  }
  return ret;
}


/**
 * @brief SignerIdentifierInput 정보(=SignerIdentifier 필드 OER 인코딩 바이트열)를 할당한다.
 * @param[in] asn1_cert 인코딩할 SignerIdentifier(=certificate) asn.1 디코딩 정보
 * @param[out] encoded_size SignerIdentifierInput 정보의 길이가 저장될 변수 포인터
 * @return SignerIdentifierInput 정보 (호출자는 free()를 통해 이를 해제해 주어야 한다)
 * @retval NULL: 실패
 */
static inline uint8_t *
dot2_ffasn1c_AllocateSignerIdentifierInput(const dot2Certificate *asn1_cert, size_t *encoded_size)
{
  return dot2_ffasn1c_EncodeCertificate(asn1_cert, encoded_size);
}


/**
 * @brief 새로운 서명자(인증서)에 대한 인증서정보 엔트리를 생성하고 정보를 저장한다.
 * @param[in] asn1_signer 서명자(인증서) asn.1 디코딩 정보
 * @param[in] signer 서명자(인증서) COER 인코딩 바이트열
 * @param[in] signer_size 서명자(인증서) COER 인코딩 바이트열의 길이
 * @param[in] signer_h 서명자(인증서) 해시값
 * @param[in] alloc_time 인증서정보 엔트리 생성시각
 * @param[out] err 실패 시 에러값(-Dot2ResultCode)이 반환될 변수 포인터
 * @return 생성된 인증서정보 엔트리 포인터 (사용 후 free() 되어야 한다)
 * @retval NULL: 실패
 */
static struct Dot2EECertCacheEntry * dot2_ffasn1c_AllocateEECertCacheEEntry(
  const dot2Certificate *asn1_signer,
  const uint8_t *signer,
  Dot2CertSize signer_size,
  const struct Dot2SHA256 *signer_h,
  Dot2Time64 alloc_time,
  int *err)
{
  const uint8_t *signer_h8 = DOT2_GET_SHA256_H8(signer_h->octs);
  Log(kDot2LogLevel_Event, "Allocate new signer("H8_FMT") EE cert cache entry\n", H8_FMT_ARGS(signer_h8));

  /*
   * 인증서정보 엔트리를 생성한다.
   */
  struct Dot2EECertCacheEntry *cert_entry = dot2_AllocateEECertCacheEntry(signer, signer_size);
  assert(cert_entry);

  /*
   * 인증서 해시값을 인증서정보 엔트리에 저장한다.
   */
  memcpy(cert_entry->cert_h.octs, signer_h->octs, DOT2_SHA_256_LEN);

  /*
   * Certificate 필드 내 정보를 파싱하여 인증서정보 엔트리에 저장한다.
   */
  int ret = dot2_ffasn1c_ParseEECertContents_2(asn1_signer, &(cert_entry->contents));
  if (ret < 0) {
    goto err;
  }

  /*
   * 인증서체인을 구성한다 = 상위인증서 인증서정보 엔트리에 대한 포인터를 참조한다.
   */
  ret = dot2_ConstructEECertChain(cert_entry);
  if (ret < 0) {
    goto err;
  }

  /*
   * 정보의 만기시각을 저장한다.
   */
  cert_entry->expiry = alloc_time + DOT2_EE_CERT_CACHE_VALID_USEC;

  Log(kDot2LogLevel_Event, "Success to allocate new signer EE cert cache entry\n");
  return cert_entry;

err:
  *err = ret;
  free(cert_entry);
  return NULL;
}


/**
 * @brief certificate 형식의 SignerIdentifier 필드를 처리한다.
 * @param[in] asn1_data SequenceOfCertificate 필드 asn.1 디코딩 정보
 * @param[in] work SPDU 처리 작업 정보
 * @retval kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstruction: 성공(공개키 재구성 요청)
 * @retval kDot2Result_SPDUProcess_RequestSignatureVerification: 성공(서명 검증 요청)
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ProcessSignerIdentifier_Certificates(
  const dot2SequenceOfCertificate *asn1_data,
  struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process certificates signer id\n");

  if ((asn1_data->tab == NULL) || (asn1_data->count == 0)) {
    Err("Fail to process certificate signer id - no signer id in message\n");
    return -kDot2Result_NoSignerIdInSPDU;
  }

  /*
   * SignerIdentifierInput 정보(=OER 인코딩된 SignerIdentifier)를 계산한다.
   * SignerIdentifier = 메시지에 서명한 서명자(인증서)
   */
  size_t encoded_signer_size;
  const dot2Certificate *asn1_signer_id = asn1_data->tab;
  uint8_t *encoded_signer = dot2_ffasn1c_AllocateSignerIdentifierInput(asn1_signer_id, &encoded_signer_size);
  if (encoded_signer == NULL) {
    Err("Fail to process certificate signer id - dot2_ffasn1c_AllocateSignerIdentifierInput() failed\n");
    return -kDot2Result_FailToOerEncode;
  }

  /*
   * H(SignerIdentifierInput)를 계산한다.
   */
  struct Dot2SHA256 signer_h;
  SHA256(encoded_signer, encoded_signer_size, signer_h.octs);

  /*
   * 서명자(인증서)에 대한 정보가 인증서정보테이블에 이미 존재하는지 확인하여,
   * 존재할 경우에는 공개키 재구성 동작을 수행할 필요 없으므로 서명 검증을 위한 필요 정보(서명자 해시, 서명자 공개키)만 저장한 후 종료한다.
   * -> 서명 검증이 수행된다.
   * 서명자인증서가 폐기되었으면 실패를 반환한다.
   */
  uint8_t *signer_h8 = DOT2_GET_SHA256_H8(signer_h.octs);
  struct Dot2EECertCacheEntry *signer_entry = dot2_FindEECertCacheWithH8(signer_h8);
  if (signer_entry) {
    if (signer_entry->revoked) {
      Err("Fail to process certificate signer id - signer is revoked\n");
      free(encoded_signer);
      return -kDot2Result_SPDUProcess_SignerRevoked;
    } else {
      signer_entry->expiry = work->data.params.rx_time + DOT2_EE_CERT_CACHE_VALID_USEC;
      work->data.signer_entry = signer_entry;
      memcpy(work->data.signer_h.octs, signer_entry->cert_h.octs, DOT2_SHA_256_LEN);
#if defined(_SIGN_VERIFY_OPENSSL_)
      free(encoded_signer);
      assert(signer_entry->contents.eck_verify_pub_key);
      work->data.eck_signer_pub_key = EC_KEY_dup(signer_entry->contents.eck_verify_pub_key);
      assert(work->data.eck_signer_pub_key);
      return kDot2Result_SPDUProcess_RequestSignatureVerification;
#elif defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
      free(encoded_signer);
      memcpy(&(work->data.signer_pub_key), &(signer_entry->contents.verify_pub_key), sizeof(struct Dot2ECPublicKey));
      return kDot2Result_SPDUProcess_RequestSignatureVerification;
#else
#error "Signature verification method is not defined"
#endif
    }
  }

  /*
   * 서명자(인증서)에 대한 정보가 인증서정보테이블에 존재하지 않으면,
   * 서명자(인증서)가 Implicit 인증서일 경우 공개키 재구성을 수행한다.
   * 서명자(인증서)가 Explicit 인증서일 경우 서명 검증을 수행한다
   *   -> 현 시점 표준 기준으로, SPDU에 대한 서명자는 모두 Implicit 인증서이므로 Explicit 인증서에 대한 처리는 수행하지 않는다.
   */

  /*
   * 서명자(인증서)에 대한 인증서정보 엔트리를 새롭게 할당한다.
   */
  int ret;
  struct Dot2EECertCacheEntry *new_signer_entry = dot2_ffasn1c_AllocateEECertCacheEEntry(asn1_signer_id,
                                                                                         encoded_signer,
                                                                                         encoded_signer_size,
                                                                                         &signer_h,
                                                                                         work->data.params.rx_time,
                                                                                         &ret);
  if (new_signer_entry == NULL) {
    free(encoded_signer);
    return ret;
  }

  /*
   * 서명자(인증서) 해시를 SPDU 처리작업정보에 저장한다.
   */
  memcpy(work->data.signer_h.octs, new_signer_entry->cert_h.octs, DOT2_SHA_256_LEN);

#if defined(_SIGN_VERIFY_SAF5400_)
  /*
   * 서명자(인증서)가 Implicit 인증서이고, 공개키재구성값이 압축 형식이면 공개키재구성값 복구를 요청한다.
   * 현 버전의 표준에 따라(2016), 공개키재구성값이 비압축 형식인 경우는 지원하지 않는다.
   * 서명자(인증서)가 Explicit 인증서인 경우는 지원하지 않는다.
   */
  struct Dot2CertVerificationKeyIndicator *vkey = &(new_signer_entry->contents.common.verify_key_indicator);
  if (vkey->type == kDot2CertVerificationKeyIndicatorType_ReconstructValue) {
    if ((vkey->key.u.point.form == kDot2ECPointForm_Compressed_y_0) ||
        (vkey->key.u.point.form == kDot2ECPointForm_Compressed_y_1)) {
      work->data.new_signer_entry = new_signer_entry;
      ret = kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstructionValueRecovery;
    } else {
      Err("Fail to process certificate signer id - uncompressed pubkey recon_val in implicit cert is not supported\n");
      ret = -kDot2Result_SPDUProcess_UncompressedPublicKeyReconstructionValueIsNotSupported;
    }
  } else {
    Err("Fail to process certificates signer id - Explicit signer is not supported\n");
    ret = -kDot2Result_ExplicitSPDUSignerIsNotSupported;
  }
#else
  /*
   * 서명자(인증서)가 Implicit 인증서인 경우 공개키 재구성을 요청한다.
   * 서명자(인증서)가 Explicit 인증서인 경우는 지원하지 않는다.
   */
  if (new_signer_entry->contents.common.verify_key_indicator.type == kDot2CertVerificationKeyIndicatorType_ReconstructValue) {
    work->data.new_signer_entry = new_signer_entry;
    ret = kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstruction;
  } else {
    Err("Fail to process certificates signer id - Explicit signer is not supported\n");
    ret = -kDot2Result_ExplicitSPDUSignerIsNotSupported;
  }
#endif

  free(encoded_signer);
  return ret;
}


/**
 * @brief 디코딩된 SignerIdentifier 필드 정보를 처리한다.
 * @param[in] asn1_data SignerIdentifier 필드 asn.1 디코딩 정보
 * @param[in] work SPDU 처리 작업 정보
 * @retval 0 이상: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ProcessSignerIdentifier(dot2SignerIdentifier *asn1_data, struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process SignerIdentifier\n");

  int ret;
  switch (asn1_data->choice) {
    /*
     * Digest 형식의 signer_id를 처리한다.
     */
    case dot2SignerIdentifier_digest:
      work->data.parsed->spdu.signed_data.signer_id_type = kDot2SignerId_Digest;
      ret = dot2_ffasn1c_ProcessSignerIdentifier_Digest(asn1_data->u.digest.buf, work);
      break;

      /*
       * Certificate 형식의 signer_id를 처리한다.
       */
    case dot2SignerIdentifier_certificate:
      work->data.parsed->spdu.signed_data.signer_id_type = kDot2SignerId_Certificate;
      ret = dot2_ffasn1c_ProcessSignerIdentifier_Certificates(&(asn1_data->u.certificate), work);
      break;

    default:
      Err("Fail to process SignerIdentifier - invalid signer id type %d\n", asn1_data->choice);
      ret = -kDot2Result_InvalidSignerIdType;
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 SignedData 필드 정보를 파싱하여 패킷파싱데이터에 저장하고 처리한다.
 * @param[in] asn1_data SignedData 필드 asn.1 디코딩 정보
 * @param[in] work SPDU 처리 작업 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseAndProcessSignedData(dot2SignedData *asn1_data, struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Parse and process SignedData\n");

  /*
   * ToBeSignedData 필드 정보를 파싱하여 패킷파싱데이터에 저장한다.
   */
  int ret = dot2_ffasn1c_ParseToBeSignedData(&(asn1_data->tbsData), work->data.parsed);
  if (ret < 0) {
    return ret;
  }

  /*
   * H(ToBeSignedData)를 계산하여 SPDU 처리 작업정보에 저장한다. (이후 서명검증을 위한 입력값으로 사용된다)
   */
  ret = dot2_ffasn1c_CalculateToBeSignedDataHash(&(asn1_data->tbsData), &(work->data.tbs_h));
  if (ret < 0) {
    return ret;
  }

  /*
   * Signature 필드 정보를 파싱하여 SPDU 처리 작업정보에 저장한다. (이후 서명검증에 사용된다.)
   */
  ret = dot2_ffasn1c_ParseSignature(&(asn1_data->signature), &(work->data.sign));
  if (ret < 0) {
    return ret;
  }

  pthread_mutex_lock(&(g_dot2_mib.mtx));

  /*
   * signer_id 필드를 처리한다.
   */
  ret = dot2_ffasn1c_ProcessSignerIdentifier(&(asn1_data->signer), work);

  /*
   * signer_id 필드 처리가 성공하면 Consistency & relevance check를 수행한다.
   */
  int ret1 = kDot2Result_Success;
  if (ret == kDot2Result_SPDUProcess_RequestSignatureVerification) {
    ret1 = dot2_ProcessSPDUConsistencyAndRelevanceCheck(work, work->data.signer_entry);
#if defined(_SIGN_VERIFY_SAF5400_)
  } else if (ret == kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstructionValueRecovery) {
    ret1 = dot2_ProcessSPDUConsistencyAndRelevanceCheck(work, work->data.new_signer_entry);
#else
  } else if (ret == kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstruction) {
    ret1 = dot2_ProcessSPDUConsistencyAndRelevanceCheck(work, work->data.new_signer_entry);
#endif
  }

  pthread_mutex_unlock(&(g_dot2_mib.mtx));

  /*
   * Consistency & relevance check 결과 더이상의 검증이 불필요하면, (Security profile의 verify = false일 경우)
   * 공개키요청/서명요청 대신 성공을 리턴하여 SPDU 처리절차를 종료하도록 한다.
   */
  if (ret1 == kDot2Result_SPDUVerificationInNotNecessary) {
    ret = kDot2Result_Success;
  } else if (ret1 < 0) {
    ret = ret1;
  }

  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 Ieee1609Dot2Data 메시지 정보를 파싱하고 처리한다.
 * @param[in] asn1_data Ieee1609Dot2Data 메시지 asn.1 디코딩 정보
 * @param[in] work SPDU 처리 작업 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int
dot2_ffasn1c_ParseAndProcessIeee1609Dot2Data(dot2Ieee1609Dot2Data *asn1_data, struct Dot2SPDUProcessWork *work)
{
  int ret;
  Log(kDot2LogLevel_Event, "Parse and process Ieee1609Dot2Data\n");

  /*
   * 프로토콜 버전을 확인한다.
   */
  if (asn1_data->protocolVersion != DOT2_PROTOCOL_VERSION) {
    Err("Fail to parse and process Ieee1609Dot2Data - invalid protocol version %d\n", asn1_data->protocolVersion);
    return -kDot2Result_InvalidProtocolVersion;
  }

  /*
   * 컨텐츠 유형별로 파싱/처리한다.
   */
  switch (asn1_data->content.choice) {
    case dot2Ieee1609Dot2Content_unsecuredData:
      work->data.parsed->spdu.content_type = kDot2Content_UnsecuredData;
      ret = dot2_ffasn1c_ParseUnsecuredData(&(asn1_data->content.u.unsecuredData), work->data.parsed);
      break;
    case dot2Ieee1609Dot2Content_signedData:
      work->data.parsed->spdu.content_type = kDot2Content_SignedData;
      ret = dot2_ffasn1c_ParseAndProcessSignedData(&(asn1_data->content.u.signedData), work);
      break;
    case dot2Ieee1609Dot2Content_encryptedData:
      work->data.parsed->spdu.content_type = kDot2Content_EncryptedData;
      Err("Fail to parse and process Ieee1609Dot2Data - encrypted data is not supported\n");
      ret = -kDot2Result_NotSupportedContentType;
      break;
    case dot2Ieee1609Dot2Content_signedCertificateRequest:
      work->data.parsed->spdu.content_type = kDot2Content_SignedCertificateRequest;
      Err("Fail to parse and process Ieee1609Dot2Data - signed certificate request is not supported\n");
      ret = -kDot2Result_NotSupportedContentType;
      break;
    default:
      Err("Fail to parse and process Ieee1609Dot2Data - invalid content type %d\n", asn1_data->content.choice);
      ret = -kDot2Result_InvalidContentType;
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 SPDU를 파싱하고 처리한다.
 * @param[in] work SPDU 처리 작업 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseAndProcessSPDU(struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Parse and process SPDU\n");

  /*
   * SPDU를 디코딩한다.
   */
  struct dot2Ieee1609Dot2Data *dot2_data = dot2_ffasn1c_DecodeSPDU(work->data.spdu, work->data.spdu_size);
  if (dot2_data == NULL) {
    Err("Fail to parse and process SPDU - dot2_ffasn1c_DecodeSPDU() failed\n");
    return -kDot2Result_SPDU_DecodeSPDU;
  }

  /*
   * 디코딩된 SPDU 정보를 파싱하고 처리한다.
   */
  int ret = dot2_ffasn1c_ParseAndProcessIeee1609Dot2Data(dot2_data, work);

  /*
   * 디코딩된 정보를 해제한다.
   */
  asn1_free_value(asn1_type_dot2Ieee1609Dot2Data, dot2_data);
  return ret;
}