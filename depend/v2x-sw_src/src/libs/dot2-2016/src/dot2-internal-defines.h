/** 
 * @file
 * @brief libdot2 라이브러리 내부에서 사용되는 각종 변수형, 매크로, 정의값 등을 정의한 파일
 * @date 2020-02-18
 * @author gyun
 */


#ifndef V2X_SW_DOT2_INTERNAL_DEFINES_H
#define V2X_SW_DOT2_INTERNAL_DEFINES_H

/// IEEE 1609.2 프로토콜 버전
#define DOT2_PROTOCOL_VERSION (3)

/// AES-CCM-128 암호화 Tag 바이트열 길이
#define DOT2_AES_128_TAG_LEN (DOT2_AES_128_LEN)
/// AES-CCM-128 Nonce 바이트열 길이
#define DOT2_AES_128_NONCE_LEN (12)
/// Authentication Tag 바이트열 길이
#define DOT2_AUTH_TAG_LEN (16)

/// Self-signed 인증서 바이트열에서 ToBeSignedCert 영역 오프셋을 가져오는 매크로.
#define DOT2_GET_SELF_SIGNED_CERT_TBS(cert) ((cert) + 5)
/// Self-signed Explicit 인증서 바이트열에서 ToBeSignedCert 영역의 길이를 가져오는 매크로.
#define DOT2_GET_SELF_SIGNED_EXPLICIT_CERT_TBS_SIZE(cert_size) ((cert_size) - 5 - 66)
/// 상위인증서에 의해 서명된 인증서 바이트열에서 ToBeSignedCert 영역 오프셋을 가져오는 매크로.
#define DOT2_GET_ISSUER_SIGNED_CERT_TBS(cert) ((cert) + 12)
/// 상위인증서에 의해 서명된 Explicit 인증서 바이트열에서 ToBeSignedCert 영역의 길이를 가져오는 매크로.
#define DOT2_GET_ISSUER_SIGNED_EXPLICIT_CERT_TBS_SIZE(cert_size) ((cert_size) - 12 - 66)
/// 상위인증서에 의해 서명된 Implicit 인증서 바이트열에서 ToBeSignedCert 영역의 길이를 가져오는 매크로.
#define DOT2_GET_ISSUER_SIGNED_IMPLICIT_CERT_TBS_SIZE(cert_size) ((cert_size) - 12)

/// EC point 바이트열에서 X 좌표 오프셋을 가져오는 매크로
#define DOT2_GET_X_IN_EC_POINT_OCTETS(ecp) ((ecp) + 1/*kDot2EcLen_PointPrefix*/)
/// EC point 바이트열에서 Y 좌표 오프셋을 가져오는 매크로 (Uncompressed 형식일 때에만 사용 가능)
#define DOT2_GET_Y_IN_EC_POINT_OCTETS(ecp,size) ((ecp) + 1/*kDot2EcLen_PointPrefix*/ + (size)/*DOT2_EC_256_KEY_LEN*/)
/// Ieee1609Dot2Data 바이트열에서 tbsData 영역 오프셋을 가져오는 매크로 \n
/// O0: protocolVersion, O1: Ieee1609Dot2Content CHOICE tag, O2: signedData.hashId(0), O3: tbsData \n
/// 바이트열 시작점과 tbsData 데이터 사이의 3바이트는 항상 고정길이(3)를 가진다.
#define DOT2_GET_TBS_DATA(msg) ((msg) + 3)

/// signed 형 elevation 값을 unsigned 형으로 변경한다.
/// 1609.3이나 J2735에서는 signed 형 값을 갖지만, 1609.2에서는 unsigned 형 값을 가진다.
#define DOT2_CONVERT_TO_UNSIGNED_ELEV(elev) ((elev) + 4096)

/// SHA256 해시값에 대한 H8값을 구하는 매크로
#define DOT2_GET_SHA256_H1(h) *((h) + (DOT2_SHA_256_LEN - 1))
/// SHA256 해시값에 대한 H8값을 구하는 매크로
#define DOT2_GET_SHA256_H8(h) ((h) + (DOT2_SHA_256_LEN - 8))
/// SHA256 해시값에 대한 H10값을 구하는 매크로
#define DOT2_GET_SHA256_H10(h) ((h) + (DOT2_SHA_256_LEN - 10))



/// SSP 최대 길이
#define DOT2_SSP_MAX_LEN 31

/// Issuer ID(발급인증서 식별자) 길이 - 발급인증서에 대한 HashedId8 값이므로 길이는 8이다.
#define DOT2_ISSUER_CERT_ID_LEN (8)
/// CRACA ID 길이
#define DOT2_CRACA_ID_LEN (3)
/// LinkageValue 길이
#define DOT2_LINKAGE_VALUE_LEN (9)
/// GroupLinkageValue 내 jValue 길이
#define DOT2_GROUP_LINKAGE_J_VALUE_LEN (4)

/// LA(Linkage Authority) ID 길이
#define DOT2_LA_ID_LEN (2)
/// Linkage seed의 길이
#define DOT2_LINKAGE_SEED_LEN (16)

/// 리눅스시스템시간(1970-01-01 00:00:00)과 TAI(2004-01-01 00:00:00)의 초 차이
/// (https://www.calculator.net/time-duration-calculator.html)
#define SYSTIME_TAI_SEC_DIFF (1072915200ULL)
/// 리눅스시스템시간과 TAI의 마이크로초 차이
#define SYSTIME_TAI_USEC_DIFF (SYSTIME_TAI_SEC_DIFF * 1000000ULL)
/// 거리 계산에 사용되는 파이 값
#define PI 3.14159265358979323846

/// HTTP URL 내 호스트(서버)이름(IP 주소도 가능) 문자열 최대 길이 (예: ra.scms.or.kr) (임의로 지정)
#define DOT2_HTTP_URL_HOSTNAME_STR_MAX_LEN (100)
/// HTTP URL 내 포트번호 문자열 최대길이 (0~65535)
#define DOT2_HTTP_URL_PORT_STR_MAX_LEN (5)
/// HTTP URL 내 Path(서비스명) 문자열 최대길이 (예: /provision-application-certificate) (임의로 지정)
#define DOT2_HTTP_URL_PATH_STR_MAX_LEN (100)
/// HTTP URL 문자열 최대길이
#define DOT2_HTTP_URL_STR_MAX_LEN (8/*"https://"*/ + DOT2_HTTP_URL_HOSTNAME_STR_MAX_LEN + 1/*":"*/ + \
                                   DOT2_HTTP_URL_PORT_STR_MAX_LEN + DOT2_HTTP_URL_PATH_STR_MAX_LEN)
/// HTTP에 사용되는 파일명 최대길이
#define DOT2_HTTP_FILE_NAME_MAX_LEN (1000)
/// HTTP 헤더에 수납되는 라인 최대길이 (파일명 최대길이에 "If-None-Match: " 추가)
#define DOT2_HTTP_HEADER_LINE_MAX_LEN (DOT2_HTTP_FILE_NAME_MAX_LEN+15)


/*
 * 함수 속성 정의 매크로
 */
/// 공개 API 함수임을 나타내기 위한 매크로
#define OPEN_API __attribute__((visibility("default")))
#ifdef _EXPORT_INTERNAL_FUNC_
/// (내부함수 단위테스트를 위해) 내부함수를 외부에서 호출 가능하도록 지정
#define INTERNAL __attribute__((visibility("default")))
#else
/// 공개 API 가 아닌 내부함수로 지정 (라이브러리 외부에서 호출 불가)
#define INTERNAL __attribute__((visibility("hidden")))
#endif

/*
 * 로그출력 매크로
 * 컴파일 시 "_DEBUG_*_"가 정의되지 않으면 로그출력 코드가 제거되어 컴파일된다.
 */
#if defined(_DEBUG_STDOUT_) || defined(_DEBUG_SYSLOG_)
/// 로그 출력 매크로
#define Log(l, f, a...) do { if (g_dot2_log >= l) { dot2_PrintLog(__FUNCTION__, f, ## a); } } while(0)
/// 에러레벨 로그 출력 매크로
#define Err(f, a ...) do { if (g_dot2_log >= kDot2LogLevel_Err) { dot2_PrintLog(__FUNCTION__, f, ## a); } } while(0)
#else
#define Log(l, f, a ...) do {} while(0)
#define Err(f, a ...) do {} while(0)
#endif


/// HashedId8 출력 형식 매크로
#define H8_FMT "0x%02X%02X%02X%02X%02X%02X%02X%02X"
/// HashedId8 출력 파라미터 매크로
#define H8_FMT_ARGS(h) h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
/// HashedId10 출력 형식 매크로
#define H10_FMT "0x%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
/// HashedId8 출력 파라미터 매크로
#define H10_FMT_ARGS(h) h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9]


#endif //V2X_SW_DOT2_INTERNAL_DEFINES_H
