/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


#ifndef V2X_SW_TCIA2023_DEFINES_H
#define V2X_SW_TCIA2023_DEFINES_H

/// V2X 인터페이스 최대개수
#define V2X_IF_MAX_NUM (2)
/// V2I/I2V 인터페이스 식별번호 (DSRC DUT에서 사용된다)
#define V2I_IF_IDX (0)
/// V2V 인터페이스 식별번호 (DSRC DUT에서 사용된다)
#define V2V_IF_IDX (1)
/// V2I & V2V 통합 인터페이스 식별번호 (LTE-V2X DUT에서 사용된다)
#define V2I_V2V_IF_IDX (0)

/// 문자열 버퍼 최대길이
#define MAXLINE 255
/// TCI 메시지 수신포트번호 기본값
#define DEFAULT_TCI_PORT (13001)
/// 0번 인터페이스 MAC 주소 문자열 기본값
#define DEFAULT_IF0_MAC_ADDR_STR "00:01:02:03:04:05"
/// 1번 인터페이스 MAC 주소 문자열 기본값
#define DEFAULT_IF1_MAC_ADDR_STR "00:01:02:03:04:06"
/// 인터페이스 기본 채널 (초기 값)
#define DEFAULT_IF_CHAN_NUM (190)
/// RCPI correction 기본값
#define DEFAULT_RCPI_CORRECTION (0)
/// 초기 위도 기본값
#define DEFAULT_INIT_LAT (374068270)
/// 초기 경도 기본값
#define DEFAULT_INIT_LON (1271016630)
/// 초기 고도 기본값
#define DEFAULT_INIT_ELEV (0)
/// BSM 자동전송 기본값
#define DEFAULT_BSM_AUTO_TX (false)
/// RSU용 CMHF 저장 디렉토리 기본값
#define DEFAULT_RSU_CMHF_DIR "certificates/cmhf/app"
/// OBU용 CMHF 저장 디렉토리 기본값
#define DEFAULT_OBU_CMHF_DIR "certificates/cmhf/pseudonym"
/// RCA 인증서 저장 디렉토리 기본값
#define DEFAULT_RCA_FILE "certificates/scc/rca"
/// ICA 인증서 저장 디렉토리 기본값
#define DEFAULT_ICA_FILE "certificates/scc/ica"
/// PCA 인증서 저장 디렉토리 기본값
#define DEFAULT_PCA_FILE "certificates/scc/pca"
/// 로그 메시지 출력 레벨 기본값
#define DEFAULT_TCIA2023_LOG_LEVEL (3)
/// V2X 라이브러리 로그 메시지 출력 레벨 기본값
#define DEFAULT_LIB_LOG_LEVEL (1)
/// J2945/1 Path 정보 백업 파일 경로
#define DEFAULT_PH_HEADING_BACKUP_FILE "path.info"
/// device 파일 경로
#define DEFAULT_DEV_NAME "/dev/spidev1.1"

/*
 * BSM 송신 관련 정의 (OBU인 경우에만 해당됨)
 */
#define DEFAULT_BSM_PSID (32) ///< BSM PSID 기본값
#define DEFAULT_BSM_CHANNEL (172) ///< BSM 송신 채널번호 기본값
#define DEFAULT_INIT_VEHICLE_WIDTH (150) ///< 초기 차량 전폭 기본값
#define DEFAULT_INIT_VEHICLE_LENGTH (250) ///< 초기 차량 전장 기본값

/// 기본 PSID
#define DEFAULT_PSID (kCvcoctci2023Psid_NA)
/// 기본 데이터레이트
#define DEFAULT_DATARATE (12)
/// 기본 송신파워
#define DEFAULT_TX_POWER (20)
/// 기본 반복 전송 주기
#define DEFAULT_REPEAT_RATE (50) // 5초당 50회 (즉, 1초당 10회)
/// 기본 컨텐츠 유형
#define DEFAULT_CONTENT_TYPE (kCvcoctci2023ContentType_Ieee16092Data)


/*
 * 로그 출력 매크로
 * 컴파일 시 "_DEBUG_*_"가 정의되지 않으면 로그출력 코드가 제거되어 컴파일된다.
 */
#if defined(_DEBUG_STDOUT_) || defined(_DEBUG_SYSLOG_)
/// 로그 출력 매크로
#define Log(l, f, a...) do { if (g_tcia_mib.log.tcia >= l) { TCIA2023_PrintLog(__FUNCTION__, f, ## a); } } while(0)
/// 에러레벨 로그 출력 매크로
#define Err(f, a ...) do { if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Err) { TCIA2023_PrintLog(__FUNCTION__, f, ## a); } } while(0)
#else
#define Log(l, f, a ...) do {} while(0)
#define Err(f, a ...) do {} while(0)
#endif


#endif //V2X_SW_TCIA2023_DEFINES_H
