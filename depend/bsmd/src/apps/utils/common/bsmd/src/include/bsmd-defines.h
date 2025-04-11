/** 
 * @file
 * @brief 각종 정의
 * @date 2022-09-17
 * @author gyun
 */


#ifndef V2X_SW_BSMD_DEFINES_H
#define V2X_SW_BSMD_DEFINES_H

/// V2V 인터페이스 식별번호
#define V2V_IF_IDX (0)
/// 문자열 버퍼 최대길이
#define MAXLINE (255)
/// V2V 채널번호
#define V2V_CHAN_NUM (172)
/// CMHF 저장 디렉토리 기본값
#define CMHF_DIR "certificates/cmhf/pseudonym"
/// RCA 인증서 저장 디렉토리 기본값
#define RCA_FILE "certificates/scc/rca"
/// ICA 인증서 저장 디렉토리 기본값
#define ICA_FILE "certificates/scc/ica"
/// PCA 인증서 저장 디렉토리 기본값
#define PCA_FILE "certificates/scc/pca"
/// 로그 메시지 출력 레벨 기본값
#define DEFAULT_BSMD_LOG_LEVEL (2)
/// V2X 라이브러리 로그 메시지 출력 레벨 기본값
#define DEFAULT_LIB_LOG_LEVEL (1)
/// LTE-V2X 통신 디바이스 기본값
#define DEFAULT_DEV_NAME "/dev/spidev1.1"

/// BSM PSID
#define BSM_PSID (32)
/// BSM 데이터레이트 (500kbps)
#define BSM_DATARATE (12)
/// BSM 송신파워 (dBm)
#define BSM_TX_POWER (20)
/// BSM 송신주기 (밀리초)
#define BSM_TX_INTERVAL (100)
/// BSM 기본 우선순위
#define BSM_DEFAULT_PRIORITY (5)
/// BSM 이벤트 우선순위
#define BSM_EVENT_PRIORITY (7)

/// 차량 전폭 기본값
#define VEHICLE_WIDTH (150)
/// 차량 전장 기본값
#define VEHICLE_LENGTH (250)

/// J2945/1 Path 정보 백업 파일 경로
#define PATH_INFO_BACKUP_FILE "path.info"

/*
 * 로그 출력 매크로
 * 컴파일 시 "_DEBUG_*_"가 정의되지 않으면 로그출력 코드가 제거되어 컴파일된다.
 */
#if defined(_DEBUG_STDOUT_) || defined(_DEBUG_SYSLOG_)
/// 로그 출력 매크로
#define Log(l, f, a...) do { if (g_bsmd_mib.log.bsmd >= l) { BSMD_PrintLog(__FUNCTION__, f, ## a); } } while(0)
/// 에러레벨 로그 출력 매크로
#define Err(f, a ...) do { if (g_bsmd_mib.log.bsmd >= kBSMDLogLevel_Err) { BSMD_PrintLog(__FUNCTION__, f, ## a); } } while(0)
#else
#define Log(l, f, a ...) do {} while(0)
#define Err(f, a ...) do {} while(0)
#endif

#endif //V2X_SW_BSMD_DEFINES_H
