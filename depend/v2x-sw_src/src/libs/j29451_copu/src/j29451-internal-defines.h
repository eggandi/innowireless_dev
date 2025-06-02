/** 
 * @file
 * @brief j29451 라이브러리 내부에서 사용되는 정의값 및 매크로 등을 정의한 헤더 파일
 * @date 2020-10-03
 * @author gyun
 */


#ifndef V2X_SW_J29451_INTERNAL_DEFINES_H
#define V2X_SW_J29451_INTERNAL_DEFINES_H


/// Temporary ID 길이
#define J29451_TEMPORARY_ID_LEN (4)

/// BSM msg count 값 증가
#define J29451_INCREASE_BSM_MSG_CNT(cnt) (((cnt) + 1) % 128)

#if defined(_TARGET_STD_VER_2016_)
/// Heading 값을 잠그기 위한 속도 임계값
#define J29451_SPEED_THRESH_LATCH_HEADING (55.555)
/// Heading 값을 풀기 위한 속도 임계값
#define J29451_SPEED_THRESH_UNLATCH_HEADING (69.444)
#elif defined(_TARGET_STD_VER_2020_)
#ifdef _DRIVING_TEST_ // 현재 Wayties TS는 Latch/Unlatch 조건에 대해서 2016 표준 버전을 기준으로 판정하고 있다.
/// Heading 값을 잠그기 위한 속도 임계값
#define J29451_SPEED_THRESH_LATCH_HEADING (55.555)
/// Heading 값을 풀기 위한 속도 임계값
#define J29451_SPEED_THRESH_UNLATCH_HEADING (69.444)
#else
/// Heading 값을 잠그기 위한 속도 임계값
#define J29451_SPEED_THRESH_LATCH_HEADING (55.0)
/// Heading 값을 풀기 위한 속도 임계값
#define J29451_SPEED_THRESH_UNLATCH_HEADING (69.0)
#endif
#endif

/// 중력가속도 값 (m/s^2 단위)
#define J29451_GRAVITATIONAL_ACCELERATION (9.79641227572363)
/// Hard braking 판정 임계값 (m/s^2 단위) (0.4G 보다 큰 값으로 감속)
#define J29451_HARD_BRAKIG_THRESHOLD (J29451_GRAVITATIONAL_ACCELERATION * 0.4 * -1)

/// 가속도 Butterworth filter order (2~16 대입 시험을 통해 레퍼런스 장비의 결과와 가장 유사한 값 선택)
#define J29451_BW_FILTER_ORDER (2)
/// 가속도 Butterworth filter sampling frequeny = 10Hz (= 가속도값 획득 주기)
#define J29451_BW_FILTER_SAMPLING_FREQ (10)
/// 가속도 Butterworth filter cutoff frequecy = 1Hz (per SAE J2945/1a-2020 p.77)
#define J29451_BW_FILTER_CUTOFF_FREQ (1)
/// 가속도 Butterworth filter 조정 계수
#define J29451_BW_FILTER_ADJUST_FACTOR (1.0)


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
#define Log(l, f, a...) do { if (g_j29451_log >= l) { j29451_PrintLog(__FUNCTION__, f, ## a); } } while(0)
/// 에러 레벨 로그 출력 매크로
#define Err(f, a ...) do { if (g_j29451_log >= kJ29451LogLevel_Err) { j29451_PrintLog(__FUNCTION__, f, ## a); } } while(0)
#else
#define Log(l, f, a ...) do {} while(0)
#define Err(f, a ...) do {} while(0)
#endif

#ifdef _D_CLEANUPHEAD
	TAILQ_HEAD(CleanupHead, J29451GNSSDataBufEntry);
#endif
extern struct CleanupHead g_cleanup_head;

#endif //V2X_SW_J29451_INTERNAL_DEFINES_H
