/**
 * @file
 * @brief dot3 라이브러리 내부에서 사용되는 각종 변수형, 매크로, 정의값 등을 정의한 파일
 * @date 2020-07-13
 * @author gyun
 */


#ifndef V2X_SW_DOT3_INTERNAL_DEFINES_H
#define V2X_SW_DOT3_INTERNAL_DEFINES_H


/// UAS 정보의 수명 (초단위)
#define DOT3_UAS_EXPIRY_TIME (5)
/// UAS 정보관리 주기 단위 (밀리초단위)
#define DOt3_UAS_MGMT_INTERVAL_UNIT (100)

/*
 * 함수 속성 정의 매크로 (gcc 빌드 시에만 적용됨)
 */
#define OPEN_API __attribute__((visibility("default")))  ///< 공개 API 함수임을 나타내기 위한 매크로
#ifdef _EXPORT_INTERNAL_FUNC_
#define INTERNAL __attribute__((visibility("default")))  ///< (내부함수 단위테스트를 위해) 내부함수 미지정 (외부로 노출됨)
#else
#define INTERNAL __attribute__((visibility("hidden")))   ///< 공개 API 가 아닌 내부함수로 지정 (외부로 노출되지 않음)
#endif


/*
 * 로그 출력 매크로
 * 컴파일 시 "_DEBUG_*_"가 정의되지 않으면 로그출력 코드가 제거되어 컴파일된다.
 */
#if defined(_DEBUG_STDOUT_) || defined(_DEBUG_SYSLOG_)
/// 로그 출력 매크로
#define Log(l, f, a...) do { if (g_dot3_log >= l) { dot3_PrintLog(__FUNCTION__, f, ## a); } } while(0)
/// 에러레벨 로그 출력 전용 매크로
#define Err(f, a ...) do { if (g_dot3_log >= kDot3LogLevel_Err) { dot3_PrintLog(__FUNCTION__, f, ## a); } } while(0)
#else
#define Log(l, f, a ...) do {} while(0)
#define Err(f, a ...) do {} while(0)
#endif


#endif //V2X_SW_DOT3_INTERNAL_DEFINES_H
