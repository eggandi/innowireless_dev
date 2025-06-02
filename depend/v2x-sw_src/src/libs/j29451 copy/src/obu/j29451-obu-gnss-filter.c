/**
 * @file
 * @brief GNSS 정보 필터 기능을 구현한 파일
 * @date 2020-10-13
 * @author gyun
 */


// 시스템 헤더 파일
#include <math.h>

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"


/**
 * @brief Butterworth Low pass 필터를 초기화한다.
 * @param[in] filter 초기화할 필터
 * @param[in] sampling_freq 필터 샘플링 주파수
 * @param[in] cutoff_freq 필터 컷오프 주파수
 *
 * 필터 구현 참조
 *  - https://github.com/adis300/filter-c
 *  - https://exstrom.com/journal/sigproc/dsigproc.html
 */
void INTERNAL j29451_InitBWLowPassFilter(struct J29451BWLowPassFilter *filter, float sampling_freq, float cutoff_freq)
{
  Log(kJ29451LogLevel_Event, "Initialize BW low pass filter\n");

  filter->n = J29451_BW_FILTER_ORDER / 2;
  float a = tanf(M_PI * cutoff_freq / sampling_freq);
  float a2 = a * a;
  float r, s;
  for (int i = 0; i < filter->n; ++i) {
    r = sinf(M_PI * (2.0 * i + 1.0) / (4.0 * filter->n));
    s = a2 + 2.0 * a * r + 1.0;
    filter->A[i] = a2 / s;
    filter->d1[i] = 2.0 * (1 - a2) / s;
    filter->d2[i] = -(a2 - 2.0 * a * r + 1.0) / s;
  }
}


/**
 * @brief 특정 입력값을 Butterworth Low pass 필터에 통과시킨다.
 * @param[in] filter 필터
 * @param[in] input 입력값
 * @return 출력값
 *
 * 필터 구현 참조
 *  - https://github.com/adis300/filter-c
 *  - https://exstrom.com/journal/sigproc/dsigproc.html
 */
float INTERNAL j29451_BWLowPassFilter(struct J29451BWLowPassFilter *filter, float input)
{
  float output = input;
  for (int i = 0; i < filter->n; ++i) {
    filter->w0[i] = filter->d1[i] * filter->w1[i] + filter->d2[i] * filter->w2[i] + input;
    output = filter->A[i] * (filter->w0[i] + 2.0 * filter->w1[i] + filter->w2[i]);
    filter->w2[i] = filter->w1[i];
    filter->w1[i] = filter->w0[i];
  }
  return output;
}

