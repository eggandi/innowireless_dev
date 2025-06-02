
## j29451 라이브러리를 빌드하기 위한 CMakeLists.txt 파일


#
# 라이브러리 빌드 사용자 설정
#
set(TARGET_STD_VER 2016) # 2016, 2020 (SAE J2945/1 표준 버전) - TCI 시험 시에는 2016(Spirent TS 기준), 드라이빙 테스트에는 2020 버전(Wayties TS 기준)을 사용해야 한다.
set(DRIVING_TEST true)  # true, false (인증을 위한 드라이빙 테스트 수행 시 true로 설정해야 한다. 실내표준적합성시험 시에는 어떤값이든 상관없다)
                        # 인증을 위한 드라이빙 테스트 중에는, 정지 상태에서 전원 리셋한 후 전송되는 BSM을 확인하는 시험이 있다.
                        # BSM에 수납되는 가속도 정보 중 종방향(lon)가속도와 yawrate는 유효한 값을 BSM에 채우는게 필수로 요구된다
                        # (그렇지 않으면 BSM을 전송하면 안된다 - SAE J2945/1 요구사항)
                        # 전원 리셋 후 GNSS 모듈이 가속도정보를 출력하도록 하기 위해서는 GNSS 모듈의 calibration을 다시 수행해야 하며,
                        # calibration을 위해서는 차량 주행이 필요하다.
                        # 따라서 정지 상태에서 전원 리셋 후 BSM을 확인하는 시험의 경우,
                        # 주행을 하지 않아 calibration을 할 수 없어 BSM에 필수 가속도정보를 채울 수 없고,
                        # 이로 인해 BSM을 전송할 수 없으므로 시험을 진행할 수 없다.
                        # 본 플래그를 설정하면, GNSS 모듈에서 필수가속도값이 출력되지 않을 경우 기본값(0)으로 설정하여 BSM을 전송한다.

#
# 라이브러리 빌드 출력 설정
#
set(TARGET_LIB j29451)
set(TARGET_LIB_FILE "lib${TARGET_LIB}.so")
set(TARGET_UNIT_TEST run-lib${TARGET_LIB}-unit-test)


#
# x64 플랫폼용으로 빌드 시에는 본 라이브러리를 빌드하지 않는다.
#  - 본 라이브러리는 실제 통신플랫폼에서만 사용된다.
#  - 단위테스트 빌드시에는 x64 플랫폼용으로도 빌드한다.
#
if (${TARGET_PLATFORM} STREQUAL "x64" AND NOT BUILD_UNIT_TEST)
  message("[${TARGET_PLATFORM}][lib${TARGET_LIB}] NOT BUILD")
  return()
else ()
  message("[${TARGET_PLATFORM}][lib${TARGET_LIB}] BUILD")
endif ()


#
# 단위테스트 빌드 시 적용되는 설정
#
if (BUILD_UNIT_TEST)
  set(CMAKE_C_OUTPUT_EXTENSION_REPLACE ON)
  set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE ON)
  add_compile_options(-g -O0 -fprofile-arcs -ftest-coverage)
  add_compile_definitions(_EXPORT_INTERNAL_FUNC_ _UNIT_TEST_)
  link_libraries(gcov)
  set(TARGET_STD_VER 2020) # 단위테스트는 2020 버전으로 진행한다.
  set(DRIVING_TEST false) # 단위테스트는 드라이빙테스트 옵션을 비활성화한다.
endif ()


#
# 라이브러리 빌드
#
add_library(${TARGET_LIB} SHARED)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/common)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/product/include)
target_include_directories(${TARGET_LIB} PRIVATE src src/bsm)
target_link_libraries(${TARGET_LIB} PRIVATE m rt)
target_sources(${TARGET_LIB} PRIVATE
               src/api/j29451-api.c
               src/api/j29451-api-gnss.c
               src/api/j29451-api-vehicle.c
               src/bsm/j29451-bsm.c
               src/bsm/j29451-bsm-construct.c
               src/bsm/j29451-bsm-tx.c
               src/obu/j29451-obu.c
               src/obu/j29451-obu-gnss.c
               src/obu/j29451-obu-gnss-data.c
               src/obu/j29451-obu-gnss-data-buf.c
               src/obu/j29451-obu-gnss-filter.c
               src/path-info/j29451-path-history.c
               src/path-info/j29451-path-info.c
               src/path-info/j29451-path-info-backup.c
               src/path-info/j29451-path-prediction.c
               src/vehicle/j29451-vehicle.c
               src/j29451.c
               src/j29451-log.c)
if (BUILD_UNIT_TEST)
  target_sources(${TARGET_LIB} PRIVATE src/j29451-test.c)
endif ()

# SAE J2945/1 표준 버전 관련 빌드 설정
if (${TARGET_STD_VER} STREQUAL "2016")
  target_compile_definitions(${TARGET_LIB} PRIVATE _TARGET_STD_VER_2016_)
elseif (${TARGET_STD_VER} STREQUAL "2020")
  target_compile_definitions(${TARGET_LIB} PRIVATE _TARGET_STD_VER_2020_)
else ()
  message(FATAL_ERROR "Not supported target std version - ${TARGET_STD_VER}")
endif ()

# GNSS 디바이스 관련 빌드 설정
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/gpsd/${TARGET_GPSD_VER}/${TARGET_GPS_DEV}/include)
target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/gpsd/${TARGET_GPSD_VER}/${TARGET_GPS_DEV}/lib/${TARGET_BUILD})
target_link_libraries(${TARGET_LIB} PRIVATE gps)

# asn.1 관련 빌드 설정
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/base)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/j2735-2016)
target_include_directories(${TARGET_LIB} PRIVATE src/asn1/${ASN1_LIB_VENDOR})
target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD})
if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
  target_compile_definitions(${TARGET_LIB} PRIVATE _OBJASN1C_)
  target_link_libraries(${TARGET_LIB} PRIVATE objasn1-j2735-2016 asn1per asn1rt)
  target_sources(${TARGET_LIB} PRIVATE src/asn1/objasn1c/j29451-objasn1c-encode.c)
elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
  target_compile_definitions(${TARGET_LIB} PRIVATE _FFASN1C_)
  target_link_libraries(${TARGET_LIB} PRIVATE ffasn1-j2735-2016 ffasn1-base)
  target_sources(${TARGET_LIB} PRIVATE src/asn1/ffasn1c/j29451-ffasn1c-encode.c)
else ()
  message(FATAL_ERROR "Not supported asn.1 library for libj29451 - ${ASN1_LIB_VENDOR}")
endif ()

# craton2 관련 빌드 설정
if (${TARGET_DEV_DSRC} STREQUAL "craton2")
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/craton2/include)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/craton2/ref_src/include)
  target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/craton2/lib/craton2)
  target_link_libraries(${TARGET_LIB} PRIVATE atlklocal_linux_u)
endif ()

# 실내 드라이빙 테스트 관련 빌드 설정
if (DRIVING_TEST)
  target_compile_definitions(${TARGET_LIB} PRIVATE _DRIVING_TEST_)
endif ()


#
# 라이브러리 빌드 결과물 생성 경로 설정
#
if (NOT BUILD_UNIT_TEST)
  set(OUTPUT_DIR ${PROJECT_ROOT}/src/libs/product/bin/${TARGET_BUILD})
else ()
  set(OUTPUT_DIR ${PROJECT_ROOT}/src/libs/product/bin/${TARGET_BUILD}-debug)
endif ()
set_target_properties(${TARGET_LIB} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR} LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})


if (NOT BUILD_UNIT_TEST)
  #
  # 버전명이 추가된 라이브러리 파일 생성
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${OUTPUT_DIR}/${TARGET_LIB_FILE} ${OUTPUT_DIR}/${TARGET_LIB_FILE}.${VERSION})

  #
  # 라이브러리 빌드 결과물(so 파일)을 어플리케이션 depend 디렉토리에 복사 (어플리케이션에서 링크할 수 있도록)
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     make_directory ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     remove ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD}/${TARGET_LIB_FILE}*)
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${OUTPUT_DIR}/${TARGET_LIB_FILE} ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${OUTPUT_DIR}/${TARGET_LIB_FILE} ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD}/${TARGET_LIB_FILE}.${VERSION})


  #
  # 라이브러리 헤더 파일(h 파일)을 어플리케이션 depend 디렉토리에 복사 (어플리케이션에서 인클루드할 수 있도록)
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     remove_directory ${PROJECT_ROOT}/src/apps/depend/include/${TARGET_LIB})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy_directory ${PROJECT_ROOT}/src/libs/product/include/${TARGET_LIB} ${PROJECT_ROOT}/src/apps/depend/include/${TARGET_LIB})


  #
  # 의존 라이브러리 파일을 어플리케이션 depend 디렉토리로 복사 (어플리케이션에서 링크할 수 있도록)
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD}/*
                     ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${PROJECT_ROOT}/src/libs/depend/gpsd/${TARGET_GPSD_VER}/${TARGET_GPS_DEV}/lib/${TARGET_BUILD}/*
                     ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
endif ()


#
# 단위테스트 빌드
#
if (BUILD_UNIT_TEST)
  add_executable(${TARGET_UNIT_TEST})
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/product/include)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/common)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${GTEST_INCLUDE_DIR})
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE src)
  target_link_libraries(${TARGET_UNIT_TEST} PRIVATE ${TARGET_LIB} gtest gtest_main pthread)
  target_compile_options(${TARGET_UNIT_TEST} PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable)
  target_sources(${TARGET_UNIT_TEST} PRIVATE
                 test/unit-test/api/test-api.cc
                 test/unit-test/api/test-api-gnss.cc
                 test/unit-test/api/test-api-vehicle.cc
                 test/unit-test/scenarios/test-scenario-check-gnss-data-in-bsm.cc
                 test/unit-test/scenarios/test-scenario-check-heading-latch.cc
                 test/unit-test/scenarios/test-scenario-check-id-change.cc
                 test/unit-test/scenarios/test-scenario-check-user-gnss-data-in-bsm.cc
                 test/unit-test/scenarios/test-scenario-check-vehicle-data-in-bsm.cc
                 test/unit-test/scenarios/test-scenario-insufficient-data-in-bsm.cc
                 test/unit-test/test-libj29451.cc)

  # SAE J2945/1 표준 버전 관련 빌드 설정
  if (${TARGET_STD_VER} STREQUAL "2016")
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _TARGET_STD_VER_2016_)
  elseif (${TARGET_STD_VER} STREQUAL "2020")
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _TARGET_STD_VER_2020_)
  else ()
    message(FATAL_ERROR "Not supported target std version - ${TARGET_STD_VER}")
  endif ()

  # GPS 디바이스 관련 설정
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/gpsd/${TARGET_GPSD_VER}/${TARGET_GPS_DEV}/include)
  target_link_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/gpsd/${TARGET_GPSD_VER}/${TARGET_GPS_DEV}/lib/${TARGET_BUILD})
  target_link_libraries(${TARGET_UNIT_TEST} PRIVATE ${TARGET_LIB} gps)

  # asn.1 라이브러리 관련 설정
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include)
  if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    target_link_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD})
    target_link_libraries(${TARGET_UNIT_TEST} PRIVATE objasn1-j2735-2016 asn1per asn1oer asn1rt)
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _OBJASN1C_)
  elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _FFASN1C_)
  else ()
    message(FATAL_ERROR "Not supported asn.1 library for libj29451 - ${ASN1_LIB_VENDOR}")
  endif ()

  # 실내 드라이빙 테스트 관련 빌드 설정
  if (DRIVING_TEST)
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _DRIVING_TEST_)
  endif ()

  # 단위테스트 실행 및 레포트 생성
  set(GTEST_REPORT_DIR ${PROJECT_ROOT}/docs/unit-test/gtest_report)
  set(UNIT_TEST_REPORT_DIR ${PROJECT_ROOT}/docs/unit-test/report/${TARGET_LIB})
  set(RESULT_REPORT_DIR ${UNIT_TEST_REPORT_DIR}/result)
  set(COVERAGE_REPORT_DIR ${UNIT_TEST_REPORT_DIR}/coverage)
  set(GCOV_FILE_DIR CMakeFiles/${TARGET_LIB}.dir/src)
  add_custom_target(${TARGET_LIB}test
                    COMMENT "Execute all unit test cases and generate result & coverage report"
                    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
                    DEPENDS ${TARGET_UNIT_TEST}
                    COMMAND mkdir -p ${RESULT_REPORT_DIR}
                    COMMAND mkdir -p ${COVERAGE_REPORT_DIR}
                    COMMAND rm -rf ${RESULT_REPORT_DIR}/*
                    COMMAND rm -rf ${COVERAGE_REPORT_DIR}/*
                    COMMAND ${CMAKE_CURRENT_LIST_DIR}/${TARGET_UNIT_TEST}
                    --gtest_output=xml:${GTEST_REPORT_DIR}/in/result.xml
                    COMMAND lcov -c -d ${GCOV_FILE_DIR} -o ${COVERAGE_REPORT_DIR}/${TARGET_LIB}.cov
                    COMMAND genhtml ${COVERAGE_REPORT_DIR}/${TARGET_LIB}.cov -o ${COVERAGE_REPORT_DIR}
                    COMMAND cd ${GTEST_REPORT_DIR} && dos2unix generate.sh && dos2unix scripts/*.py && chmod 777 generate.sh scripts/*.py && ./generate.sh
                    COMMAND rm ${GTEST_REPORT_DIR}/in/*
                    COMMAND mv ${GTEST_REPORT_DIR}/out/* ${RESULT_REPORT_DIR})
endif ()
