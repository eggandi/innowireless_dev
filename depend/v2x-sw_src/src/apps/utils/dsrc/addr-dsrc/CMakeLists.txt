
## addr-dsrc 유틸리티를 빌드하기 위한 CMakeLists.txt 파일


#
# 빌드 출력 설정
#
set(TARGET_APP addr-dsrc)


#
# x64 플랫폼용으로 빌드 시와 단위테스트 빌드 시에는 본 유틸리티를 빌드하지 않는다.
#  - 본 유틸리티는 실제 통신플랫폼에서만 사용된다.
#
if (${TARGET_PLATFORM} STREQUAL "x64" OR BUILD_UNIT_TEST)
  message("[${TARGET_PLATFORM}][${TARGET_APP}] NOT BUILD")
  return()
else ()
  message("[${TARGET_PLATFORM}][${TARGET_APP}] BUILD")
endif ()


#
# 유틸리티 빌드
#
add_executable(${TARGET_APP} src/addr-dsrc.c)
target_include_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/apps/depend/include)
target_link_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
target_link_libraries(${TARGET_APP} PRIVATE wlanaccess pthread)
target_link_options(${TARGET_APP} PRIVATE -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--allow-shlib-undefined)
if (${TARGET_DEV_DSRC} STREQUAL "saf5100" OR ${TARGET_DEV_DSRC} STREQUAL "saf5400")
  target_link_libraries(${TARGET_APP} PRIVATE LLC)
elseif (${TARGET_DEV_DSRC} STREQUAL "craton2")
  target_link_libraries(${TARGET_APP} PRIVATE atlklocal_linux_u tomcrypt tommath m rt)
endif ()

#
# 빌드 결과물을 output 디렉토리로 복사
#
set(OUTPUT_DIR ${PROJECT_ROOT}/src/apps/output/${TARGET_BUILD})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        remove ${OUTPUT_DIR}/${TARGET_APP})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        remove ${OUTPUT_DIR}/${TARGET_APP}-${VERSION})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        copy ${TARGET_APP} ${OUTPUT_DIR}/${TARGET_APP})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        copy ${TARGET_APP} ${OUTPUT_DIR}/${TARGET_APP}-${VERSION})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        remove ${TARGET_APP})