cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

# Set project's name
set(PROJECT "memreaper")
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED on)

project(${PROJECT})

if(UNIX AND NOT APPLE)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()
if (MSVC OR MSVC OR MSYS OR MINGW)
   add_definitions(-DWIN64 -D_WIN64 -DBOOST_USE_WINDOWS_H)
endif()

#set(MY_LINKER "/home/oosman/pi/x-tools/arm-rpi-linux-gnueabihf/bin/arm-rpi-linux-gnueabihf-ld")
set(MY_LINKER ${CMAKE_LINKER})
#=========================================================================
# Compilation step for static resources
FUNCTION(ADD_RESOURCES out_var)
  SET(result)
  FOREACH(in_f ${ARGN})
    FILE(RELATIVE_PATH src_f ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${in_f})
    SET(out_f "${PROJECT_BINARY_DIR}/${in_f}.o")
    MESSAGE("Building GLSL object ${out_f}")
    ADD_CUSTOM_COMMAND(OUTPUT ${out_f}
      COMMAND ${MY_LINKER} -r -b binary -o ${out_f} ${src_f}
      DEPENDS ${in_f}
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      COMMENT "Building GLSL object ${out_f}"
      VERBATIM
      )
    LIST(APPEND result ${out_f})
  ENDFOREACH()
  SET(${out_var} "${result}" PARENT_SCOPE)
ENDFUNCTION()

FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/graph)
ADD_RESOURCES(rsc_memreaperpng graph/grim-reaper.png)
ADD_RESOURCES(rsc_jquerymin graph/jquery.min.js)
ADD_RESOURCES(rsc_morris graph/morris.css)
ADD_RESOURCES(rsc_morrismin graph/morris.min.js)
ADD_RESOURCES(rsc_raphaelmin graph/raphael-min.js)
ADD_RESOURCES(rsc_webpagetemplate graph/webpage.template)
#=========================================================================

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(HEADER_FILES
   )

set(SOURCE_FILES
   memprofiler.cpp
   )

add_library(${PROJECT} SHARED
   ${SOURCE_FILES}
   ${HEADER_FILES}
   ${rsc_memreaperpng}
   ${rsc_jquerymin}
   ${rsc_morris}
   ${rsc_morrismin}
   ${rsc_raphaelmin}
   ${rsc_webpagetemplate}
   )

target_link_libraries (${PROJECT}
   -ldl
   -lpthread
   )
