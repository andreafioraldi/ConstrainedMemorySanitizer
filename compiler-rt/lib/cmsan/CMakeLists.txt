# Runtime library sources and build flags.
set(CMSAN_SOURCES
	interval-tree/rbtree.c
	cmsan_interval.c
  cmsan_flags.cpp
  cmsan_interceptors_memintrinsics.cpp
  cmsan_linux.cpp
  cmsan_rtl.cpp
  cmsan_shadow_setup.cpp
  cmsan_stack.cpp
  )

set(CMSAN_PREINIT_SOURCES
  cmsan_preinit.cpp
  )

set(CMSAN_HEADERS
  cmsan_constrainfunc_def.h
  cmsan_flags.h
  cmsan_interface_internal.h
  cmsan_internal.h
  cmsan_interval.h
  cmsan_mapping.h
  cmsan_stack.h
  )

include_directories(..)

set(CMSAN_CFLAGS ${SANITIZER_COMMON_CFLAGS})
set(CMSAN_COMMON_DEFINITIONS ${COMPILER_RT_CMSAN_SHADOW_SCALE_DEFINITION})

append_rtti_flag(OFF CMSAN_CFLAGS)

set(CMSAN_DYNAMIC_LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS})

if(ANDROID)
# Put most Sanitizer shared libraries in the global group. For more details, see
# android-changes-for-ndk-developers.md#changes-to-library-search-order
  if (COMPILER_RT_HAS_Z_GLOBAL)
    list(APPEND CMSAN_DYNAMIC_LINK_FLAGS -Wl,-z,global)
  endif()
endif()

set(CMSAN_DYNAMIC_DEFINITIONS
  ${CMSAN_COMMON_DEFINITIONS} CMSAN_DYNAMIC=1)
append_list_if(WIN32 INTERCEPTION_DYNAMIC_CRT CMSAN_DYNAMIC_DEFINITIONS)

set(CMSAN_DYNAMIC_CFLAGS ${CMSAN_CFLAGS})
append_list_if(COMPILER_RT_HAS_FTLS_MODEL_INITIAL_EXEC
  -ftls-model=initial-exec CMSAN_DYNAMIC_CFLAGS)
append_list_if(MSVC /DEBUG CMSAN_DYNAMIC_LINK_FLAGS)

set(CMSAN_DYNAMIC_LIBS ${SANITIZER_CXX_ABI_LIBRARIES} ${SANITIZER_COMMON_LINK_LIBS})

append_list_if(COMPILER_RT_HAS_LIBDL dl CMSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBRT rt CMSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBM m CMSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBPTHREAD pthread CMSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBLOG log CMSAN_DYNAMIC_LIBS)
append_list_if(MINGW "${MINGW_LIBRARIES}" CMSAN_DYNAMIC_LIBS)

if (TARGET cxx-headers OR HAVE_LIBCXX)
  set(CMSAN_DEPS cxx-headers)
endif()

# Compile ASan sources into an object library.

add_compiler_rt_object_libraries(RTCmsan_dynamic
  OS ${SANITIZER_COMMON_SUPPORTED_OS}
  ARCHS ${CMSAN_SUPPORTED_ARCH}
  SOURCES ${CMSAN_SOURCES}
  ADDITIONAL_HEADERS ${CMSAN_HEADERS}
  CFLAGS ${CMSAN_DYNAMIC_CFLAGS}
  DEFS ${CMSAN_DYNAMIC_DEFINITIONS}
  DEPS ${CMSAN_DEPS})

if(NOT APPLE)
  add_compiler_rt_object_libraries(RTCmsan
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    SOURCES ${CMSAN_SOURCES}
    ADDITIONAL_HEADERS ${CMSAN_HEADERS}
    CFLAGS ${CMSAN_CFLAGS}
    DEFS ${CMSAN_COMMON_DEFINITIONS}
    DEPS ${CMSAN_DEPS})
  add_compiler_rt_object_libraries(RTCmsan_cxx
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    SOURCES ${CMSAN_CXX_SOURCES}
    ADDITIONAL_HEADERS ${CMSAN_HEADERS}
    CFLAGS ${CMSAN_CFLAGS}
    DEFS ${CMSAN_COMMON_DEFINITIONS}
    DEPS ${CMSAN_DEPS})
  add_compiler_rt_object_libraries(RTCmsan_preinit
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    SOURCES ${CMSAN_PREINIT_SOURCES}
    ADDITIONAL_HEADERS ${CMSAN_HEADERS}
    CFLAGS ${CMSAN_CFLAGS}
    DEFS ${CMSAN_COMMON_DEFINITIONS}
    DEPS ${CMSAN_DEPS})

  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp "")
  add_compiler_rt_object_libraries(RTCmsan_dynamic_version_script_dummy
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
    CFLAGS ${CMSAN_DYNAMIC_CFLAGS}
    DEFS ${CMSAN_DYNAMIC_DEFINITIONS}
    DEPS ${CMSAN_DEPS})
endif()

# Build ASan runtimes shipped with Clang.
add_compiler_rt_component(cmsan)

if(APPLE)
  add_weak_symbols("cmsan" WEAK_SYMBOL_LINK_FLAGS)
  add_weak_symbols("ubsan" WEAK_SYMBOL_LINK_FLAGS)
  add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)
  add_weak_symbols("xray" WEAK_SYMBOL_LINK_FLAGS)

  add_compiler_rt_runtime(clang_rt.cmsan
    SHARED
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTCmsan_dynamic
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                RTSanitizerCommonCoverage
                RTSanitizerCommonSymbolizer
                RTUbsan
    CFLAGS ${CMSAN_DYNAMIC_CFLAGS}
    LINK_FLAGS ${WEAK_SYMBOL_LINK_FLAGS}
    DEFS ${CMSAN_DYNAMIC_DEFINITIONS}
    PARENT_TARGET cmsan)
else()
  # Build separate libraries for each target.

  set(CMSAN_COMMON_RUNTIME_OBJECT_LIBS
    RTInterception
    RTSanitizerCommon
    RTSanitizerCommonLibc
    RTSanitizerCommonCoverage
    RTSanitizerCommonSymbolizer
    RTUbsan)

  add_compiler_rt_runtime(clang_rt.cmsan
    STATIC
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTCmsan_preinit
                RTCmsan
                ${CMSAN_COMMON_RUNTIME_OBJECT_LIBS}
    CFLAGS ${CMSAN_CFLAGS}
    DEFS ${CMSAN_COMMON_DEFINITIONS}
    PARENT_TARGET cmsan)

  add_compiler_rt_runtime(clang_rt.cmsan_cxx
    STATIC
    ARCHS ${CMSAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTCmsan_cxx
                RTUbsan_cxx
    CFLAGS ${CMSAN_CFLAGS}
    DEFS ${CMSAN_COMMON_DEFINITIONS}
    PARENT_TARGET cmsan)

  foreach(arch ${CMSAN_SUPPORTED_ARCH})
    if (UNIX)
      add_sanitizer_rt_version_list(clang_rt.cmsan-dynamic-${arch}
                                    LIBS clang_rt.cmsan-${arch} clang_rt.cmsan_cxx-${arch}
                                    )
      set(VERSION_SCRIPT_FLAG
           -Wl,--version-script,${CMAKE_CURRENT_BINARY_DIR}/clang_rt.cmsan-dynamic-${arch}.vers)
      # The Solaris 11.4 linker supports a subset of GNU ld version scripts,
      # but requires a special option to enable it.
      if (OS_NAME MATCHES "SunOS")
          list(APPEND VERSION_SCRIPT_FLAG -Wl,-z,gnu-version-script-compat)
      endif()
      set_property(SOURCE
        ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        APPEND PROPERTY
        OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/clang_rt.cmsan-dynamic-${arch}.vers)
    else()
      set(VERSION_SCRIPT_FLAG)
    endif()

    set(CMSAN_DYNAMIC_WEAK_INTERCEPTION)
    if (WIN32)
      add_compiler_rt_object_libraries(CmsanWeakInterception
        ${SANITIZER_COMMON_SUPPORTED_OS}
        ARCHS ${arch}
        SOURCES cmsan_win_weak_interception.cpp
        CFLAGS ${CMSAN_CFLAGS} -DSANITIZER_DYNAMIC
        DEFS ${CMSAN_COMMON_DEFINITIONS}
        DEPS ${CMSAN_DEPS})
      set(CMSAN_DYNAMIC_WEAK_INTERCEPTION
          CmsanWeakInterception
          UbsanWeakInterception
          SancovWeakInterception
          SanitizerCommonWeakInterception)
    endif()

    add_compiler_rt_runtime(clang_rt.cmsan
      SHARED
      ARCHS ${arch}
      OBJECT_LIBS ${CMSAN_COMMON_RUNTIME_OBJECT_LIBS}
              RTCmsan_dynamic
              # The only purpose of RTCmsan_dynamic_version_script_dummy is to
              # carry a dependency of the shared runtime on the version script.
              # Replacing it with a straightforward
              # add_dependencies(clang_rt.cmsan-dynamic-${arch} clang_rt.cmsan-dynamic-${arch}-version-list)
              # generates an order-only dependency in ninja.
              RTCmsan_dynamic_version_script_dummy
              RTUbsan_cxx
              ${CMSAN_DYNAMIC_WEAK_INTERCEPTION}
      CFLAGS ${CMSAN_DYNAMIC_CFLAGS}
      LINK_FLAGS ${CMSAN_DYNAMIC_LINK_FLAGS}
                ${VERSION_SCRIPT_FLAG}
      LINK_LIBS ${CMSAN_DYNAMIC_LIBS}
      DEFS ${CMSAN_DYNAMIC_DEFINITIONS}
      PARENT_TARGET cmsan)

    if (SANITIZER_USE_SYMBOLS AND NOT ${arch} STREQUAL "i386")
      add_sanitizer_rt_symbols(clang_rt.cmsan_cxx
        ARCHS ${arch})
      add_dependencies(cmsan clang_rt.cmsan_cxx-${arch}-symbols)
      add_sanitizer_rt_symbols(clang_rt.cmsan
        ARCHS ${arch})
      add_dependencies(cmsan clang_rt.cmsan-${arch}-symbols)
    endif()

    if (WIN32)
      add_compiler_rt_object_libraries(CmsanDllThunk
        ${SANITIZER_COMMON_SUPPORTED_OS}
        ARCHS ${arch}
        SOURCES # cmsan_win_dll_thunk.cpp
        CFLAGS ${CMSAN_CFLAGS} -DSANITIZER_DLL_THUNK
        DEFS ${CMSAN_COMMON_DEFINITIONS}
        DEPS ${CMSAN_DEPS})

      add_compiler_rt_runtime(clang_rt.cmsan_dll_thunk
        STATIC
        ARCHS ${arch}
        OBJECT_LIBS CmsanDllThunk
                    UbsanDllThunk
                    SancovDllThunk
                    SanitizerCommonDllThunk
        SOURCES $<TARGET_OBJECTS:RTInterception.${arch}>
        PARENT_TARGET cmsan)

      set(DYNAMIC_RUNTIME_THUNK_CFLAGS "-DSANITIZER_DYNAMIC_RUNTIME_THUNK")
      if(MSVC)
        list(APPEND DYNAMIC_RUNTIME_THUNK_CFLAGS "-Zl")
      elseif(CMAKE_C_COMPILER_ID MATCHES Clang)
        list(APPEND DYNAMIC_RUNTIME_THUNK_CFLAGS "-nodefaultlibs")
      endif()

      add_compiler_rt_object_libraries(CmsanDynamicRuntimeThunk
        ${SANITIZER_COMMON_SUPPORTED_OS}
        ARCHS ${arch}
        SOURCES # cmsan_win_dynamic_runtime_thunk.cpp
        CFLAGS ${CMSAN_CFLAGS} ${DYNAMIC_RUNTIME_THUNK_CFLAGS}
        DEFS ${CMSAN_COMMON_DEFINITIONS}
        DEPS ${CMSAN_DEPS})

      add_compiler_rt_runtime(clang_rt.cmsan_dynamic_runtime_thunk
        STATIC
        ARCHS ${arch}
        OBJECT_LIBS CmsanDynamicRuntimeThunk
                    UbsanDynamicRuntimeThunk
                    SancovDynamicRuntimeThunk
                    SanitizerCommonDynamicRuntimeThunk
        CFLAGS ${CMSAN_CFLAGS} ${DYNAMIC_RUNTIME_THUNK_CFLAGS}
        DEFS ${CMSAN_COMMON_DEFINITIONS}
        PARENT_TARGET cmsan)
    endif()
  endforeach()
endif()
