include_directories(..)

# Runtime library sources and build flags.
set(CMSAN_RTL_SOURCES
	interval-tree/rbtree.c
	cmsan_interval.c
	cmsan_rtl.cpp
	cmsan_flags.cpp
	cmsan_shadow_setup.cpp
	cmsan_preinit.cpp
	cmsan_linux.cpp
	cmsan_interceptors_memintrinsics.cpp
  )

set(CMSAN_RTL_HEADERS
  cmsan_rtl.h
  cmsan_interval.h
  )

#No special cflags
set(CMSAN_COMMON_CFLAGS ${SANITIZER_COMMON_CFLAGS})
# Static runtime library.
add_compiler_rt_component(cmsan)

foreach(arch ${CMSAN_SUPPORTED_ARCH})
	set(CMSAN_CFLAGS ${CMSAN_COMMON_CFLAGS})
	append_list_if(COMPILER_RT_HAS_FPIE_FLAG -fPIE CMSAN_CFLAGS)
	add_compiler_rt_runtime(clang_rt.cmsan
		STATIC
		ARCHS ${arch}
		SOURCES ${CMSAN_RTL_SOURCES}
		$<TARGET_OBJECTS:RTInterception.${arch}>
		$<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
		$<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
		CFLAGS ${CMSAN_CFLAGS}
		PARENT_TARGET cmsan)
	add_sanitizer_rt_symbols(clang_rt.cmsan
		ARCHS ${arch}
		 )
	add_dependencies(cmsan
		clang_rt.cmsan-${arch}-symbols)
endforeach()
