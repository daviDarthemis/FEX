add_library(arm64ecfex SHARED
  Module.cpp
  ModuleSRA.S
  libarm64ecfex.def
)

target_include_directories(arm64ecfex PRIVATE
  "${CMAKE_SOURCE_DIR}/Source/Windows/include/"
  "${CMAKE_SOURCE_DIR}/Source/"
  "${CMAKE_SOURCE_DIR}/Source/Windows/"
)

target_link_libraries(arm64ecfex
  PRIVATE
  FEXCore
  Common
  CommonTools
  CommonWindows
  ntdll_ex
  ntdll
)

install(TARGETS arm64ecfex
  RUNTIME
  DESTINATION bin
  COMPONENT runtime)
