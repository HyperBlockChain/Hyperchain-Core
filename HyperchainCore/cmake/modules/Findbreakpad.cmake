# - Find breakpad
# Find the breakpad includes and library
# This module defines
#  breakpad_INCLUDE_DIRS, where to find exception_handler.h, etc.
#  BP_LIBRARIES, the libraries needed to use breakpad.
#  BP_FOUND, If false, do not try to use breakpad.
# also defined, but not for general use are
#  BP_LIBRARY, where to find the breakpad library.

if(NOT DEPEND_PATH)
set(DEPEND_PATH ${CMAKE_PREFIX_PATH})
endif()

FIND_PATH(BP_INCLUDE_DIR 
  NAMES exception_handler.h
  if(UNIX)
  PATH_SUFFIXES "client/linux/handler"
  elseif(WIN32)
  PATH_SUFFIXES "client/windows/handler"
  endif()
  PATHS
	${BP_INCLUDE_DIR}
	${DEPEND_PATH}
	/usr/local
	/usr/local/include/breakpad
  )
MESSAGE(STATUS "Found breakpad: ${BP_INCLUDE_DIR}")

SET(Lib_SUFFIX "")

SET(BP_NAMES ${BP_NAMES} breakpad_client)
FIND_LIBRARY(BP_LIBRARY
if(UNIX)
  NAMES lib${BP_NAMES}.a
else
  NAMES lib${BP_NAMES}${breakpad_VERSION_MAJOR}${breakpad_VERSION_MINOR}${Lib_SUFFIX}
endif()
  PATH_SUFFIXES "lib"
  PATHS ${DEPEND_PATH} ${BP_LIBRARY} /usr/local
  )
MESSAGE(STATUS "Found breakpad Library ${BP_LIBRARY}")

SET(BP_FOUND "NO")
IF (BP_LIBRARY AND BP_INCLUDE_DIR)
  SET(breakpad_INCLUDE_DIRS /usr/local/include/breakpad)
  SET(breakpad_LIBRARIES ${BP_LIBRARY})
  SET(BP_FOUND "YES")
ENDIF (BP_LIBRARY AND BP_INCLUDE_DIR)

IF (BP_FOUND)
  add_library(unofficial::breakpad::libbreakpad_client STATIC IMPORTED)  
  set_target_properties(unofficial::breakpad::libbreakpad_client PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${breakpad_INCLUDE_DIRS}"
  IMPORTED_LOCATION "${breakpad_LIBRARIES}"
  INTERFACE_LINK_LIBRARIES "${breakpad_LIBRARIES}"
)
	
ELSE (BP_FOUND)
    MESSAGE(FATAL_ERROR "Could not find breakpad library")
ENDIF (BP_FOUND)


 