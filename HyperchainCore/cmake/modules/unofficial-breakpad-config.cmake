# - Find breakpad
# Find the breakpad includes and library
# This module defines
#  breakpad_INCLUDE_DIRS, where to find db.h, etc.
#  DB_LIBRARIES, the libraries needed to use breakpad.
#  DB_FOUND, If false, do not try to use breakpad.
# also defined, but not for general use are
#  DB_LIBRARY, where to find the breakpad library.

#FIND_PATH(breakpad_INCLUDE_DIRS 
#  NAMES db.h
#  PATHS
#	/usr/local/include/db4
#	/usr/local/include
#	/usr/include/db4
#	/usr/include
#  )


MESSAGE(STATUS "Find breakpad")

FIND_PATH(DB_INCLUDE_DIR 
  NAMES exception_handler.h
  #PATH_SUFFIXES "include" "includes"
  PATHS
	/usr/local
	/usr/local/include/breakpad
  )
MESSAGE(STATUS "Found breakpad: ${DB_INCLUDE_DIR}")

SET(Lib_SUFFIX "")

MESSAGE(STATUS "Find breakpad Library")

SET(DB_NAMES ${DB_NAMES} breakpad_client)
FIND_LIBRARY(DB_LIBRARY
if(UNIX)
  NAMES lib${DB_NAMES}.a
else
  NAMES lib${DB_NAMES}${breakpad_VERSION_MAJOR}${breakpad_VERSION_MINOR}${Lib_SUFFIX}
endif()
  PATH_SUFFIXES "lib"
  PATHS ${DB_LIBRARY} /usr/local
  )
MESSAGE(STATUS "Found breakpad Library ${DB_LIBRARY}")

SET(DB_FOUND "NO")
IF (DB_LIBRARY AND DB_INCLUDE_DIR)
  SET(breakpad_INCLUDE_DIRS /usr/local/include/breakpad)
  SET(breakpad_LIBRARIES ${DB_LIBRARY})
  SET(DB_FOUND "YES")
ENDIF (DB_LIBRARY AND DB_INCLUDE_DIR)

IF (DB_FOUND)
  IF (NOT DB_FIND_QUIETLY)
    MESSAGE(STATUS "Found breakpad: ${breakpad_LIBRARIES}")
  ENDIF (NOT DB_FIND_QUIETLY)

add_library(unofficial::breakpad::libbreakpad_client STATIC IMPORTED)  
set_target_properties(unofficial::breakpad::libbreakpad_client PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${breakpad_INCLUDE_DIRS}"
  IMPORTED_LOCATION "${breakpad_LIBRARIES}"
  INTERFACE_LINK_LIBRARIES "${breakpad_LIBRARIES}"
)
	
ELSE (DB_FOUND)
  IF (DB_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find breakpad library")
  ENDIF (DB_FIND_REQUIRED)
ENDIF (DB_FOUND)


 