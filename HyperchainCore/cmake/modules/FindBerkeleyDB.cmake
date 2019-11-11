# - Find BerkeleyDB
# Find the BerkeleyDB includes and library
# This module defines
#  BerkeleyDB_INCLUDE_DIRS, where to find db.h, etc.
#  DB_LIBRARIES, the libraries needed to use BerkeleyDB.
#  DB_FOUND, If false, do not try to use BerkeleyDB.
# also defined, but not for general use are
#  DB_LIBRARY, where to find the BerkeleyDB library.

#FIND_PATH(BerkeleyDB_INCLUDE_DIRS 
#  NAMES db.h
#  PATHS
#	/usr/local/include/db4
#	/usr/local/include
#	/usr/include/db4
#	/usr/include
#  )

if(NOT DEPEND_PATH)
set(DEPEND_PATH ${CMAKE_PREFIX_PATH})
endif()

MESSAGE(STATUS "Find BerkeleyDB in DEPEND_PATH: ${DEPEND_PATH}")

FIND_PATH(DB_INCLUDE_DIR 
  NAMES db.h
  PATH_SUFFIXES "include" "includes"
  PATHS
	${DEPEND_PATH}
	${DB_INCLUDE_DIRS}
  )
MESSAGE(STATUS "Found BerkeleyDB: ${DB_INCLUDE_DIR}")



# Checks if the version file exists, save the version file to a var, and fail if there's no version file
if(DB_INCLUDE_DIR)
	# Read the version file db.h into a variable
	file(READ "${DB_INCLUDE_DIR}/db.h" _BERKELEYDB_DB_HEADER)
	# Parse the DB version into variables to be used in the lib names
	string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*" "\\1" BerkeleyDB_VERSION_MAJOR "${_BERKELEYDB_DB_HEADER}")
	string(REGEX REPLACE ".*DB_VERSION_MINOR	([0-9]+).*" "\\1" BerkeleyDB_VERSION_MINOR "${_BERKELEYDB_DB_HEADER}")
	# Patch version example on non-crypto installs: x.x.xNC
	string(REGEX REPLACE ".*DB_VERSION_PATCH	([0-9]+(NC)?).*" "\\1" BerkeleyDB_VERSION_PATCH "${_BERKELEYDB_DB_HEADER}")
else()
	if(BerkeleyDB_FIND_REQUIRED)
		# If the find_package(BerkeleyDB REQUIRED) was used, fail since we couldn't find the header
		message(FATAL_ERROR "Failed to find Berkeley DB's header file \"db.h\"! Try setting \"BerkeleyDB_ROOT_DIR\" when initiating Cmake.")
	elseif(NOT BerkeleyDB_FIND_QUIETLY)
		message(WARNING "Failed to find Berkeley DB's header file \"db.h\"! Try setting \"BerkeleyDB_ROOT_DIR\" when initiating Cmake.")
	endif()
	# Set some garbage values to the versions since we didn't find a file to read
	set(BerkeleyDB_VERSION_MAJOR "0")
	set(BerkeleyDB_VERSION_MINOR "0")
	set(BerkeleyDB_VERSION_PATCH "0")
endif()

SET(Lib_SUFFIX "")
SET(LIB_DEPEND_PATH ${DEPEND_PATH})
if(WIN32)
IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
   SET(Lib_SUFFIX d)
   SET(LIB_DEPEND_PATH ${DEPEND_PATH}/debug)
ENDIF(CMAKE_BUILD_TYPE STREQUAL "Debug")
endif()

MESSAGE(STATUS "Find BerkeleyDB Library in ${DEPEND_PATH}")

SET(DB_NAMES ${DB_NAMES} db)
FIND_LIBRARY(DB_LIBRARY
if(UNIX)
  NAMES lib${DB_NAMES}_cxx-${BerkeleyDB_VERSION_MAJOR}.${BerkeleyDB_VERSION_MINOR}.so
else
  NAMES lib${DB_NAMES}${BerkeleyDB_VERSION_MAJOR}${BerkeleyDB_VERSION_MINOR}${Lib_SUFFIX}
endif()
  PATH_SUFFIXES "lib"
  PATHS ${DB_LIBRARY} ${LIB_DEPEND_PATH}
  )


SET(DB_FOUND "NO")
IF (DB_LIBRARY AND DB_INCLUDE_DIR)
  SET(BerkeleyDB_INCLUDE_DIRS ${DB_INCLUDE_DIR})
  SET(BerkeleyDB_LIBRARIES ${DB_LIBRARY})
  SET(DB_FOUND "YES")
ENDIF (DB_LIBRARY AND DB_INCLUDE_DIR)

IF (DB_FOUND)
  IF (NOT DB_FIND_QUIETLY)
    MESSAGE(STATUS "Found BerkeleyDB: ${BerkeleyDB_LIBRARIES}")
  ENDIF (NOT DB_FIND_QUIETLY)
  
add_library(Oracle::BerkeleyDB UNKNOWN IMPORTED)
	set_target_properties(Oracle::BerkeleyDB PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES "${BerkeleyDB_INCLUDE_DIRS}"
		IMPORTED_LOCATION "${BerkeleyDB_LIBRARIES}"
		INTERFACE_LINK_LIBRARIES "${BerkeleyDB_LIBRARIES}"
)
	
ELSE (DB_FOUND)
  IF (DB_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find BerkeleyDB library")
  ENDIF (DB_FIND_REQUIRED)
ENDIF (DB_FOUND)

# Deprecated declarations.
SET (NATIVE_DB_INCLUDE_PATH ${DB_INCLUDE_DIR} )
GET_FILENAME_COMPONENT (NATIVE_DB_LIB_PATH ${DB_LIBRARY} PATH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BerkeleyDB DEFAULT_MSG BerkeleyDB_LIBRARIES BerkeleyDB_INCLUDE_DIRS)
MARK_AS_ADVANCED(
  DB_LIBRARYS
  BerkeleyDB_INCLUDE_DIRS
  )
 