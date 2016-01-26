project(System.Net.Security.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DPIC=1)

if (APPLE)
   find_library(LIBGSS NAMES GSS)
   add_definitions(-DGSSFW)
   set(HEIMDAL "")
else()
   find_library(LIBGSS NAMES gssapi_krb5)
   find_library(HEIMDAL NAMES heimntlm PATHS /usr/heimdal/lib)

    if(LIBGSS STREQUAL LIBGSS-NOTFOUND)
        message(SEND_ERROR "!!! Cannot find libgssapi_krb5 and System.Net.Security.Native cannot build without it. Try installing libkrb5-dev (or the appropriate package for your platform) !!!")
        return()
    endif()

    if(HEIMDAL STREQUAL HEIMDAL-NOTFOUND)
       message(SEND_ERROR "!!! Cannot find libheimntlm and System.Net.Security.Native cannot build without it. Try installing heimdal-dev (or the appropriate package for your platform) !!!")
       return()
    endif()
 
    include_directories(/usr/include)
    include_directories(/usr/include/mit-krb5)
    include_directories(/usr/include/mit-krb5/gssapi)
    include_directories(/usr/heimdal/include)
    add_definitions(-DTARGET_OS_MAC=0)
endif()

set(NATIVEGSS_SOURCES
	pal_gssapi.cpp
)

set(NATIVENTLM_SOURCES
	pal_ntlmapi.cpp
)

#if (APPLE)
   set (NETSECURITY_SOURCES     ${NATIVEGSS_SOURCES})
#else()
#set (NETSECURITY_SOURCES     ${NATIVEGSS_SOURCES} ${NATIVENTLM_SOURCES})
#endif()

add_library(System.Net.Security.Native
    SHARED
    ${NETSECURITY_SOURCES}
)

target_link_libraries(System.Net.Security.Native
	${HEIMDAL}
        ${LIBGSS} 
        ${OPENSSL_CRYPTO_LIBRARY}
)

install (TARGETS System.Net.Security.Native DESTINATION .)

