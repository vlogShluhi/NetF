cmake_minimum_required(VERSION 3.16)

project(NetF_deamon VERSION 0.1 LANGUAGES CXX)

# Поиск pkg-config для libpcap и dbus
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED libpcap)
pkg_check_modules(DBUS REQUIRED dbus-1)  # Добавляем поиск DBus

# Улучшенный поиск libnftables
find_path(LIBNFTABLES_INCLUDE_DIR
    NAMES libnftables.h
    PATHS /usr/include /usr/local/include /usr/include/libnftables
    DOC "Path to libnftables headers"
)

find_library(LIBNFTABLES_LIB
    NAMES nftables
    PATHS /usr/lib /usr/local/lib
    DOC "Path to libnftables library"
)

# Проверка наличия libnftables
if(LIBNFTABLES_INCLUDE_DIR AND LIBNFTABLES_LIB)
    message(STATUS "Found libnftables: ${LIBNFTABLES_LIB}")
    set(LIBNFTABLES_FOUND TRUE)
else()
    message(WARNING "libnftables not found! Some features will be disabled.")
    set(LIBNFTABLES_FOUND FALSE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Добавляем флаги для сборки с поддержкой DBus
add_definitions(-DDBUS_API_SUBJECT_TO_CHANGE)  # Для совместимости с разными версиями DBus

set(PROJECT_SOURCES
    firewall.h 
    firewall.cpp
    trafficmonitor.h 
    trafficmonitor.cpp
    netf_deamon.cpp
)

add_executable(NetF_deamon ${PROJECT_SOURCES})

# Добавляем директории include
target_include_directories(NetF_deamon PRIVATE
    ${LIBPCAP_INCLUDE_DIRS}
    ${DBUS_INCLUDE_DIRS}  # Добавляем include-директории DBus
)

if(LIBNFTABLES_FOUND)
    target_include_directories(NetF_deamon PRIVATE
        ${LIBNFTABLES_INCLUDE_DIR}
    )
endif()

# Линковка библиотек
target_link_libraries(NetF_deamon PRIVATE
    ${LIBPCAP_LIBRARIES}
    ${DBUS_LIBRARIES}  # Добавляем линковку с DBus
)

if(LIBNFTABLES_FOUND)
    target_link_libraries(NetF_deamon PRIVATE
        ${LIBNFTABLES_LIB}
    )
endif()

# Добавляем определения для работы с сырыми сокетами
if(UNIX AND NOT APPLE)
    target_compile_definitions(NetF_deamon PRIVATE
        -D_GNU_SOURCE
        -D_THREAD_SAFE
    )
endif()

# Установка
include(GNUInstallDirs)
install(TARGETS NetF_deamon
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Вывод информации о зависимостях
message(STATUS "----------------------------------------------------------")
message(STATUS "Project configuration summary:")
message(STATUS "  libpcap: ${LIBPCAP_LIBRARIES}")
message(STATUS "  DBus: ${DBUS_LIBRARIES}")  # Добавляем информацию о DBus
if(LIBNFTABLES_FOUND)
    message(STATUS "  libnftables: ${LIBNFTABLES_LIB}")
    message(STATUS "  libnftables headers: ${LIBNFTABLES_INCLUDE_DIR}")
else()
    message(STATUS "  libnftables: NOT FOUND")
endif()
message(STATUS "----------------------------------------------------------")