cmake_minimum_required(VERSION 3.16)

project(NetF VERSION 0.1 LANGUAGES CXX)

# Поиск pkg-config для libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED libpcap)

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

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ищем компоненты Qt с поддержкой Charts и DBus
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Charts DBus)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Charts DBus)

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui


)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(NetF
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(NetF SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(NetF
            ${PROJECT_SOURCES}
        )
    endif()
endif()

# Добавляем директории include
target_include_directories(NetF PRIVATE
    ${LIBPCAP_INCLUDE_DIRS}
)

if(LIBNFTABLES_FOUND)
    target_include_directories(NetF PRIVATE
        ${LIBNFTABLES_INCLUDE_DIR}
    )
endif()

# Линковка библиотек
target_link_libraries(NetF PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Charts
    Qt${QT_VERSION_MAJOR}::DBus
    ${LIBPCAP_LIBRARIES}
)

if(LIBNFTABLES_FOUND)
    target_link_libraries(NetF PRIVATE
        ${LIBNFTABLES_LIB}
    )
endif()

# Добавляем определения для работы с сырыми сокетами
if(UNIX AND NOT APPLE)
    target_compile_definitions(NetF PRIVATE
        -D_GNU_SOURCE
        -D_THREAD_SAFE
    )
endif()

# Настройка для macOS
if(${QT_VERSION} VERSION_LESS 6.1.0)
    set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.NetF)
endif()

set_target_properties(NetF PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Установка
include(GNUInstallDirs)
install(TARGETS NetF
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Финализация для Qt6
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(NetF)
endif()

# Вывод информации о зависимостях
message(STATUS "----------------------------------------------------------")
message(STATUS "Project configuration summary:")
message(STATUS "  Qt version: ${QT_VERSION_MAJOR}")
message(STATUS "  Qt Charts: Enabled")
message(STATUS "  Qt DBus: Enabled")
message(STATUS "  libpcap: ${LIBPCAP_LIBRARIES}")
if(LIBNFTABLES_FOUND)
    message(STATUS "  libnftables: ${LIBNFTABLES_LIB}")
    message(STATUS "  libnftables headers: ${LIBNFTABLES_INCLUDE_DIR}")
else()
    message(STATUS "  libnftables: NOT FOUND")
endif()
message(STATUS "----------------------------------------------------------")
