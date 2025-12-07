cmake_minimum_required(VERSION 3.10)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "$ENV{HOME}/.local" CACHE PATH "Default install prefix" FORCE)
endif()

project(messagebox)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Widgets Core)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
pkg_check_modules(RABBITMQ REQUIRED librabbitmq)
find_package(nlohmann_json REQUIRED)

# Include directories
include_directories(
    src
    ${MOSQUITTO_INCLUDE_DIRS}
    ${RABBITMQ_INCLUDE_DIRS}
)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Source files
set(SOURCES
    src/main.cpp
    src/App.cpp
    src/ProfileManager.cpp
    src/MqttClient.cpp
    src/AmqpClient.cpp
    resources.qrc
)

# Executable
add_executable(messagebox ${SOURCES})

# Link libraries
target_link_libraries(messagebox PRIVATE 
    Qt6::Widgets 
    Qt6::Core
    ${MOSQUITTO_LIBRARIES}
    ${RABBITMQ_LIBRARIES}
    nlohmann_json::nlohmann_json
)

# Installation
install(TARGETS messagebox DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
