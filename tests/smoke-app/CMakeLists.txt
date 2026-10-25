cmake_minimum_required(VERSION 3.21)
project(qt_lgpl_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Svg Qml WebSockets Core5Compat StateMachine SerialPort UiTools)

add_executable(smoke main.cpp)
target_link_libraries(smoke PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Svg Qt6::Qml
    Qt6::WebSockets Qt6::Core5Compat Qt6::StateMachine Qt6::SerialPort Qt6::UiTools)
