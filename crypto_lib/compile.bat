@echo off
REM Компиляция для Windows с использованием MinGW

echo Компиляция криптографической библиотеки...
g++ -O2 -shared -o crypto.dll crypto.cpp -DBUILDING_DLL -std=c++11 -Wall

if %errorlevel% equ 0 (
    echo Компиляция успешна!
    copy crypto.dll ..
) else (
    echo Ошибка компиляции!
)

pause