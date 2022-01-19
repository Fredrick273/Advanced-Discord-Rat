@echo off
color 0a
echo.
set /p a="Enter the name for the exe : "
if [%a%]==[] ( 
    CALL:error
    pause
    EXIT /B %ERRORLEVEL% 
) 
if [%a%] NEQ [] (
    CALL:main
    EXIT /B %ERRORLEVEL% 
)

:main
echo.
echo Name is: %a% 
pip uninstall -y enum34
pyinstaller --onefile --clean --noconfirm --noconsole -n %a% -i NONE .\main.py
del /s /q /f %a%.spec
rmdir /s /q __pycache__
rmdir /s /q build
EXIT /B %ERRORLEVEL% 

:error
echo.
echo bro enter a name
EXIT /B %ERRORLEVEL% 
