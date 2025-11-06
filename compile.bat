@echo off
echo Compiling Browser History Analyzer...
javac -cp ".;sqlite-jdbc.jar" *.java
if %errorlevel% equ 0 (
    echo ✅ Compilation successful!
) else (
    echo ❌ Compilation failed!
)
pause