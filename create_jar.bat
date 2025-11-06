@echo off
echo Creating launcher...
echo @echo off > HistoryAnalyzer.bat
echo java -cp "%%~dp0*.jar;%%~dp0*.class" Main >> HistoryAnalyzer.bat
echo.
echo ✅ Created HistoryAnalyzer.bat
echo 📝 Right-click -> Send to Desktop -> Right-click shortcut -> Change Icon
echo 🎯 This acts like an EXE for users!
pause