@echo off
echo Starting Network Traffic Analyzer...
echo.
echo NOTE: This application requires administrator privileges to capture network packets.
echo If it doesn't work, try running as administrator.
echo.
java -Djava.library.path=./lib -cp "NetworkTrafficAnalyzer.jar;lib/*" com.netanalyzer.NetAnalyzerServer
pause
