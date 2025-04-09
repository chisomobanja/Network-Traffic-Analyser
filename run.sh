#!/bin/bash
echo "Starting Network Traffic Analyzer..."
echo ""
echo "NOTE: This application requires root privileges to capture network packets."
echo "If it doesn't work, try running with sudo."
echo ""
java -Djava.library.path=./lib -cp "NetworkTrafficAnalyzer.jar:lib/*" com.netanalyzer.NetAnalyzerServer
