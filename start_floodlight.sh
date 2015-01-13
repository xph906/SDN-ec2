#!/bin/bash
echo "Start Floodlight controller..."
sudo java -Xmx2096M -Xms1024M -Dlogback.configurationFile=./logback.xml -jar target/floodlight.jar 2>log_err

