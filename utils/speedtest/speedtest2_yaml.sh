#!/bin/bash

# Set variables for clarity and readability
LITE_SPEEDTEST_URL="https://raw.githubusercontent.com/Airuop/cross/master/utils/download/LiteSpeedTest/releases/v0.15.0/lite-linux-amd64-v0.15.0.gz"
LITE_CONFIG_URL="https://raw.githubusercontent.com/Airuop/cross/master/utils/speedtest/lite_config_yaml.json"
SUB_MERGE_YAML_URL="https://raw.githubusercontent.com/Airuop/cross/master/sub/sub_merge_yaml.yml"
LOG_FILE="speedtest.log"

# Download LiteSpeedTest binary
echo -e "Downloading LiteSpeedTest binary..."
wget -q -O lite-linux-amd64.gz "$LITE_SPEEDTEST_URL"
echo -e "Download complete."

# Extract the binary
echo -e "Extracting LiteSpeedTest binary..."
gzip -d lite-linux-amd64.gz
echo -e "Extraction complete."

# Download LiteSpeedTest configuration
echo -e "Downloading LiteSpeedTest configuration..."
wget -q -O lite_config.json "$LITE_CONFIG_URL"
echo -e "Download complete."

# Make the binary executable
echo -e "Making LiteSpeedTest binary executable..."
chmod +x ./lite-linux-amd64
echo -e "Done."

# Run LiteSpeedTest with configuration and logging
echo -e "Running LiteSpeedTest..."
# sudo nohup ./lite-linux-amd64 --config ./lite_config.json --test "$SUB_MERGE_YAML_URL" > "$LOG_FILE" 2>&1 &
sudo  ./lite-linux-amd64 --config ./lite_config.json --test "$SUB_MERGE_YAML_URL" > "$LOG_FILE" 2>&1 &

echo -e "LiteSpeedTest Finished."
exit

# Show log output in real-time
# echo -e "Log output:"
# tail -f "$LOG_FILE"
