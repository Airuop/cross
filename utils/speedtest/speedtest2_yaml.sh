#准备好所Sprint
wget -O lite-linux-amd64.gz https://github.com/xxf098/LiteSpeedTest/releases/download/v0.13.1/lite-linux-amd64-v0.13.1.gz
gzip -d lite-linux-amd64.gz
wget -O lite_config.json https://raw.githubusercontent.com/Airuop/cross/master/utils/speedtest/lite_config_yaml.json
#运行 LiteSpeedTest
chmod +x ./lite-linux-amd64
sudo nohup ./lite-linux-amd64 --config ./lite_config.json --test https://raw.githubusercontent.com/Airuop/cross/master/sub/sub_merge_yaml.yml > speedtest.log 2>&1 &
