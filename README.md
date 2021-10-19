# Netflix-videos-downloader

## 快速开始
```
pip install -r requirements.txt
```


## 参数
```
基础参数：
    -h，--help
                显示完整参数设置帮助文档并退出
    -q <数字>       
                视频分辨率，默认选择最高（1080），可选：480，720，1080等
    -o <目录路径>     
                下载临时文件夹
    -f <目录路径>
                mkv混流输出文件夹，不指定默认输出到下载临时文件夹
    -s <数字>
                季数（Season）
    -e <数字>
                集数（Episode）不指定默认下载全集
                "-e 1" 下载第1集;
                "-e 1-7" 下载第1-7集;
                "-e 2,5" 下载第2集、第5集
    -p，--prompt
                下载前交互式提示输入yes/no
    --AD 语言代码，--alang 语言代码
                指定音轨语言，默认下载原始语言（Original）最高码率音轨
                语言代码位置："/helpers/Muxer.py"
    --slang 语言代码
                指定字幕语言，默认下载所有语言字幕，
                例如"--slang zhoS zhoT" 即指定简体中文、繁体中文字幕
    --flang 语言代码
                指定“场景字幕”语言（Force Subtitle）
    --all-audios
                下载所有语言音轨
    --all-forced
                下载所有语言“场景字幕”
    --audio-bitrate <数字>
                指定音频码率，默认下载最高码率音轨，可选：128，256，448等
    --aformat-2c，--audio-format-2ch
                指定下载2.0声道音轨
    --aformat-51ch，--audio-format-51ch
                指定下载5.1声道音轨
    --keep
                混流mkv后保留原始素材文件，默认删除
    -keys，--license
                仅输出widevine key到控制台并退出
    --no-aria2c
                不调用aria2c下载器，使用Python下载器，默认使用aria2c
                不推荐使用此参数
    --nv
                不下载视频（Video）
    --na
                不下载音频（Audio）
    --ns
                不下载字幕（Subtitle）

额外配置文件参数（Manifest）：
    --main      指定 H.264 Main
    --high      指定 H.264 High
    --hevc      指定 H.265
    --hdr       指定 H.265 HDR
    --check     比较H.264 Main/H.264 High二者质量优劣
```