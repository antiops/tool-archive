@ECHO OFF

set link=https://www.amazon.com/gp/video/detail/B07KR8383J/
set langtag="English"
set region=us
set res=1080
set aud_lang=en
set dirpath=.\Downloads


nap36.exe --langtag %langtag% -q %res% --alang %aud_lang% --slang en -s 3 -e 1 --no-prompt --region %region% --keep --output %dirpath% --url %link%
pause
