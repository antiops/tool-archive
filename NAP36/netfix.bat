@ECHO OFF
set /p url= what is netflix url? :
set /p season= what season do you want to download? :
set /p episode= what episode do you want to download? :
set /p quality= what quality do you want to download?  720 or 1080 : 

nap36.exe --aformat-51ch AFORMAT_51CH -q %quality% --no-prompt --output .\Downloads --url %url% --alang English -s %season%  -e %episode%
pause
