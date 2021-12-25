@ECHO OFF

:: Configurar las opciones:
set OPCIONES=--langtag English -q 720 -s 1 -e 1 --alang "European Spanish" English es en --slang "European Spanish" English es en es-sdh en-sdh --flang euSpa eng es en


:: Ejemplos:
::
:: --langtag English -q 720 -s 1 -e 1 --alang "European Spanish" English es en --slang "European Spanish" English es en es-sdh en-sdh --flang euSpa eng es en




:: Explicacion de todas las opciones:
:: Lee "Instrucciones.txt" para saber como usara cada opcion.



















:: NO TOCAR:
set CARPETA_SALIDA=.\Descargas
set NAP_EXE=nap36.exe
ECHO Introduce la URL de Netflix, Amazon o Primevideo:
set /p URL=
@ECHO.
@ECHO ON

"%NAP_EXE%" --url "%URL%" --output %CARPETA_SALIDA% %OPCIONES%
PAUSE
@ECHO OFF