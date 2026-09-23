@echo off
cd /d "%~dp0Flask_App"
call "C:\ProgramData\anaconda3\condabin\conda.bat" activate gan
python app.py
