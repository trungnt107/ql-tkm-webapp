@echo off
title QL Tien do Du an TKM - Server
cd /d "%~dp0"
echo ============================================
echo   Dang khoi dong QL Tien do Du an TKM...
echo   DUNG dong cua so nay khi con dang dung web.
echo ============================================
echo.
start "" http://localhost:3000
npm start
pause