@echo off
cd /d C:\TRS\backend

docker start trs-redis

call venv\Scripts\activate

start cmd /k "celery -A core worker --pool=solo --loglevel=info"
start cmd /k "celery -A core beat --loglevel=info"

pause