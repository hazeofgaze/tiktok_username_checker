# tiktok_username_checker
Tiktok.com username availability checker, time between requests is changable at the beginning, made by me bleh. 

1. install python and run `pip install requests`
2. create `usernames.txt` in the same folder as the script, with one username per line.
3. run `python username_checker_json.py`

the script checks tiktok profile pages and saves possible candidates for manual verification.

csv log: `username_status_log_json.csv` records each check's result, status codes, and diagnostic details to help investigate responses and debug the checker.

results are not proof that a username is available.
