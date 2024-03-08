import datetime


def log_message(message) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    with open("yellow_page_logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")

    return log_entry


def start_new_session_log():
    with open("yellow_page_logs.txt", "a") as log_file:
        log_file.write("\n===== New Session Started =====\n")


def get_end_session_log():
    with open("yellow_page_logs.txt", "r") as log_file:
        logs = log_file.read()
        logs = logs.split("===== New Session Started =====")
        return logs[-2]


def get_all_logs():
    with open("yellow_page_logs.txt", "r") as log_file:
        logs = log_file.read()
        return logs
