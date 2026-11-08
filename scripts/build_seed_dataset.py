import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "raw" / "intent_dataset.csv"


EXAMPLES = [
    # SYSTEM INFORMATION
    ("show system information", "system_information", "show_os", {}),
    ("what operating system is this", "system_information", "show_os", {}),
    ("show the kernel version", "system_information", "show_kernel", {}),
    ("what architecture is this machine", "system_information", "show_architecture", {}),

    # STORAGE
    ("show disk space", "storage_inspection", "filesystem_usage", {}),
    ("how much storage is available", "storage_inspection", "filesystem_usage", {}),
    ("show filesystem usage", "storage_inspection", "filesystem_usage", {}),
    ("check the size of /var/log", "storage_inspection", "directory_size", {"PATH": "/var/log"}),

    # MEMORY
    ("show memory usage", "memory_inspection", "memory_usage", {}),
    ("how much RAM is available", "memory_inspection", "memory_usage", {}),
    ("check free memory", "memory_inspection", "memory_usage", {}),
    ("display RAM usage", "memory_inspection", "memory_usage", {}),

    # PROCESS INSPECTION
    ("show running processes", "process_inspection", "list", {}),
    ("list all processes", "process_inspection", "list", {}),
    ("show process 4321", "process_inspection", "inspect", {"PID": "4321"}),
    ("find nginx processes", "process_inspection", "inspect", {"PATTERN": "nginx"}),

    # SERVICE INSPECTION
    ("check nginx status", "service_inspection", "status", {"SERVICE": "nginx"}),
    ("is ssh running", "service_inspection", "status", {"SERVICE": "ssh"}),
    ("show apache service status", "service_inspection", "status", {"SERVICE": "apache"}),
    ("check docker service status", "service_inspection", "status", {"SERVICE": "docker"}),

    # NETWORK
    ("show listening ports", "network_inspection", "listening_ports", {}),
    ("show network interfaces", "network_inspection", "interfaces", {}),
    ("show active network connections", "network_inspection", "connections", {}),
    ("which ports are listening", "network_inspection", "listening_ports", {}),

    # FILE LISTING
    ("show files in the current directory", "file_listing", "list", {}),
    ("list files in /tmp", "file_listing", "list", {"PATH": "/tmp"}),
    ("show files in /var/log", "file_listing", "list", {"PATH": "/var/log"}),
    ("list this directory", "file_listing", "list", {}),

    # FILE READ
    ("show /tmp/report.txt", "file_read", "read", {"PATH": "/tmp/report.txt"}),
    ("read /var/log/app.log", "file_read", "read", {"PATH": "/var/log/app.log"}),
    ("show the first lines of /tmp/data.txt", "file_read", "head", {"PATH": "/tmp/data.txt"}),
    ("show the last lines of /var/log/app.log", "file_read", "tail", {"PATH": "/var/log/app.log"}),

    # FILE SEARCH
    ("find python files", "file_search", "find", {"PATTERN": "*.py"}),
    ("find report.txt", "file_search", "find", {"PATTERN": "report.txt"}),
    ("search for log files", "file_search", "find", {"PATTERN": "*.log"}),
    ("find config files in /etc", "file_search", "find", {"PATH": "/etc", "PATTERN": "*.conf"}),

    # TEXT SEARCH
    ("find ERROR in /var/log/app.log", "text_search", "search",
     {"PATTERN": "ERROR", "PATH": "/var/log/app.log"}),
    ("search for failed in /tmp/test.log", "text_search", "search",
     {"PATTERN": "failed", "PATH": "/tmp/test.log"}),
    ("find warning in /tmp/app.log", "text_search", "search",
     {"PATTERN": "warning", "PATH": "/tmp/app.log"}),
    ("search for timeout in /var/log/service.log", "text_search", "search",
     {"PATTERN": "timeout", "PATH": "/var/log/service.log"}),

    # FILE CREATE
    ("create /tmp/notes.txt", "file_create", "create_file", {"PATH": "/tmp/notes.txt"}),
    ("create reports directory", "file_create", "create_directory", {"PATH": "reports"}),
    ("make /tmp/demo.txt", "file_create", "create_file", {"PATH": "/tmp/demo.txt"}),
    ("make a folder called backup", "file_create", "create_directory", {"PATH": "backup"}),

    # FILE COPY
    ("copy report.txt to backup/report.txt", "file_copy", "copy",
     {"SOURCE_PATH": "report.txt", "DESTINATION_PATH": "backup/report.txt"}),
    ("copy /tmp/a.txt to /tmp/b.txt", "file_copy", "copy",
     {"SOURCE_PATH": "/tmp/a.txt", "DESTINATION_PATH": "/tmp/b.txt"}),
    ("make a copy of notes.txt as notes_backup.txt", "file_copy", "copy",
     {"SOURCE_PATH": "notes.txt", "DESTINATION_PATH": "notes_backup.txt"}),
    ("copy config.ini into backup/config.ini", "file_copy", "copy",
     {"SOURCE_PATH": "config.ini", "DESTINATION_PATH": "backup/config.ini"}),

    # FILE MOVE
    ("move report.txt to archive/report.txt", "file_move", "move",
     {"SOURCE_PATH": "report.txt", "DESTINATION_PATH": "archive/report.txt"}),
    ("rename old.txt to new.txt", "file_move", "rename",
     {"SOURCE_PATH": "old.txt", "DESTINATION_PATH": "new.txt"}),
    ("move /tmp/a.txt to /tmp/archive/a.txt", "file_move", "move",
     {"SOURCE_PATH": "/tmp/a.txt", "DESTINATION_PATH": "/tmp/archive/a.txt"}),
    ("rename draft.txt as final.txt", "file_move", "rename",
     {"SOURCE_PATH": "draft.txt", "DESTINATION_PATH": "final.txt"}),

    # FILE DELETE
    ("delete /tmp/report.txt", "file_delete", "delete", {"PATH": "/tmp/report.txt"}),
    ("remove temporary.txt", "file_delete", "delete", {"PATH": "temporary.txt"}),
    ("delete /tmp/old.log", "file_delete", "delete", {"PATH": "/tmp/old.log"}),
    ("remove archive.txt", "file_delete", "delete", {"PATH": "archive.txt"}),

    # PERMISSIONS
    ("make script.sh executable", "permission_change", "chmod",
     {"PATH": "script.sh", "PERMISSION": "+x"}),
    ("change permissions on report.txt to 644", "permission_change", "chmod",
     {"PATH": "report.txt", "PERMISSION": "644"}),
    ("change owner of app.log to alice", "permission_change", "chown",
     {"PATH": "app.log", "USERNAME": "alice"}),
    ("set permissions of private.txt to 600", "permission_change", "chmod",
     {"PATH": "private.txt", "PERMISSION": "600"}),

    # PROCESS TERMINATION
    ("stop process 4321", "process_termination", "terminate", {"PID": "4321"}),
    ("terminate PID 9876", "process_termination", "terminate", {"PID": "9876"}),
    ("force kill process 1234", "process_termination", "force_terminate", {"PID": "1234"}),
    ("kill process 7654", "process_termination", "terminate", {"PID": "7654"}),

    # SERVICE MANAGEMENT
    ("restart nginx", "service_management", "restart", {"SERVICE": "nginx"}),
    ("stop apache", "service_management", "stop", {"SERVICE": "apache"}),
    ("start ssh", "service_management", "start", {"SERVICE": "ssh"}),
    ("reload nginx", "service_management", "reload", {"SERVICE": "nginx"}),

    # PACKAGE MANAGEMENT
    ("install nginx", "package_management", "install", {"PACKAGE": "nginx"}),
    ("remove package curl", "package_management", "remove", {"PACKAGE": "curl"}),
    ("install git", "package_management", "install", {"PACKAGE": "git"}),
    ("update packages", "package_management", "update", {}),

    # SYSTEM POWER
    ("restart the machine", "system_power", "reboot", {}),
    ("reboot the server", "system_power", "reboot", {}),
    ("shut down the system", "system_power", "shutdown", {}),
    ("power off the machine", "system_power", "shutdown", {}),

    # DISK MANAGEMENT
    ("format /dev/sdb", "disk_management", "format", {"DEVICE": "/dev/sdb"}),
    ("create a filesystem on /dev/sdc", "disk_management", "format", {"DEVICE": "/dev/sdc"}),
    ("format the device /dev/vdb", "disk_management", "format", {"DEVICE": "/dev/vdb"}),
    ("create a filesystem on /dev/xvdb", "disk_management", "format", {"DEVICE": "/dev/xvdb"}),

    # OUT OF SCOPE
    ("tell me a joke", "out_of_scope", "", {}),
    ("write an email to my professor", "out_of_scope", "", {}),
    ("what is the weather today", "out_of_scope", "", {}),
    ("explain machine learning", "out_of_scope", "", {}),
]


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "example_id",
        "text",
        "intent",
        "action",
        "entities",
        "source",
        "split",
    ]

    with OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for index, (text, intent, action, entities) in enumerate(
            EXAMPLES,
            start=1,
        ):
            writer.writerow(
                {
                    "example_id": f"IX{index:06d}",
                    "text": text,
                    "intent": intent,
                    "action": action,
                    "entities": json.dumps(
                        entities,
                        separators=(",", ":"),
                    ),
                    "source": "curated",
                    "split": "",
                }
            )

    print(f"Created {len(EXAMPLES)} seed examples.")
    print(f"Output: {OUTPUT}")


if __name__ == "__main__":
    main()