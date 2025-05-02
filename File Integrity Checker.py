import os
import hashlib
import json
import time

HASH_DB = 'hash_data.json'
LOG_FILE = 'integrity_log.txt'
IGNORE_EXTENSIONS = ['.log', '.tmp']

def get_file_hash(file_path, algorithm='sha256'):
    """Generate hash for a file based on chosen algorithm."""
    try:
        hasher = getattr(hashlib, algorithm)()
    except AttributeError:
        print("Invalid hashing algorithm.")
        return None
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def save_hashes(data):
    with open(HASH_DB, 'w') as f:
        json.dump(data, f, indent=2)

def load_hashes():
    if not os.path.exists(HASH_DB):
        return {}
    with open(HASH_DB, 'r') as f:
        return json.load(f)

def should_ignore(file_path):
    return any(file_path.endswith(ext) for ext in IGNORE_EXTENSIONS)

def scan_directory(folder, algo):
    result = {}
    for root, _, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            if should_ignore(path):
                continue
            file_hash = get_file_hash(path, algo)
            if file_hash:
                result[path] = {
                    "hash": file_hash,
                    "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
    return result

def compare_hashes(old, new):
    modified, added, deleted = [], [], []

    for path in new:
        if path not in old:
            added.append(path)
        elif old[path]['hash'] != new[path]['hash']:
            modified.append(path)

    for path in old:
        if path not in new:
            deleted.append(path)

    return modified, added, deleted

def log_changes(modified, added, deleted):
    with open(LOG_FILE, 'a') as log:
        log.write(f"\n===== Integrity Check at {time.ctime()} =====\n")
        if modified:
            log.write("Modified files:\n")
            for f in modified:
                log.write(f" * {f}\n")
        if added:
            log.write("New files:\n")
            for f in added:
                log.write(f" + {f}\n")
        if deleted:
            log.write("Deleted files:\n")
            for f in deleted:
                log.write(f" - {f}\n")
        if not (modified or added or deleted):
            log.write("No changes detected.\n")

def main():
    folder = input("Enter folder path to scan: ").strip()
    if not os.path.isdir(folder):
        print("Invalid folder path.")
        return

    print("Choose hash algorithm (sha256 / sha1 / md5):")
    algo = input(">> ").strip().lower()
    if algo not in ['sha256', 'sha1', 'md5']:
        print("Unsupported algorithm. Using sha256.")
        algo = 'sha256'

    old_data = load_hashes()
    new_data = scan_directory(folder, algo)

    modified, added, deleted = compare_hashes(old_data, new_data)

    print("\n--- File Integrity Report ---")
    if modified:
        print(f"\nModified files ({len(modified)}):")
        for f in modified:
            print(" *", f)
    if added:
        print(f"\nNew files ({len(added)}):")
        for f in added:
            print(" +", f)
    if deleted:
        print(f"\nDeleted files ({len(deleted)}):")
        for f in deleted:
            print(" -", f)

    log_changes(modified, added, deleted)

    print("\nScan complete. Details logged to:", LOG_FILE)

    update = input("Update hash records with current state? (y/n): ").strip().lower()
    if update == 'y':
        save_hashes(new_data)
        print("Hash database updated.")
    else:
        print("Hash database not updated.")

if __name__ == "__main__":
    main()
