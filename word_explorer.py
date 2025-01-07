import os
import time
import sys
from typing import List, Tuple
import concurrent.futures
from datetime import datetime

def animated_intro():
    """
    Displays a dynamic loading animation when the program starts.
    """
    animation = ["|", "/", "-", "\\"]
    print("\nStarting Word Explorer...", end="", flush=True)
    for _ in range(3):
        for frame in animation:
            print(f"\r{frame} Loading...", end="", flush=True)
            time.sleep(0.2)
    print("\rProgram is ready!          ")

def loading_message(message: str, duration: int = 3):
    """
    Displays a loading animation with a custom message.
    """
    animation = ["|", "/", "-", "\\"]
    print(f"\n{message}", end="", flush=True)
    for _ in range(duration):
        for frame in animation:
            print(f"\r{frame} {message}", end="", flush=True)
            time.sleep(0.2)
    print("\rDone!                     ")

def word_explorer(search_word: str, search_directory: str):
    """
    Searches for a word or phrase across all files in a given directory (and subdirectories) using multithreading.
    """
    match_case = input("Match case? (yes/no): ").strip().lower() == "yes"
    whole_word = input("Match whole word only? (yes/no): ").strip().lower() == "yes"

    if not os.path.isdir(search_directory):
        print("Directory not found. Please check the path and try again.")
        return

    total_occurrences = 0
    total_files_scanned = 0
    results: List[Tuple[str, int, int, str]] = []

    def process_file(file_path):
        local_occurrences = 0
        local_results = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                for line_number, line in enumerate(file, 1):
                    search_target = line if match_case else line.lower()
                    search_phrase = search_word if match_case else search_word.lower()

                    start = 0
                    while True:
                        pos = search_target.find(search_phrase, start)
                        if pos == -1:
                            break

                        # Whole word matching
                        before = search_target[pos - 1] if pos > 0 else " "
                        after = search_target[pos + len(search_phrase)] if pos + len(search_phrase) < len(search_target) else " "
                        if whole_word and not (before.isspace() or before in ",.!?;:'") and (after.isspace() or after in ",.!?;:'"):
                            start = pos + len(search_phrase)
                            continue

                        local_occurrences += 1
                        local_results.append((file_path, line_number, pos, line.strip()))
                        start = pos + len(search_phrase)
        except Exception as e:
            print(f"Could not process file {file_path}: {e}")
        return local_occurrences, local_results

    print("\nScanning directory, please wait...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_file = {
            executor.submit(process_file, os.path.join(root, file)): os.path.join(root, file)
            for root, _, files in os.walk(search_directory) for file in files
        }
        for future in concurrent.futures.as_completed(future_to_file):
            occurrences, file_results = future.result()
            total_occurrences += occurrences
            results.extend(file_results)
            total_files_scanned += 1

    if total_occurrences == 0:
        print(f"\nThe word/phrase '{search_word}' was not found in any files within the directory.")
    else:
        print(f"\n'{search_word}' was found {total_occurrences} time(s) across {total_files_scanned} file(s):")
        for result in results:
            print(f"File: {result[0]}\n  Line: {result[1]}\n  Position: {result[2]}\n  Content: {result[3]}\n")
        save_results(search_word, search_directory, total_occurrences, total_files_scanned, results)


def save_results(search_word: str, directory: str, occurrences: int, files_scanned: int, results: List[Tuple[str, int, int, str]]):
    """
    Saves the results of the search to a log file.
    """
    log_filename = "word_explorer_results.txt"
    with open(log_filename, "w", encoding="utf-8") as log_file:
        log_file.write(f"Search Word: {search_word}\n")
        log_file.write(f"Directory: {directory}\n")
        log_file.write(f"Total Occurrences: {occurrences}\n")
        log_file.write(f"Files Scanned: {files_scanned}\n")
        log_file.write("Results:\n")
        for result in results:
            log_file.write(f"File: {result[0]}\n  Line: {result[1]}\n  Position: {result[2]}\n  Content: {result[3]}\n\n")
    print(f"\nResults saved to '{log_filename}'.")

def display_help():
    """
    Displays a help menu with instructions for using the program.
    """
    print("\nHelp Menu:")
    print("1. Enter the directory to search (or leave blank for current directory).")
    print("2. Input the word or phrase you want to search.")
    print("3. Choose case-sensitive or whole word matching options.")
    print("4. Results will be displayed and saved to a log file.")
    print("5. The program scans text files only and skips unreadable files.")


def main_menu():
    """
    Displays the main menu and handles user input.
    """
    animated_intro()
    while True:
        print("\nMain Menu:")
        print("1. Search for Word/Phrase")
        print("2. Help")
        print("3. Quit Program")
        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            search_word = input("Enter the word/phrase to search: ").strip()
            search_directory = input("Enter the directory to search (leave blank for current directory): ").strip() or os.getcwd()
            if search_word:
                word_explorer(search_word, search_directory)
            else:
                print("Search word/phrase cannot be empty.")
        elif choice == "2":
            display_help()
        elif choice == "3":
            print("Exiting program. Goodbye!")
            sys.exit()
        else:
            print("Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main_menu()
