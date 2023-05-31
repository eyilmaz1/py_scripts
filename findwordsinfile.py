import os
import sys

def search_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".txt"):  
                with open(file_path, "r", encoding='utf-8-sig', errors='ignore') as f:
                    for line in f:
                        words = line.split()
                        for word in words:
                            if '$word' in word: #replace with word you want
                                print(word)

directory_path = '$directory'  # Replace with directory path
output_file_path = '$output.txt'  # Replace with output file path

with open(output_file_path, 'w', encoding='utf-8') as output_file:
    original_stdout = sys.stdout
    sys.stdout = output_file
    search_files(directory_path)
    sys.stdout = original_stdout
