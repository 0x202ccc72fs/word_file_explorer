def word_explorer(search_word):
    user_input = input("Enter Filename: ").strip()
    try:
        with open(user_input, "r") as fname:
            for line in fname:
                pos = line.find(search_word)
                if pos != -1:
                    pos1 = line[pos:].strip()
                    print(pos1)
    except FileNotFoundError:
        print("File not found. Please try again.")

def main_menu():
    while True:
        print("\n1. Run Program")
        print("2. Quit Program")
        ent_input = input("Select 1 or 2: ").strip()
        if ent_input == "1":
            search_word = input("Enter the word/phrase to search: ").strip()
            word_explorer(search_word)
        elif ent_input == "2":
            print("Program successfully closed!".upper())
            break
        else:
            print("Invalid input. Please select 1 or 2.")

main_menu()
