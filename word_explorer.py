def word_explorer():
   user_input = input("Enter Filename:".upper())
   fname      = open(user_input)
   for x in fname:
        pos  = x.find("Admin")
        if pos  != -1:
         pos1  = x[pos:].strip()
         print(pos1)

def user_input():
        print("1.Run Programm")
        print("2.Quit Programm")
        ent_input = input("Select 1 or 2 : ".strip())
        for x in ent_input:
            if   x == "1":
                 word_explorer()
            elif x == "2":
                 print("Succesfull Closed!".upper()) 
                 quit()

user_input()
