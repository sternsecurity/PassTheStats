# Password Stats program
# Created by Jon Sternstein @ Stern Security
# Version 1.4.2
# Run this program on a file containing a list of usernames and passwords in the
#    following format  [username]:[password], for example admin:Winter2019

import re, sys, time
from collections import Counter

# List containing all usernames. Note - the following lists indexes 
#   correspond to the same user account: usernames,passwords,complexity,
#   complexornot
#   So usernames[0], passwords[0],
#   and complexity[0] describe the same account.
usernames = []

# List containing all passwords
passwords = []

# Dictionary containing all accounts that should change their password
#   and the reasons they need to change it
changepassword = {}

fileindex=0

# List containing all passwords less than 8 characters and their
#  corresponding usernames
lessthan8 = []

# List containing all passwords that are equal to their usernames
usernameispass = []

# This list contains the password complexity info for each password
# s = special character, n = number, u = uppercase, l = lowercase
# A value of 1011 means the password has special characters, uppercase
#    and lowercase, but no numbers.
complexity = []

# List of noncomplex passwords
noncomplex = []

# List stating whether the password is complex or not.
# 1 = complex, 0 = not complex
complex_or_not = []

# List containing blank passwords
blankpassword = []

# List containing cracked accounts that may be administrators
admin_accounts = []
admins = ["sys", "adm", "ops"]

program_info = "\nPasswords Stats v.1.4.1\n" \
    "Developed by Stern Security\n" \
    "www.sternsecurity.com\n"

if(len(sys.argv)==1):
    print (program_info + \
    "Usage: python3 " + sys.argv[0] + " [file containing list of credentials with " + \
    "format username1:password1]")
    exit(0)
f=open(sys.argv[1],'r')

# iterate over password file
for line in f.readlines():
    line=line.strip('\n')
    # use ":" as a delimiter
    delimitedline=line.split(':')
    #insert the first split value into the usernames list
    usernames.append(delimitedline[0])
    #print "Username is " + str(delimitedline[0]) + " and index is: " + str(fileindex)
    
    # Deleting the username from the line import since this is already added to the list
    del delimitedline[0]
    
	# The rest of the text in the line is the password. Join in case password contains ':'
    passwords.append(':'.join(delimitedline))
    
    fileindex += 1

# Function to add account to the change password dictionary
def change_pass(index,reason):
    #if changepassword.has_key(usernames[index]):
    if usernames[index] in changepassword.keys():
            changepassword[usernames[index]].append(reason)
    else:
            changepassword[usernames[index]] = [reason]
    return

# If password is less than 8 characters, it adds the password to a
#   list titled "lessthan8", and adds a key/value to the changepassword
#   dictionary for the list of all users that should change their
#   password.
fileindex = 0
for password in passwords:
    if len(password) < 8:
        lessthan8.append(password)
        change_pass(fileindex,'Less_than_8')
    fileindex += 1

# Creates list of usernames that equal the password
fileindex = 0
for user in usernames:
    if usernames[fileindex].lower() == passwords[fileindex].lower():
        usernameispass.append(usernames[fileindex])
        change_pass(fileindex,'Username=password')
    fileindex += 1

# Creates list accounts with blank passwords
fileindex = 0
for password in passwords:
    if len(password) == 0:
        blankpassword.append(password)
        change_pass(fileindex,'Blank_Password')
    fileindex += 1

# Creates list of usernames may be administrators
fileindex = 0
for user in usernames:
    # Sees if any values in admins[] is contained in the username
    if any(values in usernames[fileindex].lower() for values in admins):
        admin_accounts.append(usernames[fileindex])
        change_pass(fileindex,'Potential Administrator')
    fileindex += 1

# Value is SNUL
# S = special character, N = number, U = uppercase, L = lowercase
# Value of 1011 means the password has special chars, upper & lowercase, but no numbers.
fileindex = 0
for password in passwords:
    s='0'
    n='0'
    u='0'
    l='0'
    #complexity.append('0000')
    # If string contains character that is not a word (letter), then it has special chars
    if re.search('[\W_]', password):
        s='1'
    # if the search contains a character that is a number
    if re.search('[\d]', password):
        n='1'
    if re.search('[A-Z]', password):
        u='1'
    if re.search('[a-z]', password):
        l='1'
    complexity.append(s+n+u+l)
    formula=s+n+u+l
    if formula.count('1') < 3:
        noncomplex.append(password)
        complex_or_not.append(0)
        change_pass(fileindex,'noncomplex')
    else:
        complex_or_not.append(1)
    fileindex += 1

# Count the most common passwords
c = Counter(passwords)

# Printing output to screen and file
outfile = 'PassTheStats-output-' + str(time.strftime('%m-%d-%Y_%H-%M-%S')) + '.txt'
f = open(outfile, 'w+')

print(program_info)
f.write(program_info + "\n")
f.write("--- Executive Summary---\n")

print(str(len(usernames)) + " cracked passwords have been analyzed\n")
f.write(str(len(usernames)) + " cracked passwords have been analyzed\n")

print("There are " + str(len(lessthan8)) + " passwords less than eight characters\n") #+ str(lessthan8)
f.write("There are " + str(len(lessthan8)) + " passwords less than eight characters\n")

print("There are " + str(len(usernameispass)) + " passwords that are equal to their username\n") #+ str(usernameispass)
f.write("There are " + str(len(usernameispass)) + " passwords that are equal to their username\n")

print("There are " + str(len(blankpassword)) + " accounts that have blank passwords\n")
f.write("There are " + str(len(blankpassword)) + " accounts that have blank passwords\n")

print("There are " + str(len(admin_accounts)) + " passwords cracked for users that may be admins\n")
f.write("There are " + str(len(admin_accounts)) + " passwords cracked for users that may be admins\n")

print("There are " + str(len(noncomplex)) + " passwords that have " \
    "less than three of the following: uppercase, lowercase," \
    " numbers, or symbols\n") #+ str(noncomplex)
f.write("There are " + str(len(noncomplex)) + " passwords that have " \
    "less than three of the following: uppercase, lowercase," \
    " numbers, or symbols\n")

print("\nThese are the top 10 most popular passwords:")
f.write("\nThese are the top 10 most popular passwords:\n")
for user,key in c.most_common(10):
    print(str(user) + " -> " + str(key))
    f.write(str(user) + " -> " + str(key) + "\n")

f.write("\n\n--- Detailed Weak Password Info --- \n" \
    "List of accounts with weak passwords in format [Username -> password issue]:\n\n")
for users,reason in changepassword.items():
    # print str(users) + " -> " + str(reason)
    f.write(str(users) + " -> " + str(reason) + '\n')

f.close()
print("\nSuccessfully created detailed output in " + outfile + "\n")
