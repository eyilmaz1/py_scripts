import subprocess
import sys

#The public key would be the one argument in the terminal
pub = str(sys.argv[1])

#The public key gets put into the URI
url = "https://etherscan.io/address/" + pub

#The HTML of the page, retrieved with Curl, is saved as a string
result = subprocess.run(['curl', '-s', url], stdout=subprocess.PIPE)
getext = result.stdout
gettext = str(getext)

#The whole string is gone over until 8">$ is found
#The numbers after that HTML would be the funds in the account
#The value is saved as a sting into the funds variable
#The end of the value is caught when the loop encouters a '<'
for i in range(len(gettext) - 4):
    if gettext[i] + gettext[i+1] + gettext[i+2] + gettext[i+3] == "8\">$":
        j = i
        funds = ""
        while gettext[j+3] != "<":
            funds += gettext[j+3]
            j += 1
        break
#output is printed
print("Funds: " + funds)

'''
SAMPLE OUTPUT
-------------

emin@yilmaz % python3 ethcheck.py 0xebb6c6716aa1a769b74b9252f5b93d7bf80f021e 
Funds: $180.71 
emin@yilmaz % 

'''
