#Just a simple script to loop through text you wrote and compare it 
#to text that you used to see if you didn't copy word for word
with open('readings.txt', 'r') as m_file:
    m = m_file.read().lower().strip()

with open('paper.txt', 'r') as t_file:
    t = t_file.read().lower().strip()

m_words = m.split()

for i in range(len(m_words)-4):
    for j in range(i, i+5):
        if j == i+4 and ' '.join(m_words[i:j+1]) in t:
            print('Match found:', ' '.join(m_words[i:j+1]))
