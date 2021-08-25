import sqlite3

con = sqlite3.connect('../src/db.sqlite3')
cur = con.cursor()

for row in cur.execute('SELECT * FROM secret_secret'):
    print(row)

# cur.execute('UPDATE secret_secret SET value = "ractf{data_exf1l_via_s0rt1ng_0c66de47}" WHERE id = 1')

cur.close()

con.commit()
con.close()


