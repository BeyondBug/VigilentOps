def safe(cursor):
    supplied = input()
    cursor.execute('SELECT * FROM users WHERE name = ?', (supplied,))
