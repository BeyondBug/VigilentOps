def unsafe(cursor):
    value = input()
    cursor.execute("SELECT * FROM users WHERE name=" + value)
