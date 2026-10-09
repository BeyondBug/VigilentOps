def safe(cursor):
    value = "1"
    cursor.execute("SELECT " + value)
