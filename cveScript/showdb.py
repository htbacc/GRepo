import sqlite3
import pandas as pd

# Connect to SQLite database
conn = sqlite3.connect('vulnerability_data.db')
cursor = conn.cursor()

# Fetch all data from the vulnerabilities table
cursor.execute('SELECT * FROM vulnerabilities')
data = cursor.fetchall()

# Create a DataFrame to display the data
df = pd.DataFrame(data, columns=['CVE ID', 'Published Date', 'CVSS v3 Score', 'CVSS v2 Score'])

# Print the DataFrame
print(df)

# Close the database connection
conn.close()
