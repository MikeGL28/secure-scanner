# test_samples/vulnerable.py
import pickle
import yaml
import sqlite3

# 1. Dangerous eval
eval(input("Enter code: "))

# 2. Unsafe deserialization
data = b"cos\nsystem\n(S'echo pwned'\ntR."
obj = pickle.loads(data)

# 3. Unsafe yaml.load
yaml.load("!!python/object/apply:os.system ['echo test']")

# 4. SQL injection via f-string
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
user = "1 OR 1=1"
cursor.execute(f"SELECT * FROM users WHERE id = {user}")