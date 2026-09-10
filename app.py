import sqlite3
from flask import Flask, render_template

app = Flask(__name__)
DB_NAME = "alerts.db"

def get_alerts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20")
    alerts = cursor.fetchall()
    conn.close()
    return alerts

@app.route("/")
def index():
    alerts = get_alerts()
    return render_template("index.html", alerts=alerts)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
