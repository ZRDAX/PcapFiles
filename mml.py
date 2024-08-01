from sklearn.ensemble import IsolationForest
import pandas as pd
import psycopg2

def train_model():
    conn = psycopg2.connect("dbname=yourdb user=youruser password=yourpass")
    query = "SELECT ip_src, ip_dst FROM traffic_data"
    data = pd.read_sql_query(query, conn)
    conn.close()

    model = IsolationForest(contamination=0.01)
    model.fit(data)
    return model

model = train_model()
