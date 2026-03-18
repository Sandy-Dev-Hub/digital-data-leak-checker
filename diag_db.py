import psycopg2
import urllib.parse

password = urllib.parse.quote_plus("Vicky@30110505")
project_ref = "mqkdjudzlarhhvscjskl"

regions = [
    "ap-southeast-1", # Singapore
    "ap-south-1",     # Mumbai
    "us-east-1",      # N. Virginia
    "eu-central-1"    # Frankfurt
]

results = []

for region in regions:
    pooler_host = f"aws-0-{region}.pooler.supabase.com"
    # Testing both Transaction (6543) and Session (5432) ports
    for port in [6543, 5432]:
        url = f"postgresql://postgres.{project_ref}:{password}@{pooler_host}:{port}/postgres"
        try:
            conn = psycopg2.connect(url, connect_timeout=5)
            conn.close()
            results.append(f"SUCCESS: {region} (port {port})")
        except Exception as e:
            results.append(f"FAILED: {region} (port {port}) - {e}")

with open("diag_db_results.txt", "w") as f:
    f.write("\n".join(results))
