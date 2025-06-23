import pandas as pd
import base64

def generate_csv_download_link(data, filename="captured_data.csv"):
    """
    Generates a base64 download link for given data as CSV.
    """
    df = pd.DataFrame(data)
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">📥 Download Data as CSV</a>'
    return href
