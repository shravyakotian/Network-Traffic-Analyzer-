import pandas as pd
import base64

def generate_csv_download_link(data, filename="captured_data.csv"):
    """
    Generates a base64 download link for given data as CSV (for Streamlit UI).
    """
    df = pd.DataFrame(data)
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">📥 Download Data as CSV</a>'
    return href


def auto_save_to_csv(data, filename="auto_saved_packets.csv"):
    """
    Automatically saves given data to a CSV file in the project folder.
    """
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"[INFO] Packet data automatically saved to {filename}")


def save_analysis_to_csv(protocol_stats, data_by_src, top_src, top_dst, ddos_list, filename="analysis_report.csv"):
    """
    Saves analysis results to a CSV file.
    """
    with open(filename, "w") as f:
        f.write("Protocol,Count\n")
        for proto, count in protocol_stats.items():
            f.write(f"{proto},{count}\n")

        f.write("\nSource IP,Total Data (bytes)\n")
        for ip, total in data_by_src.items():
            f.write(f"{ip},{total}\n")

        f.write("\nTop Source IPs,Packet Count\n")
        for ip, count in top_src:
            f.write(f"{ip},{count}\n")

        f.write("\nTop Destination IPs,Packet Count\n")
        for ip, count in top_dst:
            f.write(f"{ip},{count}\n")

        f.write("\nPotential DDoS Suspects\n")
        for ip in ddos_list:
            f.write(f"{ip}\n")

    print(f"[INFO] Analysis report saved to {filename}")


