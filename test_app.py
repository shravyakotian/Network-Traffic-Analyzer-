#!/usr/bin/env python3
"""
Quick test script for the network traffic analyzer
"""

def test_imports():
    print("Testing imports...")
    
    try:
        import streamlit as st
        print("✅ Streamlit imported successfully")
    except Exception as e:
        print(f"❌ Streamlit import failed: {e}")
        return False
    
    try:
        from packet_sniffer import continuous_sniffing, continuous_packets, get_capture_stats
        print("✅ packet_sniffer imported successfully")
    except Exception as e:
        print(f"❌ packet_sniffer import failed: {e}")
        return False
    
    try:
        from analyzer import analyze_packets
        print("✅ analyzer imported successfully")
    except Exception as e:
        print(f"❌ analyzer import failed: {e}")
        return False
    
    try:
        from exporter import generate_csv_download_link, save_analysis_to_csv
        print("✅ exporter imported successfully")
    except Exception as e:
        print(f"❌ exporter import failed: {e}")
        return False
    
    try:
        from scapy.all import get_if_list, conf
        print("✅ scapy imported successfully")
        print(f"   Default interface: {conf.iface}")
        print(f"   Available interfaces: {len(get_if_list())}")
    except Exception as e:
        print(f"❌ scapy import failed: {e}")
        return False
    
    return True

def test_basic_functionality():
    print("\nTesting basic functionality...")
    
    try:
        from packet_sniffer import get_capture_stats
        stats = get_capture_stats()
        print(f"✅ Capture stats: {stats}")
    except Exception as e:
        print(f"❌ Get capture stats failed: {e}")
        return False
    
    try:
        from analyzer import analyze_packets
        # Test with empty data
        result = analyze_packets([])
        print(f"✅ Analyzer works with empty data")
    except Exception as e:
        print(f"❌ Analyzer test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 50)
    print("NETWORK TRAFFIC ANALYZER - QUICK TEST")
    print("=" * 50)
    
    if test_imports():
        print("\n✅ All imports successful!")
        
        if test_basic_functionality():
            print("\n✅ Basic functionality test passed!")
            print("\n🚀 Application should work correctly!")
            print("\nTo start the application:")
            print("  streamlit run app_ui.py")
        else:
            print("\n❌ Basic functionality test failed!")
    else:
        print("\n❌ Import tests failed!")
