import streamlit as st
import socket

st.title("Port Scanner")

host = st.text_input("Please enter the IP you want to scan:")
port = st.number_input("Please enter the port you want to scan:", min_value=1, max_value=65535, step=1)

if st.button("Scan Port"):
    if host and port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        
        try:
            result = s.connect_ex((host, int(port)))
            if result == 0:
                st.success(f"Port {port} is open on {host}")
            else:
                st.error(f"Port {port} is closed on {host}")
        except socket.gaierror:
            st.error("Hostname could not be resolved")
        except socket.error:
            st.error("Could not connect to server")
        finally:
            s.close()
