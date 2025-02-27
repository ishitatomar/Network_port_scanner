During my internship in Cyber Security and Ethical Hacking, I developed a Port and Network Scanner with a user-friendly GUI.

Key Features:
- Interactive GUI: Designed with Tkinter for a smooth and intuitive user experience.
- Website Information Retrieval: Fetches key website details, including IP addresses and geographical locations, using requests and ipinfo.io.
- Port Scanning: Leverages nmap via python-nmap to scan and report the status of specified ports.
- Threading for Responsiveness: Ensures the GUI remains responsive while performing port scans.
- Robust Error Handling: Implements message boxes to gracefully handle unexpected errors.
  
Technologies Used:
- Python
- Tkinter
- requests
- python-nmap
- socket
- argparse
- threading
  
Outcome:
This application provides users with valuable insights into network configurations and potential vulnerabilities. It retrieves and displays details such as IP address, location, region, city, and country, along with the status of each scanned port.
