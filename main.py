import requests
from ratelimit import limits, RateLimitException, sleep_and_retry
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
import os
import json  # Added for cleaner result formatting

# Constants for rate limiting
ONE_MINUTE = 60
MAX_LOOKUPS_PER_MINUTE = 4

ONE_DAY = 86400
MAX_LOOKUPS_PER_DAY = 500

ONE_MONTH = 2592000
MAX_LOOKUPS_PER_MONTH = 15500

# API Key and base URL
API_KEY = '5d19579326e26d1781c2b99a51d2782c0b274d0a7538cc5dea87431c7fb6994b'
BASE_URL = 'https://www.virustotal.com/api/v3'


class RateLimitedClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'x-apikey': API_KEY})

    @sleep_and_retry
    @limits(calls=MAX_LOOKUPS_PER_MINUTE, period=ONE_MINUTE)
    def get_minute(self, url):
        response = self.session.get(url)
        if response.status_code != 200:
            raise RateLimitException('API response: {}'.format(response.status_code))
        return response.json()

    @sleep_and_retry
    @limits(calls=MAX_LOOKUPS_PER_DAY, period=ONE_DAY)
    def get_day(self, url):
        response = self.session.get(url)
        if response.status_code != 200:
            raise RateLimitException('API response: {}'.format(response.status_code))
        return response.json()

    @sleep_and_retry
    @limits(calls=MAX_LOOKUPS_PER_MONTH, period=ONE_MONTH)
    def get_month(self, url):
        response = self.session.get(url)
        if response.status_code != 200:
            raise RateLimitException('API response: {}'.format(response.status_code))
        return response.json()


class Scanner:
    def __init__(self):
        self.client = RateLimitedClient()

    def scan_file(self, file_path):
        if not os.path.exists(file_path):
            return {'error': f'File not found: {file_path}'}

        url = f'{BASE_URL}/files'
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = self.client.session.post(url, files=files)
            return response.json()

    def scan_url(self, url):
        scan_url = f'{BASE_URL}/urls'
        response = self.client.session.post(scan_url, data={'url': url})
        return response.json()

    def scan_domain(self, domain):
        url = f'{BASE_URL}/domains/{domain}'
        return self.client.get_minute(url)

    def scan_ip(self, ip):
        url = f'{BASE_URL}/ip_addresses/{ip}'
        return self.client.get_minute(url)

class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Scanner")
        self.scanner = Scanner()

        # Main frame
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Scan type selection
        scan_type_frame = tk.Frame(main_frame)
        scan_type_frame.pack(fill=tk.X, pady=5)
        tk.Label(scan_type_frame, text="Select Scan Type:").pack(anchor=tk.W)
        self.scan_type = tk.StringVar(value="file")
        tk.Radiobutton(scan_type_frame, text="File", variable=self.scan_type, value="file").pack(anchor=tk.W)
        tk.Radiobutton(scan_type_frame, text="URL", variable=self.scan_type, value="url").pack(anchor=tk.W)
        tk.Radiobutton(scan_type_frame, text="Domain", variable=self.scan_type, value="domain").pack(anchor=tk.W)
        tk.Radiobutton(scan_type_frame, text="IP", variable=self.scan_type, value="ip").pack(anchor=tk.W)

        # Input field
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        tk.Label(input_frame, text="Input:").pack(anchor=tk.W)
        self.input_field = tk.Entry(input_frame, width=50)
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.browse_button = tk.Button(input_frame, text="Browse", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        # Scan button
        self.scan_button = tk.Button(main_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        # Result display
        result_frame = tk.Frame(main_frame)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        tk.Label(result_frame, text="Result:").pack(anchor=tk.W)
        self.result_text = tk.Text(result_frame, height=10, width=50)
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_field.delete(0, tk.END)
            self.input_field.insert(0, file_path)

    def start_scan(self):
        scan_type = self.scan_type.get()
        input_value = self.input_field.get()

        if not input_value:
            messagebox.showerror("Input Error", "Please provide an input value.")
            return

        self.progress.start()
        self.scan_button.config(state=tk.DISABLED)

        with PoolExecutor(max_workers=1) as executor:
            if scan_type == "file":
                future = executor.submit(self.scanner.scan_file, input_value)
            elif scan_type == "url":
                future = executor.submit(self.scanner.scan_url, input_value)
            elif scan_type == "domain":
                future = executor.submit(self.scanner.scan_domain, input_value)
            elif scan_type == "ip":
                future = executor.submit(self.scanner.scan_ip, input_value)
            else:
                messagebox.showerror("Scan Error", "Invalid scan type selected.")
                return

            result = future.result()
            self.progress.stop()
            self.scan_button.config(state=tk.NORMAL)

            # Debugging: Print the result to console
            print(result)

            formatted_result = self.format_result(result)

            # Debugging: Print the formatted result to console
            print(formatted_result)

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, formatted_result)

    def format_result(self, result):
        if 'error' in result:
            return f"Error: {result['error']}"

        formatted_result = "Scan Result:\n"
        if 'data' in result:
            attributes = result['data'].get('attributes', {})

            # Calculate risk percentage
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            total_scans = sum(last_analysis_stats.values())
            malicious_scans = last_analysis_stats.get('malicious', 0)
            risk_percentage = (malicious_scans / total_scans) * 100 if total_scans > 0 else 0

            formatted_result += f"  - Risk Percentage: {risk_percentage:.2f}%\n"
            formatted_result += f"  - Reputation: {attributes.get('reputation', 'N/A')}\n"

            # Add a summary of the analysis
            formatted_result += f"  - Analysis Summary:\n"
            for vendor, analysis in attributes.get('last_analysis_results', {}).items():
                formatted_result += f"    {vendor}: {analysis['result']}\n"
        else:
            formatted_result += "No detailed data available."

        return formatted_result

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()