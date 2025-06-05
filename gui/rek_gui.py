import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
import asyncio
from rek_beta import ReconTool
from gui.utils import TextHandler, run_async_in_thread
import argparse
import os
from termcolor import colored

class RekGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("REK - Reconnaissance Tool")
        self.root.geometry("800x600")
        self.loop = asyncio.new_event_loop()
        self.setup_styles()
        self.create_widgets()
        self.setup_logging()

    def setup_styles(self):
        """Configure styles for colored log tags."""
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TEntry', padding=5)

    def setup_logging(self):
        """Set up logging to display in the GUI."""
        self.log_text = tk.Text(self.root, height=10, state='disabled', wrap='word')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=5)
        for color in ['green', 'yellow', 'red', 'white']:
            self.log_text.tag_configure(color, foreground=color)

        handler = TextHandler(self.log_text)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    def create_widgets(self):
        """Create the tabbed interface."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)

        self.subdomain_frame = ttk.Frame(self.notebook)
        self.http_frame = ttk.Frame(self.notebook)
        self.dir_frame = ttk.Frame(self.notebook)
        self.email_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.subdomain_frame, text="Subdomain Enumeration")
        self.notebook.add(self.http_frame, text="HTTP Status Checking")
        self.notebook.add(self.dir_frame, text="Directory Scanning")
        self.notebook.add(self.email_frame, text="REK Email Search")

        self.create_subdomain_tab()
        self.create_http_tab()
        self.create_directory_tab()
        self.create_email_tab()

    def create_subdomain_tab(self):
        """Create widgets for the Subdomain Enumeration tab."""
        ttk.Label(self.subdomain_frame, text="Domain (e.g., xyz.com):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.sub_domain_entry = ttk.Entry(self.subdomain_frame, width=50)
        self.sub_domain_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.subdomain_frame, text="Output File (default: results.txt):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.sub_output_entry = ttk.Entry(self.subdomain_frame, width=50)
        self.sub_output_entry.insert(0, "results.txt")
        self.sub_output_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.subdomain_frame, text="Browse", command=self.browse_sub_output).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(self.subdomain_frame, text="Subdomain Wordlist:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.sub_wordlist_entry = ttk.Entry(self.subdomain_frame, width=50)
        self.sub_wordlist_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(self.subdomain_frame, text="Browse", command=self.browse_sub_wordlist).grid(row=2, column=2, padx=5, pady=5)

        ttk.Label(self.subdomain_frame, text="GitHub Token (optional):").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.sub_token_entry = ttk.Entry(self.subdomain_frame, width=50)
        self.sub_token_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(self.subdomain_frame, text="Timeout (seconds, default: 10):").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.sub_timeout_entry = ttk.Entry(self.subdomain_frame, width=10)
        self.sub_timeout_entry.insert(0, "10")
        self.sub_timeout_entry.grid(row=4, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.subdomain_frame, text="Concurrency (default: 50):").grid(row=5, column=0, sticky='w', padx=5, pady=5)
        self.sub_concurrency_entry = ttk.Entry(self.subdomain_frame, width=10)
        self.sub_concurrency_entry.insert(0, "50")
        self.sub_concurrency_entry.grid(row=5, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.subdomain_frame, text="Retries (default: 3):").grid(row=6, column=0, sticky='w', padx=5, pady=5)
        self.sub_retries_entry = ttk.Entry(self.subdomain_frame, width=10)
        self.sub_retries_entry.insert(0, "3")
        self.sub_retries_entry.grid(row=6, column=1, sticky='w', padx=5, pady=5)

        self.sub_silent_var = tk.BooleanVar()
        ttk.Checkbutton(self.subdomain_frame, text="Silent Mode", variable=self.sub_silent_var).grid(row=7, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        ttk.Button(self.subdomain_frame, text="Run Subdomain Enumeration", command=self.run_subdomain).grid(row=8, column=0, columnspan=3, pady=10)

    def create_http_tab(self):
        """Create widgets for the HTTP Status Checking tab."""
        ttk.Label(self.http_frame, text="Input File (default: results.txt):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.http_input_entry = ttk.Entry(self.http_frame, width=50)
        self.http_input_entry.insert(0, "results.txt")
        self.http_input_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.http_frame, text="Browse", command=self.browse_http_input).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(self.http_frame, text="Output File (default: http_results.csv):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.http_output_entry = ttk.Entry(self.http_frame, width=50)
        self.http_output_entry.insert(0, "http_results.csv")
        self.http_output_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.http_frame, text="Browse", command=self.browse_http_output).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(self.http_frame, text="Timeout (seconds, default: 10):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.http_timeout_entry = ttk.Entry(self.http_frame, width=10)
        self.http_timeout_entry.insert(0, "10")
        self.http_timeout_entry.grid(row=2, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.http_frame, text="Concurrency (default: 50):").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.http_concurrency_entry = ttk.Entry(self.http_frame, width=10)
        self.http_concurrency_entry.insert(0, "50")
        self.http_concurrency_entry.grid(row=3, column=1, sticky='w', padx=5, pady=5)

        self.http_silent_var = tk.BooleanVar()
        ttk.Checkbutton(self.http_frame, text="Silent Mode", variable=self.http_silent_var).grid(row=4, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        ttk.Button(self.http_frame, text="Run HTTP Status Checking", command=self.run_http).grid(row=5, column=0, columnspan=3, pady=10)

    def create_directory_tab(self):
        """Create widgets for the Directory Scanning tab."""
        ttk.Label(self.dir_frame, text="Input File (default: http_results.csv):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.dir_input_entry = ttk.Entry(self.dir_frame, width=50)
        self.dir_input_entry.insert(0, "http_results.csv")
        self.dir_input_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.dir_frame, text="Browse", command=self.browse_dir_input).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(self.dir_frame, text="Status Codes (e.g., 200,301):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.dir_status_entry = ttk.Entry(self.dir_frame, width=50)
        self.dir_status_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.dir_frame, text="Single URL (optional, e.g., https://xyz.com):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.dir_url_entry = ttk.Entry(self.dir_frame, width=50)
        self.dir_url_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(self.dir_frame, text="Directory Wordlist:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.dir_wordlist_entry = ttk.Entry(self.dir_frame, width=50)
        self.dir_wordlist_entry.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(self.dir_frame, text="Browse", command=self.browse_dir_wordlist).grid(row=3, column=2, padx=5, pady=5)

        ttk.Label(self.dir_frame, text="Timeout (seconds, default: 10):").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.dir_timeout_entry = ttk.Entry(self.dir_frame, width=10)
        self.dir_timeout_entry.insert(0, "10")
        self.dir_timeout_entry.grid(row=4, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.dir_frame, text="Concurrency (default: 50):").grid(row=5, column=0, sticky='w', padx=5, pady=5)
        self.dir_concurrency_entry = ttk.Entry(self.dir_frame, width=10)
        self.dir_concurrency_entry.insert(0, "50")
        self.dir_concurrency_entry.grid(row=5, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.dir_frame, text="Depth (1-10, default: 5):").grid(row=6, column=0, sticky='w', padx=5, pady=5)
        self.dir_depth_entry = ttk.Entry(self.dir_frame, width=10)
        self.dir_depth_entry.insert(0, "5")
        self.dir_depth_entry.grid(row=6, column=1, sticky='w', padx=5, pady=5)

        self.dir_silent_var = tk.BooleanVar()
        ttk.Checkbutton(self.dir_frame, text="Silent Mode", variable=self.dir_silent_var).grid(row=7, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        ttk.Button(self.dir_frame, text="Run Directory Scanning", command=self.run_directory).grid(row=8, column=0, columnspan=3, pady=10)

    def create_email_tab(self):
        """Create widgets for the REK Email Search tab."""
        ttk.Label(self.email_frame, text="Search Type:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.email_search_type = tk.StringVar(value="domain")
        ttk.Radiobutton(self.email_frame, text="By Domain", variable=self.email_search_type, value="domain").grid(row=0, column=1, sticky='w')
        ttk.Radiobutton(self.email_frame, text="By Username", variable=self.email_search_type, value="username").grid(row=0, column=2, sticky='w')

        ttk.Label(self.email_frame, text="Domain or Username (e.g., xyz.com or exampleuser):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.email_target_entry = ttk.Entry(self.email_frame, width=50)
        self.email_target_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.email_frame, text="Output File (default: email_results.csv):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.email_output_entry = ttk.Entry(self.email_frame, width=50)
        self.email_output_entry.insert(0, "email_results.csv")
        self.email_output_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(self.email_frame, text="Browse", command=self.browse_email_output).grid(row=2, column=2, padx=5, pady=5)

        ttk.Label(self.email_frame, text="GitHub Token (optional):").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.email_token_entry = ttk.Entry(self.email_frame, width=50)
        self.email_token_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(self.email_frame, text="Max Commits (default: 50):").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.email_max_commits_entry = ttk.Entry(self.email_frame, width=10)
        self.email_max_commits_entry.insert(0, "50")
        self.email_max_commits_entry.grid(row=4, column=1, sticky='w', padx=5, pady=5)

        self.email_skip_forks_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.email_frame, text="Skip Forks", variable=self.email_skip_forks_var).grid(row=5, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        ttk.Label(self.email_frame, text="Timeout (seconds, default: 10):").grid(row=6, column=0, sticky='w', padx=5, pady=5)
        self.email_timeout_entry = ttk.Entry(self.email_frame, width=10)
        self.email_timeout_entry.insert(0, "10")
        self.email_timeout_entry.grid(row=6, column=1, sticky='w', padx=5, pady=5)

        self.email_silent_var = tk.BooleanVar()
        ttk.Checkbutton(self.email_frame, text="Silent Mode", variable=self.email_silent_var).grid(row=7, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        ttk.Button(self.email_frame, text="Run Email Search", command=self.run_email).grid(row=8, column=0, columnspan=3, pady=10)

    def browse_sub_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.sub_output_entry.delete(0, tk.END)
            self.sub_output_entry.insert(0, filename)

    def browse_sub_wordlist(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.sub_wordlist_entry.delete(0, tk.END)
            self.sub_wordlist_entry.insert(0, filename)

    def browse_http_input(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")])
        if filename:
            self.http_input_entry.delete(0, tk.END)
            self.http_input_entry.insert(0, filename)

    def browse_http_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if filename:
            self.http_output_entry.delete(0, tk.END)
            self.http_output_entry.insert(0, filename)

    def browse_dir_input(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.dir_input_entry.delete(0, tk.END)
            self.dir_input_entry.insert(0, filename)

    def browse_dir_wordlist(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.dir_wordlist_entry.delete(0, tk.END)
            self.dir_wordlist_entry.insert(0, filename)

    def browse_email_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if filename:
            self.email_output_entry.delete(0, tk.END)
            self.email_output_entry.insert(0, filename)

    def validate_numeric(self, value, field_name, min_val=1):
        try:
            val = int(value)
            if val < min_val:
                raise ValueError
            return val
        except ValueError:
            messagebox.showerror("Invalid Input", f"{field_name} must be an integer >= {min_val}")
            raise

    def run_subdomain(self):
        """Run subdomain enumeration."""
        try:
            args = argparse.Namespace(
                domain=self.sub_domain_entry.get().strip(),
                output=self.sub_output_entry.get().strip(),
                subdomain_wordlist=self.sub_wordlist_entry.get().strip() or None,
                token=self.sub_token_entry.get().strip() or None,
                timeout=self.validate_numeric(self.sub_timeout_entry.get(), "Timeout"),
                concurrency=self.validate_numeric(self.sub_concurrency_entry.get(), "Concurrency"),
                retries=self.validate_numeric(self.sub_retries_entry.get(), "Retries"),
                silent=self.sub_silent_var.get(),
                input=None,
                status=None,
                url=None,
                dir_wordlist=None,
                depth=5,
                email_domain=None,
                email_username=None,
                limit_commits=50,
                skip_forks=True
            )
            if not args.domain:
                messagebox.showerror("Error", "Domain is required")
                return
            logging.getLogger().setLevel(logging.CRITICAL if args.silent else logging.INFO)
            recon_tool = ReconTool(args)
            run_async_in_thread(recon_tool.run_subdomain_scan(args), self.loop)
            messagebox.showinfo("Started", "Subdomain Enumeration started. Check logs for progress.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_http(self):
        """Run HTTP status checking."""
        try:
            args = argparse.Namespace(
                input=self.http_input_entry.get().strip(),
                output=self.http_output_entry.get().strip(),
                timeout=self.validate_numeric(self.http_timeout_entry.get(), "Timeout"),
                concurrency=self.validate_numeric(self.http_concurrency_entry.get(), "Concurrency"),
                silent=self.http_silent_var.get(),
                domain=None,
                subdomain_wordlist=None,
                status=None,
                url=None,
                dir_wordlist=None,
                retries=3,
                depth=5,
                token=None,
                email_domain=None,
                email_username=None,
                limit_commits=50,
                skip_forks=True
            )
            if not args.input:
                messagebox.showerror("Error", "Input file is required")
                return
            if not os.path.exists(args.input):
                messagebox.showerror("Error", f"Input file {args.input} does not exist")
                return
            logging.getLogger().setLevel(logging.CRITICAL if args.silent else logging.INFO)
            recon_tool = ReconTool(args)
            run_async_in_thread(recon_tool.run_http_check(args), self.loop)
            messagebox.showinfo("Started", "HTTP Status Checking started. Check logs for progress.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_directory(self):
        """Run directory scanning."""
        try:
            status = self.dir_status_entry.get().strip()
            status_codes = [int(code.strip()) for code in status.split(',')] if status else None
            args = argparse.Namespace(
                input=self.dir_input_entry.get().strip() or None,
                status=status,
                url=self.dir_url_entry.get().strip() or None,
                dir_wordlist=self.dir_wordlist_entry.get().strip() or None,
                timeout=self.validate_numeric(self.dir_timeout_entry.get(), "Timeout"),
                concurrency=self.validate_numeric(self.dir_concurrency_entry.get(), "Concurrency"),
                depth=self.validate_numeric(self.dir_depth_entry.get(), "Depth", min_val=1),
                silent=self.dir_silent_var.get(),
                domain=None,
                subdomain_wordlist=None,
                output=None,
                retries=3,
                token=None,
                email_domain=None,
                email_username=None,
                limit_commits=50,
                skip_forks=True
            )
            if not (args.status or args.url):
                messagebox.showerror("Error", "Must provide either status codes with input file or a URL")
                return
            if args.input and not os.path.exists(args.input):
                messagebox.showerror("Error", f"Input file {args.input} does not exist")
                return
            logging.getLogger().setLevel(logging.CRITICAL if args.silent else logging.INFO)
            recon_tool = ReconTool(args)
            run_async_in_thread(recon_tool.run_directory_scan(args), self.loop)
            messagebox.showinfo("Started", "Directory Scanning started. Check logs for progress.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_email(self):
        """Run email search."""
        try:
            search_type = self.email_search_type.get()
            target = self.email_target_entry.get().strip()
            args = argparse.Namespace(
                email_domain=target if search_type == "domain" else None,
                email_username=target if search_type == "username" else None,
                output=self.email_output_entry.get().strip(),
                token=self.email_token_entry.get().strip() or None,
                limit_commits=self.validate_numeric(self.email_max_commits_entry.get(), "Max Commits"),
                skip_forks=self.email_skip_forks_var.get(),
                timeout=self.validate_numeric(self.email_timeout_entry.get(), "Timeout"),
                silent=self.email_silent_var.get(),
                domain=None,
                subdomain_wordlist=None,
                input=None,
                status=None,
                url=None,
                dir_wordlist=None,
                concurrency=50,
                retries=3,
                depth=5
            )
            if not target:
                messagebox.showerror("Error", "Domain or username is required")
                return
            logging.getLogger().setLevel(logging.CRITICAL if args.silent else logging.INFO)
            recon_tool = ReconTool(args)
            run_async_in_thread(recon_tool.run_email_search(args), self.loop)
            messagebox.showinfo("Started", "Email Search started. Check logs for progress.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = RekGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()