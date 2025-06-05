import logging
import tkinter as tk
import threading
import asyncio

class TextHandler(logging.Handler):
    """Custom logging handler to display logs in a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        color = {
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red'
        }.get(record.levelname, 'white')

        def append_log():
            self.text_widget.config(state='normal')
            self.text_widget.insert(tk.END, msg + '\n', color)
            self.text_widget.see(tk.END)
            self.text_widget.config(state='disabled')

        self.text_widget.after(0, append_log)

def run_async_in_thread(coro, loop):
    """Run an async coroutine in a separate thread."""
    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)
        loop.close()

    threading.Thread(target=run, daemon=True).start()