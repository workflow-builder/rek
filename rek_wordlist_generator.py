class REKWordlistGenerator:
    def __init__(self, silent: bool = False, domain: str = None):
        self.silent = silent
        self.domain = domain
        self.seclists_base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        if domain:
            self.wordlists_dir = f"{domain}-wordlists"
            self.output_dir = f"{domain}-wordlists/generated"
        else:
            self.wordlists_dir = "wordlists"
            self.output_dir = "generated_wordlists"
class REKWordlistGenerator:
    def __init__(self, silent: bool = False, domain: str = None):
        self.silent = silent
        self.domain = domain
        self.seclists_base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        if domain:
            self.wordlists_dir = f"{domain}-wordlists"
            self.output_dir = f"{domain}-wordlists/generated"
        else:
            self.wordlists_dir = "wordlists"
            self.output_dir = "generated_wordlists"
def main():
    """Main function for standalone execution."""
    print(colored("🔧 REK Wordlist Generator", "cyan", attrs=["bold"]))
    print(colored("Standalone wordlist generation tool", "cyan"))

    generator = REKWordlistGenerator(silent=False)