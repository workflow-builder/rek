#!/usr/bin/env python3
import requests
import argparse
import os
import re
import logging
from typing import List, Dict

EMAIL_REGEX = r"[a-zA-Z0.9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

class EmailSearcher:
    def __init__(self, timeout: int = 10, silent: bool = False):
        self.timeout = timeout
        self.silent = silent
        self.logger = logging.getLogger(__name__)

    def get_repos(self, entity_name: str, token: str = None) -> List[Dict]:
        """Fetch repositories for a user or organization."""
        url = f"https://api.github.com/users/{entity_name}/repos?per_page=100&type=all"
        headers = {"Authorization": f"token {token}"} if token else {}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 404:
                if not self.silent:
                    print(f"❌ Entity '{entity_name}' not found on GitHub.")
                raise ValueError(f"Entity '{entity_name}' not found.")
            response.raise_for_status()
            repos = response.json()
            if not self.silent:
                print(f"✅ Found {len(repos)} repositories.\n")
            return repos
        except requests.RequestException as e:
            if not self.silent:
                print(f"❌ Error fetching repos for {entity_name}: {e}")
            raise

    def get_commit_emails(self, entity: str, repo: Dict, token: str = None, max_commits: int = 50) -> List[Dict]:
        """Extract emails from commits in a repository."""
        url = f"https://api.github.com/repos/{entity}/{repo['name']}/commits?per_page={max_commits}"
        headers = {"Authorization": f"token {token}"} if token else {}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            commits = response.json()
            emails = []

            for commit in commits:
                commit_data = commit.get("commit", {})
                commit_url = commit.get("html_url", "")
                commit_message = commit_data.get("message", "")
                commit_author = commit_data.get("author", {})
                author_info = commit.get("author", {})
                github_user = author_info.get("login", entity) if author_info else entity

                candidates = set(re.findall(EMAIL_REGEX, commit_message))
                if commit_author.get("email"):
                    candidates.add(commit_author["email"])

                for email in candidates:
                    emails.append({
                        "email": email,
                        "commit_url": commit_url,
                        "repo": repo["name"],
                        "github_user": github_user
                    })

            return emails
        except requests.RequestException as e:
            if not self.silent:
                print(f"❌ Error fetching commits for {repo['name']}: {e}")
            return []

    def search_by_domain(self, domain: str, token: str = None, max_results: int = 50) -> List[Dict]:
        """Search GitHub public commits for emails associated with a domain."""
        if not self.silent:
            print(f"🔍 Searching GitHub public commits for domain: {domain}...")
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.text-match+json"
        } if token else {
            "Accept": "application/vnd.github.text-match+json"
        }

        results, page = [], 1
        while len(results) < max_results:
            search_url = f"https://api.github.com/search/commits?q={domain}+in:message&type=Commits&page={page}&per_page=100"
            try:
                response = requests.get(search_url, headers=headers, timeout=self.timeout)
                if response.status_code != 200:
                    if not self.silent:
                        print(f"⚠️ Search stopped with status {response.status_code}")
                    break
                data = response.json()
                for item in data.get("items", []):
                    msg = item.get("commit", {}).get("message", "")
                    commit_url = item.get("html_url", "")
                    found_emails = re.findall(EMAIL_REGEX, msg)
                    for email in found_emails:
                        if email.endswith(domain):
                            results.append({
                                "email": email,
                                "commit_url": commit_url,
                                "repo": item.get("repository", {}).get("name", ""),
                                "github_user": item.get("repository", {}).get("owner", {}).get("login", "")
                            })
                            if len(results) >= max_results:
                                break
                page += 1
            except requests.RequestException as e:
                if not self.silent:
                    print(f"❌ Error searching commits for domain {domain}: {e}")
                break
        return results

    def check_leaked_email(self, email: str, hibp_key: str = None) -> tuple[bool, str]:
        """Check if an email has been involved in a data breach using HIBP."""
        if not hibp_key:
            return False, ""
        headers = {
            "hibp-api-key": hibp_key,
            "User-Agent": "rek-email-scanner"
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 404:
                return False, ""
            if response.status_code != 200:
                if not self.silent:
                    print(f"⚠️ HIBP check failed for {email}: Status {response.status_code}")
                return False, ""
            breaches = response.json()
            sources = [b["Name"] for b in breaches]
            return True, ", ".join(sources)
        except Exception as e:
            if not self.silent:
                print(f"❌ Error checking HIBP for {email}: {e}")
            return False, ""

    def save_results(self, results: List[Dict], output_file: str) -> None:
        """Save email search results to a CSV file."""
        try:
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("Email,Repo,GitHubUser,Leaked,LeakedSource,CommitURL\n")
                for r in results:
                    f.write(f"{r['email']},{r['repo']},{r['github_user']},{r['leaked']},{r['leaked_source']},{r['commit_url']}\n")
            if not self.silent:
                print(f"\n✅ Results saved to: {output_file}")
        except Exception as e:
            if not self.silent:
                print(f"❌ Error saving results to {output_file}: {e}")
            raise

    def run(self, domain: str = None, username: str = None, token: str = None, output_file: str = "email_results.csv",
            max_commits: int = 50, skip_forks: bool = True, hibp_key: str = None) -> None:
        """Run the email search based on provided parameters."""
        if not self.silent:
            user = os.getenv('USER') or 'user'
            print(f"\n👋 Hello {user}! Starting GitHub email recon...\n")
        all_results = []

        if domain:
            all_results = self.search_by_domain(domain, token=token, max_results=max_commits)
        elif username:
            # Handle username or org
            entity_type = "organization" if username.lower() in ["microsoft", "google", "facebook"] else "user"  # Example heuristic
            if not self.silent:
                print(f"{'🏢' if entity_type == 'organization' else '📦'} Fetching repositories for {entity_type}: {username}")
            try:
                repos = self.get_repos(username, token=token)
                for i, repo in enumerate(repos, 1):
                    if skip_forks and repo.get("fork"):
                        if not self.silent:
                            print(f"[{i}/{len(repos)}] Skipping forked repo {repo['name']}")
                        continue
                    if not self.silent:
                        print(f"[{i}/{len(repos)}] Scanning {repo['name']}...")
                    commits = self.get_commit_emails(username, repo, token=token, max_commits=max_commits)
                    all_results.extend(commits)
            except ValueError:
                return

        # Enrich with HIBP
        seen = set()
        final_results = []
        for item in all_results:
            key = (item["email"], item["repo"])
            if key not in seen:
                is_leaked, source = self.check_leaked_email(item["email"], hibp_key=hibp_key)
                item["leaked"] = "Yes" if is_leaked else "No"
                item["leaked_source"] = source
                final_results.append(item)
                seen.add(key)

        self.save_results(final_results, output_file)

def main():
    parser = argparse.ArgumentParser(description="GitHub Email Recon Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--username", help="GitHub username to search repos")
    group.add_argument("--org", help="GitHub organization to search repos")
    group.add_argument("--domain", help="Email domain to search in public commits")
    parser.add_argument("--token", help="GitHub API token (optional)")
    parser.add_argument("--hibp-key", help="HIBP API key (optional)")
    parser.add_argument("--limit-commits", type=int, default=50, help="Commit limit per repo or total results (default: 50)")
    parser.add_argument("--output", default="email_results.csv", help="CSV output file")
    parser.add_argument("--silent", action="store_true", help="Run in silent mode")
    args = parser.parse_args()

    logging.basicConfig(level=logging.CRITICAL if args.silent else logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s")

    searcher = EmailSearcher(timeout=10, silent=args.silent)
    if args.org:
        args.username = args.org  # Treat org as username for compatibility
    searcher.run(
        domain=args.domain,
        username=args.username,
        token=args.token,
        output_file=args.output,
        max_commits=args.limit_commits,
        hibp_key=args.hibp_key
    )

if __name__ == "__main__":
    main()