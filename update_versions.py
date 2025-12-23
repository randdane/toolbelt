# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "pyyaml",
#     "requests",
# ]
# ///

import hashlib
import logging
import os
from pathlib import Path

import requests
import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
CONFIG_FILE = Path("tools_versions.yml")


def get_latest_github_version(repo_name):
    """Queries GitHub API for the latest release tag."""
    url = f"https://api.github.com/repos/{repo_name}/releases/latest"
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        tag_name = response.json().get("tag_name", "")
        return tag_name[1:] if tag_name.startswith("v") else tag_name
    except Exception as e:
        logging.error(f"Failed to fetch version for {repo_name}: {e}")
        return None


def calculate_sha256(url):
    """Downloads the file from URL and returns its SHA256 hash."""
    logging.info(f"   Downloading to calculate hash: {url}")
    sha256_hash = hashlib.sha256()
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"   Failed to calculate hash: {e}")
        return None


def update_tools():
    if not CONFIG_FILE.exists():
        logging.error("Config file not found.")
        return

    with open(CONFIG_FILE, "r") as f:
        data = yaml.safe_load(f)

    updates_found = False

    for tool_name, tool_config in data.get("tools", {}).items():
        current_ver = str(tool_config.get("version"))
        repo = tool_config.get("github_repo")
        url_template = tool_config.get("url_template")

        if not repo or not url_template:
            continue

        logging.info(f"Checking {tool_name} (Current: {current_ver})...")
        latest_ver = get_latest_github_version(repo)

        # Update if version changed OR if checksum is missing
        if latest_ver and (latest_ver != current_ver or "checksum" not in tool_config):
            if latest_ver != current_ver:
                logging.info(
                    f"🚀 UPDATE FOUND for {tool_name}: {current_ver} -> {latest_ver}"
                )
            else:
                logging.info(
                    f"   Version match, but calculating missing checksum for {tool_name}..."
                )

            # Calculate Hash
            download_url = url_template.replace("{version}", latest_ver)
            file_hash = calculate_sha256(download_url)

            if file_hash:
                data["tools"][tool_name]["version"] = latest_ver
                # Ansible expects the format "sha256:<hash>"
                data["tools"][tool_name]["checksum"] = f"sha256:{file_hash}"
                updates_found = True
        else:
            logging.info(f"   {tool_name} is up to date.")

    if updates_found:
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(data, f, sort_keys=False, default_flow_style=False)
        logging.info("✅ tools_versions.yml updated with versions and checksums.")
    else:
        logging.info("No updates required.")


if __name__ == "__main__":
    update_tools()
