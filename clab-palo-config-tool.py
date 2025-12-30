import argparse

parser = argparse.ArgumentParser(description="Save and load Palo Alto Networks device configurations in Containerlab environments")
parser.add_argument(
    "action", choices=["save", "load"], help="'save' to export device configurations, 'load' to import and apply saved configurations"
)

args = parser.parse_args()
action = args.action  # 'save' or 'load'

import requests
import json
import yaml
import inquirer
import subprocess
import os
import xmltodict
import urllib3
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Function block
def do_panos_login(host: str, username: str, password: str):
    """
    Authenticate with a Palo Alto Networks device and retrieve an API key.

    This function sends a POST request to the Palo Alto Networks API keygen endpoint
    to authenticate with the device using provided credentials.

    Args:
        host (str): The IP address or hostname of the Palo Alto Networks device.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        requests.Response: The response object containing the API key in the response body.

    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an error status code.
    """
    resp = requests.post(
        f"https://{host}/api/?type=keygen&user={username}&password={password}",
        verify=False,
    )
    resp.raise_for_status()
    return resp


def do_panos_export_configuration(host: str, api_key: str):
    """
    Export the configuration from a Palo Alto Networks device.

    This function sends a GET request to the Palo Alto Networks API to export the
    device configuration using the provided API key.

    Args:
        host (str): The IP address or hostname of the Palo Alto Networks device.
        api_key (str): The API key for authentication.
    Returns:
        requests.Response: The response object containing the exported configuration in the response body.
    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an error status code.
    """
    resp = requests.get(
        f"https://{host}/api/?type=export&category=device-state&key={api_key}",
        verify=False,
    )
    resp.raise_for_status()
    return resp


def do_panos_import_device_state_tgz(
    host: str, api_key: str, tgz_bytes: bytes, filename: str = "device-state.tgz"
):
    """
    Import a device state .tgz to a Palo Alto Networks device.

    Args:
        host (str): PAN-OS device hostname or IP.
        api_key (str): API key for authentication.
        tgz_bytes (bytes): The content of the .tgz file as bytes.
        filename (str): Name to assign to the uploaded file (default: 'device-state.tgz').

    Returns:
        requests.Response: The HTTP response (raise_for_status already called).
    """
    url = f"https://{host}/api/?type=import&category=device-state&key={api_key}"
    # Build multipart/form-data. Do NOT set Content-Type; `requests` will add a correct boundary.
    # The server expects the field name to be exactly 'file'.
    files = {
        # (filename, filebytes, content_type)
        # 'application/gzip' is common for .tgz; 'application/octet-stream' also works.
        "file": (filename, tgz_bytes, "application/gzip"),
    }

    resp = requests.post(url, files=files, verify=False, timeout=60)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    status = root.get("status")
    assert (
        status == "success"
    ), f"Import configuration API call failed with status: {status}"

    return resp


def do_panos_load_configuration(
    host: str, api_key: str,
):
    """
    Load the imported configuration on a Palo Alto Networks device.

    This function sends a GET request to the Palo Alto Networks API to load the
    imported configuration using the provided API key.

    Args:
        host (str): The IP address or hostname of the Palo Alto Networks device.
        api_key (str): The API key for authentication.
    Returns:
        requests.Response: The response object containing the load configuration response in the response body.
    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an error status code.
    """
    cmd = "<load><device-state></device-state></load>"
    url = f"https://{host}/api/?type=op&key={api_key}"
    resp = requests.post(url, data={"cmd": cmd}, timeout=60, verify=False)
    resp.raise_for_status()
    return resp


def do_panos_commit(host: str, api_key: str, description: str = ""):
    url = f"https://{host}/api/?type=commit&key={api_key}"
    cmd = f"<commit><description>{description}</description></commit>"
    resp = requests.post(url, data={"cmd": cmd}, verify=False, timeout=60)
    resp.raise_for_status()
    return resp.text


def do_check_commit_job_status(host: str, api_key: str, job_id: str):
    url = f"https://{host}/api/?type=op&key={api_key}"
    cmd = f"<show><jobs><id>{job_id}</id></jobs></show>"
    resp = requests.post(url, data={"cmd": cmd}, verify=False, timeout=60)
    resp.raise_for_status()
    return resp.text


def process_save_node(node, selected_lab, inventory_data, lab_path):
    """Worker function to save configuration for a single node."""
    hostname = node["name"]
    prefix = "clab-" + selected_lab + "-"
    real_hostname = hostname.removeprefix(prefix)
    ip_address = str(node["ipv4_address"]).split("/")[0]
    node_username = inventory_data[real_hostname]["username"]
    node_password = inventory_data[real_hostname]["password"]
    
    token = do_panos_login(
        host=ip_address, username=node_username, password=node_password
    )
    token = xmltodict.parse(token.text)
    token = token["response"]["result"]["key"]
    
    config = do_panos_export_configuration(host=ip_address, api_key=token)
    with open(
        f"{lab_path}/clab-{str(selected_lab).split('.clab.yml')[0]}/{real_hostname}/config/device-state.tgz",
        "wb",
    ) as f:
        f.write(config.content)
    
    return f"Saved configuration for device: {real_hostname} ({ip_address})"


def process_load_node(node, selected_lab, inventory_data, lab_path):
    """Worker function to load configuration for a single node."""
    hostname = node["name"]
    prefix = "clab-" + selected_lab + "-"
    real_hostname = hostname.removeprefix(prefix)
    ip_address = str(node["ipv4_address"]).split("/")[0]
    node_username = inventory_data[real_hostname]["username"]
    node_password = inventory_data[real_hostname]["password"]
    
    token = do_panos_login(
        host=ip_address, username=node_username, password=node_password
    )
    token = xmltodict.parse(token.text)
    token = token["response"]["result"]["key"]
    
    tgz_bytes = open(
        f"{lab_path}/clab-{str(selected_lab).split('.clab.yml')[0]}/{real_hostname}/config/device-state.tgz",
        "rb",
    ).read()
    
    print(f"Device: {real_hostname} ({ip_address}) - API Key: {token}")
    
    import_config = do_panos_import_device_state_tgz(
        host=ip_address, api_key=token, tgz_bytes=tgz_bytes
    )
    print(f"{hostname}: Import response: {import_config.text}")
    
    load_config = do_panos_load_configuration(
        host=ip_address, api_key=token
    )
    print(f"{hostname}: Load response: {load_config.text}")
    
    commit_response = do_panos_commit(
        host=ip_address,
        api_key=token,
        description="Committed via palo-clab-config-tool",
    )
    commit_job_id = commit_response.split("jobid")[1].split("<")[0].split()[0]
    print(f"Commit response: {commit_response}")
    
    for attempt in range(25):
        status_response = do_check_commit_job_status(
            host=ip_address, api_key=token, job_id=int(commit_job_id)
        )
        status_dict = xmltodict.parse(status_response)
        job_status = status_dict["response"]["result"]["job"]["status"]
        print(job_status)
        print(f"{hostname}: Commit job status): {job_status}")
        if job_status == "FIN":
            print(f"{hostname}: Commit finished successfully")
            break
        elif job_status == "PEND" or job_status == "ACT":
            print(
                f"{hostname}: Commit still in progress, waiting 5 seconds before checking again..."
            )
            time.sleep(5)
        else:
            print(f"{hostname}: Commit failed with status: {job_status}")
            break
    
    return f"{hostname}: Completed load"


if __name__ == "__main__":
    ## Prompt user for lab ##

    # Navigate to root directory before running command so the labPath var is complete
    command = "clab inspect --all -w -f json"
    labs = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Parse the JSON
    try:
        labs = json.loads(labs.stdout)
    except json.decoder.JSONDecodeError:
        print("Error decoding containerlab output, are any containers running?")
        quit(1)

    # Only one lab, no need for a list of options
    if len(labs) == 1:
        print("One running lab detected")
        first_key = list(labs.keys())[0]
        first_entry = labs[first_key][0]
        onelabquestion = [
            inquirer.Confirm(
                "continue",
                message=f"Should I continue to open for lab \"{first_key}\" (Owner: {first_entry['owner']}, {len(labs[first_key])} containers, File: {first_entry['absLabPath']})?",
                default=True,
            )
        ]
        answers = inquirer.prompt(onelabquestion)
        # Exit if no is pressed
        if not answers["continue"]:
            quit()
        # Strip the ending file as we need to find the actual lab files
        selected_lab_topo_file_path = first_entry["absLabPath"]

    elif len(labs) > 1:
        print("Multiple running labs detected")
        lablist = []
        for lab_name, lab_entries in labs.items():
            first_entry = lab_entries[0]
            lablist.append(
                f"{lab_name} (Owner: {first_entry['owner']}, {len(lab_entries)} containers, File: {first_entry['absLabPath']})"
            )

        questions = [
            inquirer.List(
                "Lab Selection",
                message="Which lab do you wish to open?",
                choices=lablist,
            )
        ]
        answers = inquirer.prompt(questions)

        # Extract the selected lab name
        selected_lab = answers["Lab Selection"].split(" ")[0]
        lab_entries = labs[selected_lab]
        # Just take the first entry's lab path as they should all be the same
        selected_lab_topo_file_path = lab_entries[0]["absLabPath"]

# selected_lab_topo_file_path was defined in either case, so we can exit the conditionals
try:
    lab_path = os.path.dirname(selected_lab_topo_file_path)
    topology_file_name = os.path.basename(selected_lab_topo_file_path)
    inventory_path = lab_path + f"/clab-{selected_lab}/nornir-simple-inventory.yml"
    inventory_data = yaml.safe_load(open(inventory_path))
except PermissionError:
    print(f"Permission denied when trying to open {inventory_path}")
    quit(1)
except FileNotFoundError:
    print(f"Could not find file {selected_lab_topo_file_path} or inventory file.")
    quit(1)

panos_nodes = [c for c in lab_entries if c.get("kind") == "paloalto_panos"]

if action == "save":
    with ThreadPoolExecutor(max_workers=len(panos_nodes)) as executor:
        futures = [
            executor.submit(process_save_node, node, selected_lab, inventory_data, lab_path)
            for node in panos_nodes
        ]
        for future in as_completed(futures):
            try:
                result = future.result()
                print(result)
            except Exception as e:
                print(f"Error processing node: {e}")
elif action == "load":
    with ThreadPoolExecutor(max_workers=len(panos_nodes)) as executor:
        futures = [
            executor.submit(process_load_node, node, selected_lab, inventory_data, lab_path)
            for node in panos_nodes
        ]
        for future in as_completed(futures):
            try:
                result = future.result()
                print(result)
            except Exception as e:
                print(f"Error processing node: {e}")
