import json
import re

# Load policies
with open("policies.json", "r") as f:
    policies = json.load(f)


# ---------------- PASSWORD POLICY ----------------
def check_password(password):
    policy = policies["password_policy"]
    results = {}
    results["length"] = len(password) >= policy["min_length"]
    results["uppercase"] = bool(re.search(r"[A-Z]", password)) if policy["require_uppercase"] else True
    results["lowercase"] = bool(re.search(r"[a-z]", password)) if policy["require_lowercase"] else True
    results["digit"] = bool(re.search(r"\d", password)) if policy["require_digit"] else True
    results["special"] = bool(re.search(r"[^A-Za-z0-9]", password)) if policy["require_special"] else True
    # Optional: expiration days check (assuming you provide last password change in days)
    results["expiration_days"] = True  # Replace with real logic if needed
    return results


# ---------------- FIREWALL POLICY ----------------
def check_firewall(open_ports, default_deny):
    policy = policies["firewall_policy"]
    results = {}
    unexpected_ports = [p for p in open_ports if p not in policy["allowed_ports"]]
    results["allowed_ports"] = len(unexpected_ports) == 0
    results["default_deny"] = default_deny == policy["deny_all_default"]
    return results, unexpected_ports


# ---------------- LOGGING POLICY ----------------
def check_logging(auth_failures, log_rotation, syslog_forwarding):
    policy = policies["logging_policy"]
    results = {}
    results["auth_failures_enabled"] = auth_failures == policy["auth_failures_enabled"]
    results["log_rotation"] = log_rotation == policy["log_rotation"]
    results["syslog_forwarding_enabled"] = syslog_forwarding == policy["syslog_forwarding_enabled"]
    return results


# ---------------- USER POLICY ----------------
def check_user_accounts(inactive_days, admin_users):
    policy = policies["user_policy"]
    results = {}
    results["max_inactive_days"] = inactive_days <= policy["max_inactive_days"]
    results["max_admin_users"] = admin_users <= policy["max_admin_users"]
    return results


# ---------------- SERVICE POLICY ----------------
def check_services(running_services, open_ports):
    policy = policies["service_policy"]
    results = {}
    results["disable_services"] = all(s not in running_services for s in policy["disable_services"])
    unexpected_ports = [p for p in open_ports if p not in policy["allowed_ports"]]
    results["allowed_ports"] = len(unexpected_ports) == 0
    return results, unexpected_ports


# ---------------- FILE POLICY ----------------
def check_file_permissions(file_permissions):
    policy = policies["file_policy"]
    results = {}
    for f, perm in policy["critical_files"].items():
        results[f] = file_permissions.get(f, "0") == perm
    # Optionally check world-writable dirs here
    return results


# ---------------- PATCH POLICY ----------------
def check_patch(pending_updates):
    policy = policies["patch_policy"]
    return {"pending_updates": pending_updates <= policy["max_pending_updates"]}


# ---------------- NETWORK POLICY ----------------
def check_network(ssh_root_login, tls_version):
    policy = policies["network_policy"]
    results = {}
    results["ssh_root_login"] = ssh_root_login == policy["ssh_root_login"]
    results["tls_min_version"] = tls_version >= policy["tls_min_version"]
    return results


# ---------------- ENDPOINT POLICY ----------------
def check_endpoint(antivirus_running, definitions_up_to_date):
    policy = policies["endpoint_policy"]
    results = {}
    results["antivirus_running"] = antivirus_running == policy["antivirus_running"]
    results["definitions_up_to_date"] = definitions_up_to_date == policy["definitions_up_to_date"]
    return results


# ---------------- MAIN SCRIPT ----------------
if __name__ == "__main__":
    # ---------------- Example Inputs ----------------
    password = "MySecurePass123!"
    open_ports = [22, 443, 8080]  
    default_deny = True
    auth_failures = True
    log_rotation = False
    syslog_forwarding = True
    inactive_days = 120
    admin_users = 3
    running_services = ["ssh", "ftp", "cron"]
    file_permissions = {"/etc/passwd": "644", "/etc/shadow": "640"}
    pending_updates = 6
    ssh_root_login = True
    tls_version = "1.0"
    antivirus_running = True
    definitions_up_to_date = False

    # ---------------- Run Checks ----------------
    pw_results = check_password(password)
    fw_results, fw_unexpected_ports = check_firewall(open_ports, default_deny)
    log_results = check_logging(auth_failures, log_rotation, syslog_forwarding)
    user_results = check_user_accounts(inactive_days, admin_users)
    service_results, service_unexpected_ports = check_services(running_services, open_ports)
    file_results = check_file_permissions(file_permissions)
    patch_results = check_patch(pending_updates)
    network_results = check_network(ssh_root_login, tls_version)
    endpoint_results = check_endpoint(antivirus_running, definitions_up_to_date)

    # ---------------- Print Report ----------------
    print("\n--- Security Policy Check Report ---")

    print("\nPassword Policy:")
    for k, v in pw_results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nFirewall Policy:")
    for k, v in fw_results.items():
        if k == "allowed_ports" and not v:
            print(f"  {k}: FAIL (Unexpected ports: {fw_unexpected_ports})")
        else:
            print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nLogging Policy:")
    for k, v in log_results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nUser Policy:")
    for k, v in user_results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nService Policy:")
    for k, v in service_results.items():
        if k == "allowed_ports" and not v:
            print(f"  {k}: FAIL (Unexpected ports: {service_unexpected_ports})")
        else:
            print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nFile Policy:")
    for f, v in file_results.items():
        print(f"  {f}: {'PASS' if v else 'FAIL'}")

    print("\nPatch Policy:")
    for k, v in patch_results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nNetwork Policy:")
    for k, v in network_results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")

    print("\nEndpoint Policy:")
    for k, v in endpoint_results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
