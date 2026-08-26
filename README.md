# Aruba Certificate Renewer

Automates monitoring and renewal of HTTPS certificates on ArubaOS-Switch devices such as the Aruba 2930M.

The project is intended to use:

* **Netmiko** for SSH access to ArubaOS-Switch devices
* **OPNsense** as the internal certificate authority
* **Python** for certificate inspection, renewal logic, and validation
* **Docker** for deployment
* **Cron** or a similar scheduler for unattended execution

## Current Status

The project is currently in its initial development stage.

Implemented:

* SSH connectivity to ArubaOS-Switch using Netmiko
* Detection of the active Web certificate
* Certificate expiry parsing
* Configurable renewal warning threshold
* Read-only certificate health reporting

Planned:

* Generate CSRs directly on the switch
* Submit CSRs to the OPNsense CA
* Validate returned certificates
* Install signed certificates over the existing SSH session
* Verify the certificate actually presented by HTTPS
* Automatically save the switch configuration after successful renewal
* Containerised unattended execution
* Logging and failure notifications

## Requirements

For local development:

* Python 3.12 or later
* Netmiko 4.7.0

Install the dependencies into a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Configuration

Copy the example configuration:

```bash
cp config.example.toml config.toml
```

Example:

```toml
[settings]
warning_days = 30

[[switches]]
name = "EXAMPLE-SWITCH"
host = "192.0.2.10"
fqdn = "switch.example.com"
```

`config.toml` is excluded from Git and should contain the real switch inventory.

## Usage

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Run the certificate checker:

```bash
python src/aruba_cert_check.py
```

If credentials are not supplied through the environment, the script prompts for them:

```text
SSH username:
SSH password:
```

Example output:

```text
EXAMPLE-SWITCH
--------------
Address:          192.0.2.10
FQDN:             switch.example.com
AOS-S version:    WC.16.11.0015
Certificate:      webcert2026
TA profile:       webprofile2026
Expires:          2027-09-27
Days remaining:   397
Status:           OK

Summary
-------
Switches checked: 1
OK:               1
Renewal due:      0
Errors:           0
```

## Credentials

The script currently supports credentials supplied either interactively or through:

```text
ARUBA_SSH_USERNAME
ARUBA_SSH_PASSWORD
```

Credentials should not be committed to the repository.

A more suitable unattended authentication mechanism will be implemented before automated renewal is enabled.

## Exit Codes

The checker uses the following exit codes:

| Code | Meaning                                                              |
| ---: | -------------------------------------------------------------------- |
|  `0` | All certificates are healthy                                         |
|  `1` | One or more certificates are expired or within the renewal threshold |
|  `2` | One or more switches could not be checked reliably                   |

## Safety

The current implementation is deliberately read-only.

It issues only inspection commands against the switches and does not enter configuration mode or modify device configuration.

Automated renewal will only be added after the certificate discovery and validation workflow has been proven reliable.

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
