#!/usr/bin/env python3
import argparse
import os
from typing import Dict, List, Set
import shutil
import asyncio
import json
from itertools import chain
import ipaddress


def v(line: str):
    if verbose:
        print(line)


def w(line: str):
    print(f"[!] WARNING - {line}")


def cli():
    """
    Parse the input commands and return the arguments class

        Returns:
            args (argparse.ArgumentParser): Parser containing the arguments from the command line
    """
    parser = argparse.ArgumentParser(
        description="Automate the recon, enumeration, and vulnerability scanning of a target"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (display each command)",
        default=False,
    )
    parser.add_argument(
        "-dr",
        "--dry-run",
        action="store_true",
        help="Perform dry run (do not run commands but print them out to console)",
        default=False,
    )
    domain_group = parser.add_mutually_exclusive_group(required=True)
    domain_group.add_argument(
        "-d",
        "--domain",
        action="store",
        type=str,
        help="The target domain (e.g. example.com)",
    )
    domain_group.add_argument(
        "-dL",
        "--domain-list",
        action="store",
        type=str,
        help="Input file containing target domains",
    )
    domain_group.add_argument(
        "--skip-dns",
        action="store_true",
        help="Skip DNS (subdomain) enumeration.",
    )
    parser.add_argument(
        "-iL",
        "--ips",
        action="store",
        type=str,
        help="Input file containing IP addresses to include in scanning/enumeration",
        default=None,
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="store",
        type=str,
        help="Input file containing IP addresses or hostnames to exclude",
        default=None,
    )
    parser.add_argument(
        "-c",
        "--config",
        action="store",
        type=str,
        help="Path to the 'config' folder containing tool configuration files",
        default="config",
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        type=str,
        help="Directory to write output files too",
        default="output",
    )
    args = parser.parse_args()

    # Seting the verbose and dry run flags
    global verbose
    global dry_run
    verbose = args.verbose
    dry_run = args.dry_run

    return args


def parse_config(config: str):
    """
    Parse the arves.json configuation file from the config directory

        Parameters:
            config (str) - The directory that the arves.json file is stored in

        Returns:
            commands (Dict) - Parsed JSON containing the commands to be run by the script
    """
    try:
        with open(f"{config}/arves.json") as f:
            commands = json.load(f)
    except FileNotFoundError as err:
        print(f"[!] Error opening config file: {config}/arves.json")
        exit(-1)

    return commands


def get_domains(args: argparse.Namespace):
    """
    Retrieve the input domains from the CLI and input files as a list.

        Parameters:
            args (argparse.ArgumentParser): Command line inputs

        Returns:
            domains (List): List of domains to be enumerated
    """
    # If only one input was provided, then convert it to a list
    if args.domain:
        return [args.domain]
    # Otherwise, open the file and read the contents as a list
    else:
        try:
            with open(args.domain_list) as f:
                file_contents = f.read()
                domains = file_contents.splitlines()
            return domains
        except FileNotFoundError as err:
            print(f"[!] Could not open input domain list: {args.domain_list}")
            exit(0)


def check_bins(commands: List):
    """
    Check that the nessecary binaries are available and on the $PATH

        Parameters:
            commands (List) - The list of commands to run

        Returns:
            passed (bool) - False if a nessecary binary is not on the $PATH, otherwise true
    """

    # We don't want to fail as soon as we find a missing binary, but we want to report
    # all of the missing binaries. This variable will remain "True" unless a binary is found
    # missing, but we will continue going through the loop to see if anything else is missing
    passed = True

    for phase, cmd_list in commands.items():
        for cmd in cmd_list:
            # shutil.which is basically just the platform independant `which` command
            # this line just checks to see if the binary name is in the path
            if shutil.which(cmd.get("bin")) == None:
                w(f"Missing binary: {cmd.get('bin')} ({cmd.get('loc')})")
                passed = False

    return passed


def read_ips(ip_file: str):
    """
    Collect all of the IP addresses from the provided IP list. Expand CIDR ranges.

        Parameters:
            ip_file (List) - path to the file contining IP addresses belonging to target
            output (str) - path to output directory
            exclude_file (str) - path to the file containing IP addresses to remove

        Returns:
            ips (Set) - The IP addresses from the file in set form
    """
    ips = set()
    try:
        with open(ip_file) as f:
            # Read in all the IPs as CIDR, even if they aren't
            cidrs = [
                ipaddress.ip_network(cidr, strict=False)
                for cidr in f.read().splitlines()
            ]
            # Then get all the individual ip addresses from the CIDRs
            for cidr in cidrs:
                for ip in cidr:
                    ips.add(str(ip))
    except FileNotFoundError as err:
        w(f"Could not open IP address file ({ip_file})")
    return ips


def collect_targets(ip_in_file: str, output: str, ip_ex_file: str, skip_dns: bool):
    """
    Collect all of the IP addresses from the provided IP list, as well as from
    the subdomain enumeration, and write them to a file. This will write 2 files,
    one with just IP addresses, and one with IP addresses and subdomains (for virtual
    hosting). This function will also use the exclude file to remove hosts from the
    final target files.

        Parameters:
            ip_in_file (List) - path to the file contining IP addresses to include
            output (str) - path to output directory
            ip_ex_file (str) - path to the file containing IP addresses to exclude
            skip_dns (bool) - Whether to read data from DNS folder or not

        Returns:
            N/A
    """
    # Read in the two IP files (if the were provided)
    # If no IP files were provided just use an empty set
    if ip_in_file:
        ip_in = read_ips(ip_file=ip_in_file)
    else:
        ip_in = set()
    if ip_ex_file:
        ip_ex = read_ips(ip_file=ip_ex_file)
    else:
        ip_ex = set()

    ips = ip_in - ip_ex
    hosts = set()

    # read in the DNS validation files
    targets_folder = os.path.join(output, "targets")
    with open(os.path.join(targets_folder, "all.dnsx")) as f:
        # newline delimited JSON
        for line in f:
            record = json.loads(line)
            # Only proceed if there was an A record (IP address) for the host
            if record.get("a", False):

                # Add the host to the list of hostnames
                hosts.add(record.get("host"))

                # Get the A records (IP addresses) for the host and
                # add the IP to the list if it is not in the exclusion list
                for ip in record.get("a"):
                    if ip not in ip_ex:
                        ips.add(ip)

    # Write the resulting sets to their output files
    with open(os.path.join(targets_folder, "ips.txt"), "w") as f:
        f.write("\n".join(ips))

    with open(os.path.join(targets_folder, "hosts.txt"), "w") as f:
        f.write("\n".join(hosts))
        f.write("\n")
        f.write("\n".join(ips))


async def execute_command(command: Dict, **kwargs):
    """
    This funciton acts as a wrapper around subprocess.run to run commands. Dynamic input such as
    {domain} or {config} may be passed in via the kwargs variable.

        Parameters:
            command (str) - The command to execute
            stdin (str) - Any input to pass to the program if it needs input via stdin (looking at
                            you aquatone)
            kwargs (Dict) - All of the dynamic values to populate the `command` with

        Returns:
            None
    """
    # Build the command
    cmd = f"{command.get('bin')} {command.get('args')}"
    for key, val in kwargs.items():
        cmd = cmd.replace(f"{{{key}}}", val)

    # If the command requires input from stdin
    stdin = command.get("stdin", None)
    if command.get("stdin", None) is not None:
        for key, val in kwargs.items():
            stdin = stdin.replace(f"{{{key}}}", val)

    if dry_run or verbose:
        print(f"[*] Issued: {cmd}")

    if dry_run == False:
        # Run the command
        if stdin is None:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate(input=bytes(stdin, encoding="utf8"))

        stdout, stderr = await proc.communicate()
        v(f"[*] Command {cmd!r} exited with code: {proc.returncode}")
        if stdout:
            print(f"[stdout]\n{stdout.decode()}")
        if stderr:
            print(f"[stderr]\n{stderr.decode()}")


async def dns_enum(commands: List, domains: List, output: str, config: str):
    """
    Perform subdomain (DNS) enumeration by executing all of the 'dns_enum' commands

        Parameters:
            commands (List) - List of the command objects to be run
            domains (List) - List of target domains
            output (str) - path to output directory
            config (str) - path to config directory

        Returns:
            N/A
    """
    # Make the output "subs" directory
    subs_folder = os.path.join(output, "subs")
    if not os.path.exists(subs_folder):
        os.makedirs(subs_folder)

    # Execute each of the dns_enum commands
    await asyncio.gather(
        *[
            execute_command(
                command=command,
                domain=domain,
                output=os.path.join(subs_folder, f"{domain}.{command.get('bin')}"),
                config=config,
            )
            # This loop will go over all of the target domains
            for domain in domains
            # this loop will perform each target command on each target domain
            for command in commands
        ]
    )


async def dns_validation(commands: List, output: str, config: str):
    """
    Perform DNS lookups of discovered subdomains to discover live hosts

        Parameters:
            commands (List) - List of the command objects to be run
            output (str) - path to output directory
            config (str) - path to config directory

        Returns:
            N/A
    """
    # Gather all of the enumerated subdomains into a file
    subs = []
    subs_folder = os.path.join(output, "subs")
    for sub_file in os.listdir(subs_folder):
        with open(os.path.join(subs_folder, sub_file)) as f:
            # Append all of the subs as its own list
            subs.append(f.read().splitlines())

    # flatten the lists of subdomains and remove duplicates
    subs = set(chain.from_iterable(subs))

    # write the results to a file
    subs_file = os.path.join(subs_folder, "all.txt")
    with open(subs_file, "w") as f:
        f.write("\n".join(subs))

    # Make targets folder
    targets_folder = os.path.join(output, "targets")
    if not os.path.exists(targets_folder):
        os.makedirs(targets_folder)

    # Execute DNS validation commands
    await asyncio.gather(
        *[
            execute_command(
                command=command,
                output=os.path.join(targets_folder, f"all.{command.get('bin')}"),
                config=config,
                input=subs_file,
            )
            for command in commands
        ]
    )


async def port_scan(commands: List, output: str):
    """
    Perform rapid port scanning via masscan to discover open hosts. Save the
    discovered open ports to a file.

        Parameters:
            commands (List) - List of the command objects to be run
            output (str) - path to output directory

        Returns:
            discovered_ports (Set) - Set of all discovered open ports
    """
    # Make the scans folder
    scans_folder = os.path.join(output, "scans", "ports")
    if not os.path.exists(scans_folder):
        os.makedirs(scans_folder)

    # Retrieve the target list of IP addresses
    # Since this phase is just determining open ports, we wont bother
    # with DNS hostnames
    ip_file = os.path.join(output, "targets", "ips.txt")

    # The default config will only run masscan, but in case someone wants
    # to add extra port scanners here, its possible
    await asyncio.gather(
        *[
            execute_command(
                command=command,
                output=os.path.join(scans_folder, command.get("bin")),
                input=ip_file,
            )
            for command in commands
        ]
    )

    discovered_ports = set()
    with open(os.path.join(scans_folder, "masscan")) as f:
        # Read in the masscan output and add all ports listed as "open"
        # to the discovered_ports set
        discovered = json.load(f)
        for host in discovered:
            for port in host.get("ports"):
                if port.get("status") == "open":
                    discovered_ports.add(str(port.get("port")))

    # Write the discovered ports to a file
    with open(os.path.join(scans_folder, "ports.txt"), "w") as f:
        f.write(",".join(discovered_ports))

    return discovered_ports


async def validation_scan(commands: List, output: str, ports: Set):
    """
    Perform service port scanning via nmap to discover open hosts. Save the
    discovered open ports to a file.

        Parameters:
            commands (List) - List of the command objects to be run
            output (str) - path to output directory
            ports (Set) - Set of discovered ports to scan

        Returns:
            N/A
    """
    scans_folder = os.path.join(output, "scans", "ports")

    # Retrieve the list of hosts to scan
    # We are scanning the hosts and not just the IPs because the output
    # from this tool will be feed into other HTTP scanning tools.
    # Due to virtual hosting, the direct IP address may not be as useful as
    # the full URL with the hostname.
    host_file = os.path.join(output, "targets", "hosts.txt")

    # The default config will only run masscan, but in case someone wants
    # to add extra port scanners here, its possible
    await asyncio.gather(
        *[
            execute_command(
                command=command,
                output=os.path.join(scans_folder, command.get("bin")),
                input=host_file,
                ports=",".join(ports),
            )
            for command in commands
        ]
    )


async def screenshot(commands: List, output: str):
    """
    Perform service port scanning via nmap to discover open hosts. Save the
    discovered open ports to a file.

        Parameters:
            commands (List) - List of the command objects to be run
            output (str) - path to output directory
            ports (Set) - Set of discovered ports to scan

        Returns:
            target_urls (str) - Path to the target URLs file
    """
    scans_folder = os.path.join(output, "scans")

    # Retrieve the list of hosts to scan
    # We are scanning the hosts and not just the IPs because the output
    # from this tool will be feed into other HTTP scanning tools.
    # Due to virtual hosting, the direct IP address may not be as useful as
    # the full URL with the hostname.
    with open(os.path.join(scans_folder, "ports", "nmap.xml")) as f:
        nmap_file = f.read()

    # The default config will only run masscan, but in case someone wants
    # to add extra port scanners here, its possible
    await asyncio.gather(
        *[
            execute_command(
                command=command,
                output=os.path.join(scans_folder, command.get("bin")),
                input=nmap_file,
            )
            for command in commands
        ]
    )

    # return the path to the target urls file
    return os.path.join(scans_folder, "aquatone", "aquatone_urls.txt")


async def http_scan(commands: List, output: str, input: str, config: str):
    """
    Perform service port scanning via nmap to discover open hosts. Save the
    discovered open ports to a file.

        Parameters:
            commands (List) - List of the command objects to be run
            output (str) - path to output directory
            input (str) - input string of URLs
            config (str) - path to config directory

        Returns:
            N/A
    """
    scans_folder = os.path.join(output, "scans")

    with open(input) as f:
        targets = f.read()

    # The default config will only run masscan, but in case someone wants
    # to add extra port scanners here, its possible
    await asyncio.gather(
        *[
            execute_command(
                command=command,
                output=os.path.join(scans_folder, command.get("bin")),
                input=targets,
                config=config
            )
            for command in commands
        ]
    )

    # return the path to the target urls file
    return os.path.join(scans_folder, "aquatone", "aquatone_urls.txt")


async def main():
    # Get the user input from the command parser
    args = cli()

    # Parse the configuration file
    commands = parse_config(args.config)

    # Make sure the requried bins are installed
    if check_bins(commands=commands) == False:
        print(f"[!] Not all nessecary binaries were found on the $PATH, exiting...")
        exit(-1)

    # Create the output directory (if it doesn't already exist)
    # And warn the user if the output directory does already exist
    if os.path.exists(args.output):
        w(
            f"Output directory ({args.output}) already exists. "
            f"This script will overwrite the contents of the {args.output} directory"
        )
    else:
        os.makedirs(args.output)

    # # Subdomain Enumeration
    # if args.skip_dns == False:
    #     print("[+] Running Subdomain Enumeration")
    #     await dns_enum(
    #         commands=commands.get("dns_enum"),
    #         domains=get_domains(args),
    #         output=args.output,
    #         config=args.config,
    #     )

    #     # Determine live subdomains
    #     print("[+] Running DNS Validation")
    #     await dns_validation(
    #         commands=commands.get("dns_valid"),
    #         output=args.output,
    #         config=args.config,
    #     )

    # # Assemble the target list
    # print("[+] Collecting targets")
    # collect_targets(
    #     ip_in_file=args.ips,
    #     ip_ex_file=args.exclude,
    #     output=args.output,
    #     skip_dns=args.skip_dns,
    # )

    # # Port scan the targets in two phases
    # # The first phase uses masscan to quickly discover all open ports
    # print("[+] Running Inital Port Scan")
    # ports = await port_scan(
    #     commands=commands.get("port_scan"),
    #     output=args.output,
    # )

    # # The second phase uses nmap to validate masscan and discover services
    # print("[+] Runnning Validation Port Scan")
    # await validation_scan(
    #     commands=commands.get("validation_scan"), output=args.output, ports=ports
    # )

    # # Perform HTTP screenshotting on discovered hosts (this has the
    # # added benefit of also producing an easy to use URL list)
    # print("[+] Runnning HTTP Screenshotting")
    # target_urls = await screenshot(
    #     commands=commands.get("screenshot"), output=args.output
    # )
    target_urls = os.path.join(args.output, "scans", "aquatone", "aquatone_urls.txt")

    # Now that all services have been enumerated, begin performing HTTP scanning
    print("[+] Runnning HTTP Scanning")
    await http_scan(
        commands=commands.get("http_scan"),
        output=args.output,
        input=target_urls,
        config=args.config,
    )


if __name__ == "__main__":
    asyncio.run(main())
