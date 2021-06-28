#!/usr/bin/env python3
import argparse
import os
from typing import Dict, List, Set
import shutil
import asyncio
import json
from itertools import chain
import ipaddress
from libnmap.parser import NmapParser
from urllib.parse import urlparse
import socket


def v(line: str):
    if verbose:
        print(f"[+] {line}")


def w(line: str):
    print(f"[!] WARNING - {line}")


def i(line: str):
    print(f"[*] {line}")


def cli():
    """
    Parse the input commands and return the arguments Namespace

        Returns:
            args (argparse.Namespace): Namespace containing the arguments from the command line
    """
    parser = argparse.ArgumentParser(
        description="Automate the recon, enumeration, and vulnerability scanning phases of external pen-tests and \
            bug bounties."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (display each command)",
        default=False,
    )
    parser.add_argument(
        "-d",
        "--domains",
        action="store",
        type=str,
        help="A comma-separated list of target domains (e.g. -d 'example.com,info.com')",
        default=None,
    )
    parser.add_argument(
        "-dL",
        "--domain-file",
        action="store",
        type=str,
        help="Input file containing a newline separated list of target domains",
        default=None,
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store",
        type=str,
        help="Input file containing IP addresses, CIDR ranges, or hostnames to INCLUDE in scanning/enumeration",
        default=None,
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="store",
        type=str,
        help="Input file containing IP addresses, CIDR ranges, or hostnames to EXCLUDE from scanning/enumeration. \
            This has precedence over the --include flag.",
        default=None,
    )
    parser.add_argument(
        "-p",
        "--phase",
        action="store",
        type=str,
        help="Execute only a single 'phase' of the arves.json config file. (Must be used with --target-file)",
        default=None,
    )
    parser.add_argument(
        "-tf",
        "--target-file",
        action="store",
        type=str,
        help="The path to the target file to use for performing scanning of a specific phase (To be used with \
            the --phase flag)",
        default=None,
    )
    parser.add_argument(
        "--workers",
        action="store",
        type=int,
        help="The maximum amount of commands to run at a time",
        default=10,
    )
    parser.add_argument(
        "-c",
        "--config",
        action="store",
        type=str,
        help="Path to the 'config' folder containing both the 'arves.json' file as well as individual \
            tool configuration files",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        type=str,
        help="Path to the output directory",
        required=True,
    )

    args = parser.parse_args()

    if args.phase and not args.target_file:
        w("If the --phase flag is provided then a --target-file must also be provided.")
        exit(-1)
    if args.target_file and not args.phase:
        w("A --target-file was provided but no --phase was provided.")
        exit(-1)

    # TODO do more error checking here, such as checking that all provided files exist

    # Seting the verbose and dry run flags
    global verbose
    global dry_run
    verbose = args.verbose

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
        w(f"Error opening config file: {config}/arves.json")
        exit(-1)

    return commands


def clean_target(target: str):
    """
    This function cleans the target of path characters and the pesky http[s]

        Parameters:
            target (str) - the target (domain, URL, etc.) to clean

        Returns:
            (str) - The cleaned version of the target
    """
    # Parse the URL
    parsed = urlparse(target)
    # If an incomplete URL was provided (such as with domains)
    # Then complete the URL so that urllib can parse out the netloc
    if parsed.scheme == "":
        parsed = urlparse(f"http://{target}")
    return parsed.netloc


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
                w(
                    f"Missing binary: {cmd.get('bin')} ({cmd.get('loc', 'No location provided')})"
                )
                passed = False

    return passed


def read_target_file(target_file: str, resolve_hostnames: bool):
    """
    Read in a target file and return the contents of the raw file and
    the resolved IP addresses

        Parameters:
            target (str) - path to the input target file
            resolve_hostnames (bool) - Whether to include the IP addresses
                of resolved hostnames in the returned IP list

        Returns:
            hostnames (Set), ips (Set) - Tuple containing a set of all the hostnames
                included in the file as well as a set of the IP addresses. If
                resovle_hostnames is true, the IP address set will also contain the
                resolved IP addresses of hosts discovered in the file
    """
    cidrs = set()
    ips = set()
    hostnames = set()

    with open(target_file) as f:
        contents = set(f.read().splitlines())

    for target in contents:
        # This try / except will catch if the provided input is a hostname or IP address/network
        try:
            cidrs.add(ipaddress.ip_network(target, strict=False))
        except ValueError:
            # This except is hit when a hostname is provided to the ip_network function
            hostnames.add(target)
            if resolve_hostnames:
                # Resolve the hostname then pass each IP address to the ip_network function
                # to be added to the cidrs pool
                _, _, resolved_ips = socket.gethostbyname_ex(target)
                for ip in resolved_ips:
                    cidrs.add(ipaddress.ip_network(ip, strict=False))

    # get all the individual ip addresses from the CIDRs
    for cidr in cidrs:
        for ip in cidr:
            ips.add(str(ip))

    return hostnames, ips


def collect_domains(output: str, input_domains: str, domain_file: str):
    """
    Retrieve the input domains from the CLI and input files, then write them to a file in the
    output folder.

        Parameters:
            output (str) - path to output directory
            input_domains (str) - List of input domains provided via CLI
            domain_file (str) - path to file containing input domains

        Returns:
            domains_file (str): file containing domains to run tools against
    """
    domains = set()

    # Grab domains provided via CLI
    if input_domains:
        domains.update(input_domains.split(","))
    # Grab domains provided in a file
    if domain_file:
        try:
            with open(domain_file) as f:
                file_contents = f.read()
                domains.update(file_contents.splitlines())
        except FileNotFoundError as err:
            w(f"Could not open input domain list: {domain_file}")
            exit(-1)

    # Write the domains to a file
    domain_file = os.path.join(output, "targets", "domains.txt")
    with open(domain_file, "w") as f:
        f.write("\n".join(domains))

    # Return the path to the domain file
    return domain_file


def collect_subdomains(output: str):
    """
    Collect the output of the 'dns_enum' phase into one file

        Parameters:
            output (str) - path to output directory

        Returns:
            N/A
    """
    # Gather all of the enumerated subdomains into a file
    subs = set()
    subs_folder = os.path.join(output, "dns_enum")
    for file in os.listdir(subs_folder):
        with open(os.path.join(subs_folder, file)) as f:
            # Add all of the discovered subdomains to the list
            subs.update(f.read().splitlines())

    # write the results to a file
    sub_file = os.path.join(output, "targets", "subs.txt")
    with open(sub_file, "w") as f:
        f.write("\n".join(subs))

    return sub_file


def collect_ips(output: str, include_file: str, exclude_file: str):
    """
    Collect all of the IP addresses from the provided IP list, as well as from
    the subdomain enumeration, and write them to a file. This will write 2 files,
    one with just IP addresses, and one with IP addresses and subdomains (for virtual
    hosting). This function will also use the exclude file to remove hosts from the
    final target files.

        Parameters:
            output (str) - path to output directory
            ip_in_file (List) - path to the file contining IP addresses to include
            ip_ex_file (str) - path to the file containing IP addresses to exclude

        Returns:
            (str) - path to the final ip file
    """
    ips = set()
    hosts = set()

    # Read in the two target files (if the were provided)
    # If no target files were provided just use an empty set
    if include_file:
        in_hostnames, in_ips = read_target_file(
            target_file=include_file, resolve_hostnames=True
        )
    else:
        in_hostnames = in_ips = set()
    if exclude_file:
        ex_hostnames, ex_ips = read_target_file(
            target_file=exclude_file, resolve_hostnames=False
        )
    else:
        ex_hostnames = ex_ips = set()

    # read in the DNS validation file
    dns_file = os.path.join(output, "dns_valid", "dnsx")

    with open(dns_file) as f:
        # newline delimited JSON
        for line in f:
            record = json.loads(line)
            # Only proceed if there was an A record (IP address) for the host
            if record.get("a", False):

                # Add the host to the list of hostnames
                hosts.add(record.get("host"))

                # Get the A records (IP addresses) for the host and
                # add the IP to the list if it is not in the exclusion list
                ips.update(record.get("a"))

    # Add the "include" targets and remove the "exclude" targets
    ips.update(in_ips)
    ips = ips - ex_ips
    hosts.update(in_hostnames)
    hosts = hosts - ex_hostnames

    # Write the resulting sets to their output files
    targets_folder = os.path.join(output, "targets")
    ip_file = os.path.join(targets_folder, "ips.txt")
    host_file = os.path.join(targets_folder, "hosts.txt")
    with open(ip_file, "w") as f:
        f.write("\n".join(ips))

    with open(host_file, "w") as f:
        f.write("\n".join(hosts))
        f.write("\n")
        f.write("\n".join(ips))

    return ip_file


def collect_ports(output: str):
    """
    Collect the open ports from the masscan run, as well as return the full hosts
    list to run against nmap.

        Parameters:
            output (str) - The output directory

        Returns:
            (str), (str) - A tuple containing the ports to be scanned (in nmap format)
                as well as the path to the host list file
    """
    ports = set()
    targets_folder = os.path.join(output, "targets")
    with open(os.path.join(output, "port_scan", "masscan")) as f:
        # Read in the masscan output and add all ports listed as "open"
        # to the discovered_ports set
        discovered = json.load(f)
        for host in discovered:
            for port in host.get("ports"):
                if port.get("status") == "open":
                    ports.add(str(port.get("port")))

    # Format the ports in nmap style
    ports = ",".join(ports)

    # Write the discovered ports to a file
    with open(os.path.join(targets_folder, "ports.txt"), "w") as f:
        f.write(ports)

    return (ports, os.path.join(targets_folder, "hosts.txt"))


def collect_webservers(output: str):
    """
    Collect all of the HTTP web servers from the nmap XML output and write
    them to a webservers file

        Parameters:
            output (str) - Path to the output folder

        Returns:
            (str) - Path to the webservers file
    """
    webservers = set()
    nmap_file = os.path.join(output, "validation_scan", "nmap.xml")
    parser = NmapParser.parse_fromfile(nmap_file)
    for host in parser.hosts:
        for service in host.services:
            if service.state == "open":
                if "https" in service.service:
                    webservers.add(f"https://{host.address}:{service.port}")
                    for hostname in host.hostnames:
                        webservers.add(f"https://{hostname}:{service.port}")
                elif "http" in service.service:
                    webservers.add(f"http://{host.address}:{service.port}")
                    for hostname in host.hostnames:
                        webservers.add(f"http://{hostname}:{service.port}")

    webserver_file = os.path.join(output, "targets", "webservers.txt")
    with open(webserver_file, "w") as f:
        f.write("\n".join(webservers))

    return webserver_file


class Phase:
    """
    This class represents the a 'phase' of the recon scanning process. This is initialized with all
    of the variables that the phase needs to run. The run() method is used to actually execute the
    phase of the scan.
    """

    def __init__(
        self, name: str, commands: List, target_file: str, output: str, workers: int
    ) -> None:
        self.name = name
        self.commands = commands
        self.target_file = target_file
        self.targets = self._read_targets(target_file)
        self.output = output
        self.log_dir = os.path.join(output, "log")
        self.sem = asyncio.Semaphore(workers)

        # Make the output and log directories
        os.makedirs(self.output, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    @staticmethod
    def _read_targets(target_file):
        with open(target_file) as f:
            return f.read().splitlines()

    async def _run_cmd(self, cmd, **kwargs):
        """
        This funciton acts as a wrapper around subprocess.run to run commands. Dynamic input such as
        {config} may be passed in via the kwargs variable.

            Parameters:
                cmd (Dict) - The command dict to execute
                kwargs (Dict) - All of the dynamic values to populate the `cmd` with

            Returns:
                None
        """
        async with self.sem:
            # Build the command
            shell_cmd = f"{cmd.get('bin')} {cmd.get('args')}"
            for key, val in kwargs.items():
                shell_cmd = shell_cmd.replace(f"{{{key}}}", val)

            # Get the STDIN input (if it was provided)
            stdin = cmd.get("stdin", None)

            # If the command requires input from stdin
            if stdin:
                # This pipe will tell the create_subprocess_shell method to
                # expect data from STDIN
                input_pipe = asyncio.subprocess.PIPE
                for key, val in kwargs.items():
                    stdin = stdin.replace(f"{{{key}}}", val)
                # convert STDIN into bytes
                stdin = bytes(stdin, encoding="utf8")
            else:
                # If the command doesn't require STDIN then send None
                # so that create_subprocess_shell doesn't expect anything
                input_pipe = None

            i(f"Issued: {shell_cmd}")

            # Write the command to the log file
            with open(os.path.join(self.log_dir, "_commands.log"), "a") as f:
                f.write(f"{shell_cmd}\n")

            # Run the command
            proc = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdin=input_pipe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Send whatever STDIN there is to the process, then wait
            # for the command to exit and return stdout and stderr
            stdout, stderr = await proc.communicate(input=stdin)
            v(f"Command {shell_cmd!r} exited with code: {proc.returncode}")

            # Get the name of the file from the output
            filename = kwargs.get("output").split("/")[-1]

            # Write the command output to a write to a log file
            with open(os.path.join(self.log_dir, filename), "w") as f:
                if stderr:
                    f.write(f"[stderr]\n{stderr.decode()}")
                if stdout:
                    f.write(f"[stdout]\n{stdout.decode()}\n")

    async def run(self, **kwargs):
        """
        This method will handle the execution of this phase of the process.

            Parameters:
                kwargs (Dict) - Any dynamically defined variables from the config
                    file, such as {ports}
        """
        # Make the output directory
        output = os.path.join(self.output, self.name)
        os.makedirs(output, exist_ok=True)

        # generate the command list
        cmd_list = []
        for cmd in self.commands:
            # determine target type for each command (single vs multi)
            if cmd.get("target_type", None) == "single":
                # Single target commands require that each target be passed individually
                for target in self.targets:
                    # output file is {output}/{phase}/{target}.{cmd}
                    cleaned_output_filename = os.path.join(
                        output, f"{clean_target(target)}.{cmd.get('bin')}"
                    )
                    cmd_list.append(
                        self._run_cmd(
                            cmd,
                            output=cleaned_output_filename,
                            target=target,
                            **kwargs,
                        )
                    )
            else:
                # Multi target commands can accept the targets either via stdin
                # or as an input file
                # output file is {output}/{phase}/{cmd}
                output_filename = os.path.join(output, cmd.get("bin"))
                cmd_list.append(
                    self._run_cmd(
                        cmd,
                        output=output_filename,
                        target="\n".join(self.targets),
                        target_file=self.target_file,
                        **kwargs,
                    )
                )

        # Execute the commands
        i(f"Executing phase: {self.name}")
        await asyncio.gather(*cmd_list)


async def main():
    # Get the user input from the command parser
    args = cli()

    # Parse the configuration file
    commands = parse_config(args.config)

    # This only works on Unix, gotta figure out a windows alternative
    # If this script is calling nmap, then it must be run with sudo
    if (args.phase == None or args.phase == "validation_scan") and os.geteuid() != 0:
        w("This script must be run with sudo, exiting...")
        exit(-1)

    # Make sure the requried bins are installed
    if check_bins(commands=commands) == False:
        w(f"Not all nessecary binaries were found on the $PATH, exiting...")
        exit(-1)

    # Create the output directory (if it doesn't already exist)
    # And warn the user if the output directory does already exist
    if os.path.exists(args.output):
        w(f'Output directory ({args.output}) already exists. '
            f'This script will overwrite the contents of the "{args.output}" directory.')

    # Create the targets directory that will hold the target files for each phase
    os.makedirs(os.path.join(args.output, "targets"), exist_ok=True)

    if args.phase:
        await Phase(
            args.phase,
            commands.get(args.phase),
            target_file=args.target_file,
            output=args.output,
            workers=args.workers,
        ).run(config=args.config)
    else:
        # Create the initial "domains" target file
        target_file = collect_domains(
            output=args.output,
            input_domains=args.domains,
            domain_file=args.domain_file,
        )

        # Run the DNS enumeration (subdomain enuymeration) phase
        await Phase(
            "dns_enum",
            commands.get("dns_enum"),
            target_file=target_file,
            output=args.output,
            workers=args.workers,
        ).run(config=args.config)

        # Collect the subdomains from the DNS enumeration
        target_file = collect_subdomains(
            output=args.output,
        )

        # Run the DNS validation phase
        await Phase(
            "dns_valid",
            commands.get("dns_valid"),
            target_file=target_file,
            output=args.output,
            workers=args.workers,
        ).run(config=args.config)

        # Collect the active hosts from the DNS enumeration
        target_file = collect_ips(
            output=args.output, include_file=args.include, exclude_file=args.exclude
        )

        # Run the initial port scan phase
        await Phase(
            "port_scan",
            commands.get("port_scan"),
            target_file=target_file,
            output=args.output,
            workers=args.workers,
        ).run(config=args.config)

        # Collect the active hosts from the DNS enumeration
        ports, target_file = collect_ports(output=args.output)

        # Run the service validation phase
        await Phase(
            "validation_scan",
            commands.get("validation_scan"),
            target_file=target_file,
            output=args.output,
            workers=args.workers,
        ).run(config=args.config, ports=ports)

        # Collect the web servers from the nmap results
        target_file = collect_webservers(output=args.output)

        # Run the final HTTP scanning phase
        await Phase(
            "http_scan",
            commands.get("http_scan"),
            target_file=target_file,
            output=args.output,
            workers=args.workers,
        ).run(config=args.config)

    i("Completed Scanning!")


if __name__ == "__main__":
    asyncio.run(main())
