#!/usr/bin/env python3
import argparse
import os
import subprocess
from typing import Dict, List
import shutil
import asyncio
import json
from itertools import chain


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
        help="Input file containing IP addresses",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="store",
        type=str,
        help="Input file containing IP addresses or hostnames to exclude",
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


async def execute_command(command: Dict, **kwargs):
    """
    This funciton acts as a wrapper around subprocess.run to run commands. Dynamic input such as
    {domain} or {config} may be passed in via the kwargs variable.

        Parameters:
            command (str) - The command to execute
            kwargs (Dict) - All of the dynamic values to populate the `command` with

        Returns:
            None
    """
    # Build the command
    cmd = f"{command.get('bin')} {command.get('args')}"
    for k, v in kwargs.items():
        cmd = cmd.replace(f"{{{k}}}", v)

    if dry_run or verbose:
        print(f"[*] Issued: {cmd}")

    if dry_run == False:
        # Run the command
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

    stdout, stderr = await proc.communicate()
    if verbose:
        print(f"[*] Command {cmd!r} exited with code: {proc.returncode}")
    # if stdout:
    #     print(f"[stdout]\n{stdout.decode()}")
    # if stderr:
    #     print(f"[stderr]\n{stderr.decode()}")


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

    for cmd in commands:
        # shutil.which is basically just the platform independant `which` command
        # this line just checks to see if the binary name is in the path
        if shutil.which(cmd.get("bin")) == None:
            print(f"[!] WARNING - Missing binary: {cmd.get('bin')} ({cmd.get('loc')})")
            passed = False

    return passed


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
    if not os.path.exists(output):
        os.makedirs(os.path.join(output, "subs"))
    await asyncio.gather(
        *[
            execute_command(
                command=command, domain=domain, output=output, config=config
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
    with open(os.path.join(subs_folder, "all.txt"), "w") as f:
        f.write('\n'.join(subs))

    await asyncio.gather(
        *[
            execute_command(command=command, output=output, config=config)
            for command in commands
        ]
    )


def get_domain_list(args: argparse.ArgumentParser):
    """
    Retrieve the input domains from the CLI as a list.

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


def get_command_list(commands: List, phase: str):
    """
    Get all the commands from the list with a certain phase (eg. dns_enum)

        Parameters:
            commands (List) - The full list of commands to run
            phase (str) - The specific phase to filter for

        Returns:
            r (List) - The filtered list of commands
    """
    r = []
    for cmd in commands:
        if cmd.get("phase") == phase:
            r.append(cmd)
    return r


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
        print(
            f"[!] WARNING - Output directory ({args.output}) already exists\n"
            f"[!] This script will overwrite the contents of the {args.output} directory"
        )
    else:
        os.makedirs(args.output)

    # Subdomain Enumeration
    if args.skip_dns == False:
        print("[+] Running Subdomain Enumeration")
        await dns_enum(
            commands=get_command_list(commands=commands, phase="dns_enum"),
            domains=get_domain_list(args),
            output=args.output,
            config=args.config,
        )

        # Determine live subdomains
        print("[+] Running DNS Validation")
        await dns_validation(
            commands=get_command_list(commands=commands, phase="dns_valid"),
            output=args.output,
            config=args.config,
        )

    # Port scan the targets
    # TODO

    # Use httpx to determine which exposed ports are web servers

    # Use nuclei to perform vulnerability scanning

    # Use aquatone to perform HTTP screenshotting

    # Use gau to retrieve archieved URLs from the target web servers


if __name__ == "__main__":
    asyncio.run(main())
