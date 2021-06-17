# arves
*Its like Arbys, but with a V*

ARVES is (yet another) Automated Recon, Vulnerability, and Enumeration Scanner. Inspired by the fantastic [AutoRecon](https://github.com/Tib3rius/AutoRecon) tool by Tib3rius, this tool is designed to automate as much of the inital phases of a external network penetration test (or bug bounty assessment) as possible. There are three main differences between ARVES and many of the other popular All-in-one recon tools/scripts.

1. ARVES is written in Python and is designed to be platform-independant
2. ARVES makes heavy use of the `asyncio` module to execute mulitple commands at the same "phase" of the tool simultaneously... AKA concurrency go brrrr
3. ARVES was designed to be extensible, so if you want to drop in another tool (or remove one) then it should be as easy as possible to do so.

Now, I can already hear what your thinking, "Isn't this just a shell script with an extra coat of paint?" The answer is yes, that is exactly what this is; however, that coat of paint is doing a lot of work to make automating the recon and scanning phase of an engagement as easy as possible.

Other features:
- Accepts lists of IP addresses to include/exclude from scanning (accepts CIDR format!)

## Set-up
- Install the required binaries
    - ADD A LIST OF REQUIRED BINARIES FOR DEFAULT CONFIG
- Enter in API keys for `amass` and `subfinder`

## Usage

## Extending ARVES