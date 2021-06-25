# ARVES
*Its like Arbys, but with a V*

- [ARVES](#arves)
  - [Set-up](#set-up)
    - [Requried](#requried)
    - [Optional (But Recommended)](#optional-but-recommended)
  - [Usage](#usage)
    - [A Note About Nuclei](#a-note-about-nuclei)
    - [Include / Exclude Files](#include--exclude-files)
    - [Examples](#examples)
  - [Extending ARVES](#extending-arves)
    - [Keywords](#keywords)
    - [Variables](#variables)
    - [Phases](#phases)
    - [Examples](#examples-1)
  - [Credit](#credit)

ARVES stands for Automated Recon, Vulnerability, and Enumeration Scanner. This tool is designed to automate as much of the inital phases of a external network penetration test (or bug bounty assessment) as possible. ARVES was designed with the following principles in mind, which also happen to differentiate it from the many other popular All-in-one recon tools/scripts.

1. ARVES is written in Python and is designed to be platform-independant
2. ARVES uses the `asyncio` module to execute mulitple commands/tools at each "phase" simultaneously... AKA concurrency go brrrr
3. ARVES was designed to be extensible, so if you want to drop in another tool (or remove one) then ARVES can support that, regardless of how your tool accepts input.

Now, I can already hear what your thinking, "Isn't this just a shell script with an extra coat of paint?" The answer is yes, that is exactly what this is; however, that coat of paint is doing a lot of work to make automating the recon and scanning phase of an engagement as easy as possible.

Other features:
- Accepts lists of IP addresses and hostnames to include/exclude from scanning (including CIDR format)
- Allows for individual "phase" selection if you don't want to perform the entire enumeration and scanning process
- Third thing?

## Set-up
ARVES requires Python 3.7 or later, since it uses `asyncio` features that were not available before Python 3.7. The following command can be used to install ARVES lone dependancy.

```bash
python3 -m pip install -r requirements.txt
```

### Requried
- Install the required binaries
    - If you are on a *nix OS you can run the `setup.sh` script included in this repo to help with that.
- For OhMyZsh users, [unalias `gau`](https://github.com/lc/gau/issues/8#issuecomment-622323249)
- Update your nuclei templates: `nuclei [-ut | --update-templates]`
- Copy in a subdomain bruteforcing wordlist into your "config" folder. I recommend [Jason Haddix's DNS list](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt).
- Get a list of DNS resolvers. I recommend using the [dnsvalidatior](https://github.com/vortexau/dnsvalidator) project to do this.

### Optional (But Recommended)
- Add the `$HOME/go/bin` folder to your `$PATH` so that golang tools installed via `go get` are automagically in your `$PATH`. The setup script does this.
  - `echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc`  *(change `.zshrc` to `.bashrc` if you are a `bash` user)*
- Enter in API keys for `amass` and `subfinder` config files in the config directory

## Usage
You have to run ARVES with `sudo` because it runs `nmap` with the `-sS` flag! I would suggest reading the code first before you run random scripts off the internet with `sudo`, or alternatively you can get rid of the `-sS` flag from the `nmap` command in the `arves.json` file.

ARVES requires both an "output" destination folder and a "config" folder to be provided, as well as a target selection. The `--config` folder must contain a `arves.json` file, which ARVES uses to determine which commands will be run. The target selection can either be a single domain (`-d`) or a file containing a list of domains (`-dL`) if you want to run the full scan, or an individual `--phase` along with a `--target-file`.

### A Note About Nuclei
`nuclei` will always read the configuration file at `~/.config/nuclei/config.yaml` first, so if you have specified a custom configuration than that will be read from before `{config}/nuclei-config.yaml`. If you want to use a different configuration setting in your ARVES scan then what is in your default, then comment out the configuration settings you want to override in the `~/.config/nuclei/config.yaml`.

### Include / Exclude Files
Exclude takes precedence over include. If a IP or hostname is in both, then it will **NOT** be included in scanning.

You can provide ARVES with include and/or exclude files that contain IP addresses, CIDR ranges, or hostnames to be included or excluded from scanning. When a hostname is provided to ARVES via a file in the `--include` flag, the tool will attempt to resolve the hostname, and it will include the IP address of the resolved hostname in further scans. However, when a hostname is provided to ARVES via a file in the `--exclude` flag, it will not attempt to resolve the hostname and it will not remove the IP address of the host from the scan list. 

This was intentional because I was considering virtual hosting, where multiple applications that could be in scope would share the same underlying IP addresses with other applications that were out of scope. With this current configuration, ARVES will include the underlying IP address of the host, but it will not scan the specific application that was listed as out of scope.

### Examples
TL; DR Give me the examples.

Running a full scan against a single domain
```bash
sudo python3 arves.py -c config -o output -d hackerone.com
```

Running a full scan against a list of domains with a list of hostnames and IP addresses to include and exclude.
```bash
sudo python3 arves.py -c config -o output -i include_list.txt -e exclude_list.txt -dL domain_list.txt
```

Running just the HTTP scanning phase with a target file
```bash
sudo python3 arves.py -c config -o output -p http_scan -tf webservers.txt
```

## Extending ARVES
ARVES was designed to be as extensible and customizable as possible; however, I also tried to make the default config as useful as possible right out of the box. The default config tries to strike a balance between practicality and noiseiness. As an example, it *doesn't* run `nikto` on every discovered webserver, because thats just a lot of traffic (I included that example config below). 

### Keywords
ARVES was designed to provide tools with input from as many sources as possible. Some tools only accept input via STDIN (looking at you `aquatone`), while other tools can only accept single targets at a time (like `nikto`). These configurations were both considered, and have been accounted for using the keywords described in the table below. These keywords can also be combined.

| Keyword     | Description                                                                                                                                                                                                                                                                                                      |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| target_type | If this keyword is included with the value "single" then ARVES will execute each command once per target in the target file. This is useful for tools like `nikto` which can only be run on one target at a time. This will also change the output filename to be `[output_folder]/[phase]/[target].[bin_name]`. |
| stdin       | This keyword can be used to pass input via STDIN. This is useful for tools like `aquatone` which require the input via STDIN and won't accept file based input.                                                                                                                                                  |

### Variables
The `arves.json` file defines a few variables that it uses in the commands in runs as placeholders for data that will be filled out while the script is running. The following table defines these variables.

| Variable Name | Description                                                                                                                                                                                                                                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| {target}      | This variable holds the contents of the `{target_file}`  . If the  `target_type`  is  `single`  then this will contain each individual line of the target file. Otherwise, this will contain the entire contents of the target file, which you might want to use if passing the input via the  `stdin`  keyword. |
| {target_file} | This variable holds the name of the file containing the targets for each phase.                                                                                                                                                                                                                                  |
| {output}      | This variable holds the output file for each command. If the  `target_type`  is  `single`  then the output format will be  `[output_folder]/[phase]/[target].[bin_name]` , otherwise, the output format is  `[output_folder]/[phase]/[bin_name]` .                                                               |
| {config}      | This variable holds the path to the "config" directory specified via the  `--config`  flag.                                                                                                                                                                                                                      |
| {ports}       | This is a special variable specifically for the  `validation_scan`  phase of the tool. This will be replaced with the ports that  `masscan`  discovered to be open during the  `port_scan`  phase.                                                                                                               |

### Phases
The `dns_valid`, `port_scan`, and `validation_scan` all require their current tools (`dnsx`, `masscan`, and `nmap` respectively) to be present in order for the script to work properly. You can include other tools if you like, but you cannot remove these tools.

The other phases, `dns_enum` and `http_scan` can be completely customized however you like. Hate my tool choices? Well thats kinda harsh but you can choose your own instead.

Also important to note, the tools will be run in the order that they are listed in the `arves.json` file. So if you want a certain tool to run earlier, such as a screenshotting tool, then push it to the top of the list.

### Examples
TL;DR Here are some examples of other tools that could be included in the `arves.json` file. The `loc` keyword is just there to help the user if they don't have the tool installed to go get it, but it is not nessecary.

Run `nikto` on every discovered webserver. This would be included in the `http_scan` phase (WARNING - NOISY AS HECK).
```json
{
    "bin": "nikto",
    "loc": "https://github.com/sullo/nikto",
    "args": "-h {target} -output {output} -Format txt",
    "target_type": "single"
}
```

Run `gau` on individual targets instead of against all domains at once
```json
{
    "bin": "gau",
    "loc": "https://github.com/lc/gau",
    "args": "-b jpg,png,gif -o {output}",
    "stdin": "{target}",
    "target_type": "single"
}
```

Run `hakrawler` (golang-based HTTP spider) on every webserver.
```json
{
    "bin": "hakrawler",
    "loc": "https://github.com/hakluke/hakrawler",
    "args": "-url {target}  -outdir {output} -plain -linkfinder -depth 2",
    "target_type": "single"
}
```

Run `ffuf` on all discovered webservers (WARNING this will send a TON of traffic - I wouldn't recommend it). Also, if you want to append a file extension to the output file, you can do so here, as shown with the `.csv` at the end of the output file.
```json
{
    "bin": "ffuf",
    "loc": "https://github.com/ffuf/ffuf",
    "args": "-u {target}/FUZZ -of csv -o {output}.csv -w /usr/local/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "target_type": "single"
}
```

Use `shuffledns` instead of `puredns` to perform subdomain bruteforcing. This would be included in the `dns_enum` phase. This assumes that there is a subdomain wordlist called "all.txt" and a resolver list called "resolvers.txt" in the config directory.
```json
{
    "bin": "shuffledns",
    "loc": "https://github.com/projectdiscovery/shuffledns",
    "args": "-d {target} -w {config}/all.txt -o {output} -r {config}/resolvers.txt",
    "stdin": "target"
}
```

## Credit

This tool was inspired by the the fantastic [AutoRecon](https://github.com/Tib3rius/AutoRecon) and [Interlace](https://github.com/codingo/Interlace) tools. Both of these tools are great for their specific use case, and are worth looking into if you too classify yourself as an automation junkey.