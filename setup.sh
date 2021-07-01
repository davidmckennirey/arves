check_go_bin() {
    if ! loc=$(command -v $1); then
        echo "Could not find $1 on the \$PATH, installing with go get..."
        GO111MODULE=on go get -v $2
    else
        echo "Found $1 on the \$PATH: $loc"
    fi
}

echo "Running ARVES installation script..."
$passed = 1

if ! loc=$(command -v go)
then
    echo "Could not find go on the \$PATH.\nPlease install golang [apt install golang | brew install golang]."
    $passed = 0
else
    echo "Found go on the \$PATH: $loc"

    # check if the go/bin folder is already in the path
    echo "Checking if go bin folder in \$PATH..."
    if [[ "$PATH" == *"$HOME/go/bin"* ]]; then
        echo "go bin folder already in \$PATH"
    else
        echo "Adding $HOME/go/bin to path..."
        export PATH=$PATH:$HOME/go/bin
        echo "Added $HOME/go/bin to the \$PATH: PATH=$PATH"
    fi

    echo "Checking for golang binaries..."
    check_go_bin "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    check_go_bin "puredns" "github.com/d3mondev/puredns/v2"
    check_go_bin "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
    check_go_bin "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    check_go_bin "gau" "github.com/lc/gau"
fi



if ! loc=$(command -v aquatone)
then
    echo "Could not find aquatone on the \$PATH."
    echo "Aquatone has build issues so you have to download the correct version for your OS and put it in your \$PATH. (https://github.com/michenriksen/aquatone/releases/)"
    $passed = 0
else
    echo "Found aquatone on the \$PATH: $loc"
fi

echo "Checking for non-golang binaries..."

if ! loc=$(command -v massdns)
then
    echo "Could not find massdns on the \$PATH."
    echo "Download and build massdns from its github repo. (https://github.com/blechschmidt/massdns)"
    $passed = 0
else
    echo "Found massdns on the \$PATH: $loc"
fi

if ! loc=$(command -v masscan)
then
    echo "Could not find masscan on the \$PATH."
    echo "Download and build masscan from its github repo. (https://github.com/robertdavidgraham/masscan)"
    $passed = 0
else
    echo "Found masscan on the \$PATH: $loc"
fi

if ! loc=$(command -v nmap)
then
    echo "Could not find nmap on the \$PATH."
    echo "There are like a million ways to install nmap, so I will let you figure that one out."
    $passed = 0
else
    echo "Found nmap on the \$PATH: $loc"
fi

echo "Updating nuclei templates..."
nuclei -ut -silent
echo "Templates updated!"

echo "Checking for resolvers.txt file in config directory..."
if test -f "./config/resolvers.txt"; then
    echo "resolvers.txt file found!"
else
    echo "No resolvers.txt file found in config directory"
    echo "Generate a resolvers.txt file using the dnsvalidator project (https://github.com/vortexau/dnsvalidator) and save it to the config directory."
    $passed = 0
fi

echo "Checking for all.txt file in config directory..."
if test -f "./config/all.txt"; then
    echo "all.txt file found!"
else
    echo "No all.txt file found in config directory"
    echo "Add a subdomain wordlist in your config directory called 'all.txt', I recommend the dns-Jhaddix.txt wordlist from SecLists (https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt)"
    $passed = 0
fi

if $passed; then
    echo "Completed, all checks passed!"
    echo "All requried binaires and files for the default config are present; however, there are still a few more steps:"
    echo "1. Configure the subfinder and amass config files to your liking. I recommend adding in all of your API keys so you can get much better results."
    echo "2. If you are an OhMyZsh user, then unalias gau (https://github.com/lc/gau/issues/8#issuecomment-622323249)"
    echo "If you have completed these steps, then you are ready to rock!"
else
    echo "Not all prerequirements were met."
    echo "Please address the issues listed above, and then rerun this script."
fi