#!/bin/bash

# Retrieves domains from DNS request query rules in the Emerging Threats
# Suricata rulesets.

readonly URL='https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.zip'

# https://community.emergingthreats.net/t/current-suricata-5-and-suricata-6-rule-categories/94
# Rulesets with no domains extracted are not included
readonly -a RULESETS=(
    emerging-exploit_kit
    emerging-malware
    emerging-mobile_malware
    emerging-phishing
)

# Function 'get_domains' extracts domains from the ruleset.
# Input:
#   $1: file containing the ruleset
#   $2: file to output the domains to
get_domains() {
    # Ignore rules with specific payload keywords. See here:
    # https://docs.suricata.io/en/suricata-6.0.0/rules/payload-keywords.html
    # Note 'endswith' is accepted as those rules tend to be wildcard matches of
    # root domains.
    # Ignore IP addresses
    # Remove leading periods ('endswith' rules)
    # Convert to lower case
    # Remove whitelisted domains
    mawk '!/^#/ && /dns[\.|_]query/ && !/content:!/ && !/startswith/ &&
        !/offset/ && !/distance/ && !/within/ && !/pcre/' "$1" \
        | grep -oE 'content:"[[:alnum:].-]+\.[[:alnum:]-]*[a-z]{2,}[[:alnum:]-]*' \
        | sed 's/content:"\.\?//' \
        | mawk '{print tolower($0)}' \
        | grep -vxFf data/whitelist.txt \
        | sort -u -o "$2"
}

build() {
    # The compressed rules directory is smaller than the individual uncompressed
    # rules
    curl -sSL --retry 2 --retry-all-errors "$URL" -o rules.zip
    unzip -q rules.zip
    rm rules.zip

    # Collate rules
    for RULE in "${RULESETS[@]}"; do
        cat "rules/${RULE}.rules" >> rules.tmp
    done

    get_domains rules.tmp raw.tmp

    # Compile list. See the list of transformations here:
    # https://github.com/AdguardTeam/HostlistCompiler
    printf "\n"
    hostlist-compiler -i raw.tmp -o compiled.tmp

    # Remove dead domains
    printf "\n"
    dead-domains-linter -a -i compiled.tmp

    # Get entries, ignoring comments
    grep -F '||' compiled.tmp > temp
    mv temp compiled.tmp

    # Deploy blocklist
    append_header
    cat compiled.tmp >> malicious.txt

    # Build separate phishing list for Jarelllama's Scam Blocklist
    get_domains rules/emerging-phishing.rules data/phishing.txt
}

append_header() {
    cat << EOF > malicious.txt
[Adblock Plus]
! Title: (Unofficial) Emerging Threats Blocklist
! Description: Fork of https://github.com/tweedge/emerging-threats-pihole
! Homepage: https://github.com/jarelllama/Emerging-Threats
! License: https://github.com/tweedge/emerging-threats-pihole/blob/main/LICENSE
! Version: $(date -u +"%m.%d.%H%M%S.%Y")
! Expires: 1 day
! Last modified: $(date -u)
! Syntax: Adblock Plus
! Number of entries: $(wc -l < compiled.tmp)
!
! WHAT:
! This blocklist is intended for use in PiHole or similar DNS-level filters. It's generated automatically from part of
! the current Emerging Threats Open ruleset, which is threat intelligence and signatures provided by the Emerging
! Threats research team and contributed to by security researchers around the world.
!
! TECHNICAL NOTICE:
! While this list provides some DNS filtering coverage, the provided filter is NOT comparable to protection offered by
! Emerging Threats' signatures when implemented in an IPS such as Snort or Suricata. This is because IDS can perform
! advanced matching functionality and make bypassing the filter much more difficult. Some key examples:
!  * If a particular strain of malware queries the public DNS resolver 8.8.8.8 directly, this could bypass PiHole on
!    your network.
!  * Emerging Threats includes much more than blocking specific domains, such as detecting and blocking DNS
!    exfiltration attacks based on different parts of the DNS payload that PiHole would simply ignore.
!  * And of course, Emerging Threats covers 100s of different protocols with their signatures, extending FAR beyond
!    DNS! This allows researchers to write very specific rules to detect and block threats at the network level,
!    making it harder for malware or threats to hide from security staff by just changing what domain they use.
! After all, a domain can cost only a few dollars - but re-engineering your custom malware implant could take days!
!
! WHY:
! First, of course I hope this can help you keep some malware/unwanted traffic/etc. off your network!
! Second, for folks interested in cybersecurity (personal or career) that you get a glimpse of some new technology
! that you may not have heard of before and something fun to learn about - or maybe contribute to in the future! :)
!
! SOMETHING IS WRONG:
! Sorry! This is NOT an official Emerging Threats project and while I'll do my best to ensure correctness,
! this hosts file is not provided with any guarantees.
! Please report false positives or other issues here: https://github.com/jarelllam/emerging-threats-pihole/issues
!
! LICENSE:
! Emerging Threats community rules, from which this hosts file is derived, are BSD-licensed:
!  Copyright (c) 2003-2024, Emerging Threats
!  All rights reserved.
!
!  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
!  following conditions are met:
!
!  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
!    disclaimer.
!  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
!    following disclaimer in the documentation and/or other materials provided with the distribution.
!  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
!    from this software without specific prior written permission.
!
!  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES,
!  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
!  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
!  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
!  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
!  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
!  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
!
EOF
}

cleanup() {
    rm -r rules
    find . -maxdepth 1 -type f -name "*.tmp" -delete
}

# Entry point

trap cleanup EXIT

# Install AdGuard's Dead Domains Linter
if ! command -v dead-domains-linter &> /dev/null; then
    npm install -g @adguard/dead-domains-linter > /dev/null
fi

# Install AdGuard's Hostlist Compiler
if ! command -v hostlist-compiler &> /dev/null; then
    npm install -g @adguard/hostlist-compiler > /dev/null
fi

build
