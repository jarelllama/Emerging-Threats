# emerging-threats-pihole

**This is a fork that maintains an updated Adblock Plus version of [tweedge/emerging-threats-pihole](https://github.com/tweedge/emerging-threats-pihole).**

Dead domains and redundant rules are now removed during the build, along with other enhancements like whitelist filtering and improved domain extraction.

The updated blocklist can be found here (updated at 00:00 AM UTC daily): **[malicious.txt](https://raw.githubusercontent.com/jarelllama/emerging-threats-pihole/main/malicious.txt)**

Sourced rulesets:
* emerging-exploit_kit.rules
* emerging-malware.rules
* emerging-mobile_malware.rules
* emerging-phishing.rules

The phishing ruleset is also integrated into **[Jarelllamas's Scam Blocklist](https://github.com/jarelllama/Scam-Blocklist)**.

View the full list of fullsets here:
* [rulesets](https://rules.emergingthreats.net/)
* [categories](https://community.emergingthreats.net/t/current-suricata-5-and-suricata-6-rule-categories/94)

The rest of the README is kept mostly the same.

---

This repository extracts and categorizes malicious/unwanted domains from the Emerging Threats ruleset for people using PiHole to block easily.

[malicious.txt](https://raw.githubusercontent.com/jarelllama/emerging-threats-pihole/main/malicious.txt) - Blocks malware and phishing

This allows home users to increase their defenses against new threats and provides a window into some technology used to secure large or sensitive networks. At launch (2022-12-31), the `malicious.txt` host file blocked >2,100 unique domains (including domains used by major malware strains, APTs, and more) and *~83% of these domains were not found in popular PiHole anti-malware/anti-phishing/etc. lists.*

## FAQ

**Where is this data coming from / what is Emerging Threats?** [Emerging Threats](https://doc.emergingthreats.net/bin/view/Main/EmergingFAQ) is a part of Proofpoint, Inc. They maintain the Emerging Threats ruleset, which is a free (BSD-licensed) list of rules contributed to by their team and security researchers around the world. Using Emerging Threats and other rulesets, you can detect and prevent malicious network activity using an IPS (Intrusion Prevention System) such as [Snort](https://www.snort.org/) or [Suricata](https://suricata.io/).

**Whoah, an IPS sounds cool. Is this how corporations protect themselves?** Using an IPS is often part of how corporations protect themselves, yes! An IPS allows you to monitor traffic flowing through a network, dissecting that traffic in near-real-time to look for threats based on rules that security engineers and researchers write. Emerging Threats (owned by Proofpoint) is one of the major vendors of those rules (alongside Cisco Talos and others) but you can also write your own IPS rules with a bit of background knowledge! If you have some networking/IT experience already, you may be ready to write these (with a bit of effort) if you follow [Motasem Hamdan's guide](https://www.youtube.com/watch?v=pvPdOO2VcwM) through the Snort IDS TryHackMe challenge.

**How effective is this compared to running an IPS with Emerging Threats rulesets?** Not effective. IPS are more sophisticated, much harder to evade, and support *many* more traffic types than just DNS (this repo's contents are distilled from under 1/10th of Emerging Threats rules). However, most home users won't run an IPS, and this at least can help them extract some value from Emerging Threats' and security researchers' work. It's not comprehensive protection, because it's not *designed* to be comprehensive protection. Essentially: if you have PiHole running already, here's something cool that you can get some value out of & learn more about security from - if you don't have PiHole running already, I wouldn't jump to implement one just to use these rules.

**...So will this protect me from malware/phishing/etc?** Some, yes. It's one source of threat intelligence among many that you can use - but finding and curating many sources of threat intelligence is difficult. To increase the malware-fighting capabilities of your PiHole, I would *strongly* recommend using a public filtering DNS resolver which will have many more sources of threat intelligence integrated already. However, please remember that is *part* of your cybersecurity stack, there is no all-in-one complete solution and there is no machine that can protect you from *all* malware/phishing/etc.

### Notice of Non-Affiliation

This project is not affiliated, associated, authorized, endorsed by, or in any way officially connected with Emerging Threats, Proofpoint, or any of its subsidiaries or its affiliates. The official Emerging Threats rulesets can be found at [https://rules.emergingthreats.net/](https://rules.emergingthreats.net/).

The names Emerging Threats and Proofpoint as well as related names, marks, emblems, and images are registered trademarks of their respective owners.
