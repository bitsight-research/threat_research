# Amadey IOCs and detection rules

- `amadey_iocs.csv` is the human-readable IOC feed.
- `amadey_iocs_misp.json` is a MISP event-import file.
- `amadey_iocs_stix2.json` is a STIX 2.1 bundle.
- `amadey.yara` is a portable YARA rule with no proprietary runtime dependencies.
- `amadey.rules` contains the Amadey Suricata rule.

The machine-readable IOC feeds use standard URL and IP notation so security tooling can ingest them; this normalizes the defanged values in the research notes and does not perform an active lookup.

More IoCs at [ThreatFox](https://threatfox.abuse.ch/user/9563/), [MalwareBazaar](https://bazaar.abuse.ch/user/12060/), and [URLhaus](https://urlhaus.abuse.ch/user/7705/).
