
# Super simple Linode firewall rule updater
I assume others are like me and have a dynamic IP at home but would always like your firewall rules to allow full access from this IP.

This simple tool does that. 

## How to configure
- Add your Linode Personal Access Token with Firewalls access to app.config
- Update app.config with a comma separated array of DNS names you want to resolve to IP and have added to your firewalls. 

Run the tool!

Hope it helps :D


## DDNS Setup
### Added simple [DuckDNS](https://www.duckdns.org/) support to the tool.
Add your token and DuckDNS domains to the app.config and it will update those domains to the public IP of the system running.

** The tokens in the app.config in this repo are an example and definitely not me accidentally committing my actual tokens and having to recreate them afterwards... 

## Configuration
The FullAccessDomains configuration is a comma separated list of domains you want to resolve to the public IP of the system running the tool.
The format is `domainname.com|PortsToUse|FirewallFilter`
Where:
- `domainname.com` is the domain name you want to resolve to the public IP of the system running the tool.
- `PortsToUse` is * for all ports or 1,23,4,55 or 1-25 for a range of ports.
- `FirewallFilter` is a string filter if you only want to apply the rule to a firewall that contains this string. * for all firewalls.

## Known Issues
- Linode limits a rule label to 32 characters, currently using the domain name in the label. If you have a domain name longer than 32 characters it will fail.
