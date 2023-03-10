
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