
# Super simple Linode firewall rule updater
I assume others are like me and have a dynamic IP at home but would always like your firewall rules to allow full access from this IP.

This simple tool does that. 

## How to configure
- Add your Linode Personal Access Token with Firewalls access to app.config
- Update app.config with a comma separated array of DNS names you want to resolve to IP and have added to your firewalls. 

Run the tool!

Hope it helps :D


** Check out [DuckDNS](https://www.duckdns.org/) for a great DDNS provider. (Then add your DuckDNS domain to this tool!)
