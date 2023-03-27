using System.Configuration;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace LinodeFirewallRulesUpdater;
class Program
{
    static async Task Main(string[] args)
    {
        string linodePersonalAccessToken = ConfigurationManager.AppSettings["LinodePersonalAccessToken"];
        string[] fullAccessDomains = ConfigurationManager.AppSettings["FullAccessDomains"].Split(',');

        string duckDNSToken = ConfigurationManager.AppSettings["DuckDNSToken"] ?? "";
        string duckDNSDomains = ConfigurationManager.AppSettings["DuckDNSDomains"] ?? "";

        string apiUrl = "https://api.linode.com/v4/networking/firewalls";

        // Create an HttpClient instance and set the authorization header
        using (HttpClient client = new HttpClient())
        {
            //UpdateDuckDNS
            if (!String.IsNullOrEmpty(duckDNSToken) && !String.IsNullOrEmpty(duckDNSDomains))
            {
                Console.WriteLine("Updating DuckDNS with this IP Address...");
                HttpResponseMessage duckDNSResponse = await client.GetAsync($"https://www.duckdns.org/update?domains={duckDNSDomains}&token={duckDNSToken}&ip=");
                string duckDNSResponseBody = await duckDNSResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Response... {duckDNSResponseBody}");
            }

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", linodePersonalAccessToken);

            // Send a GET request to the API endpoint and read the response
            HttpResponseMessage response = await client.GetAsync(apiUrl);
            string responseBody = await response.Content.ReadAsStringAsync();
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull};

            var json = JsonSerializer.Deserialize<Firewalls>(responseBody, options);


            foreach (var domainConfig in fullAccessDomains)
            {
                string[] domainConfigs = domainConfig.Split("|");
                string domainName = domainConfigs[0]; // example.com
                string domainPorts = domainConfigs[1]; // 1-50 or 1,2,3,4,5 or 42
                string firewallMask = domainConfigs[2]; // FirewallNameFilter to apply it to.  If *, it will apply to all firewalls

                string resolvedIPFormatted = $"{GetIP(domainName)}/32";

                //Skip this domain if it didn't resolve as expected.
                if (String.IsNullOrEmpty(resolvedIPFormatted))
                {
                    Console.WriteLine($"Could not resolve domain {domainName}... Have to skip it");
                    continue;
                }

                foreach (var firewall in json.data)
                {
                    //Skip this firewall if it doesn't match the mask
                    if (!firewall.label.Contains(firewallMask) && firewallMask != "*")
                    {
                        Console.WriteLine($"Firewall {firewall.label} doesn't match mask {firewallMask}... skipping");
                        continue;
                    }

                    bool updateNeeded = false;
                    var rules = firewall.rules;

                    //Check for the TCP Rules
                    var matchingRuleTCP = GetMatchingRule(rules.inbound, domainName, "TCP", domainPorts);
                    if (matchingRuleTCP == null)
                    {
                        var newRule = CreateNewRule(domainName, resolvedIPFormatted, "TCP", domainPorts);
                        AddNewRule(rules, newRule);
                        Console.WriteLine($"{domainName}-TCP {resolvedIPFormatted} MISSING for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else if (!matchingRuleTCP.addresses.ipv4.Contains(resolvedIPFormatted))
                    {
                        UpdateRule(matchingRuleTCP, resolvedIPFormatted, domainPorts);
                        Console.WriteLine($"{domainName}-TCP {resolvedIPFormatted} IP MISMATCH for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else
                    {
                        Console.WriteLine($"{domainName}-TCP {resolvedIPFormatted} rule exists for firewall {firewall.label} skipping...");
                    }

                    //Check for the UDP Rules
                    var matchingRuleUDP = GetMatchingRule(rules.inbound, domainName, "UDP", domainPorts);
                    if (matchingRuleUDP == null)
                    {
                        var newRule = CreateNewRule(domainName, resolvedIPFormatted, "UDP", domainPorts);
                        AddNewRule(rules, newRule);
                        Console.WriteLine($"{domainName}-UDP {resolvedIPFormatted} MISSING for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else if (!matchingRuleUDP.addresses.ipv4.Contains(resolvedIPFormatted))
                    {
                        UpdateRule(matchingRuleUDP, resolvedIPFormatted, domainPorts);
                        Console.WriteLine($"{domainName}-UDP {resolvedIPFormatted} IP MISMATCH for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else
                    {
                        Console.WriteLine($"{domainName}-UDP {resolvedIPFormatted} rule exists for firewall {firewall.label} skipping...");
                    }

                    //Update the firewalls if needed!
                    if (updateNeeded)
                    {
                        var updateRulesJson = JsonSerializer.Serialize(rules, options);
                        var content = new StringContent(updateRulesJson, System.Text.Encoding.UTF8, "application/json");
                        var updateResponse = await client.PutAsync($"{apiUrl}/{firewall.id}/rules", content);
                        var updateResponseBody = await updateResponse.Content.ReadAsStringAsync();
                        PrintUpdateResponse(updateResponseBody, firewall.label);
                    }
                }
            }

        }

        if(args.Contains("-s")) Console.Read();
    }

    public static void PrintUpdateResponse(string updateResponse, string firewallName)
    {
        Console.WriteLine("");
        Console.WriteLine($"----- Update Response For Firewall {firewallName} -----");
        Console.WriteLine(updateResponse);
        Console.WriteLine("");


    }

    static Inbound GetMatchingRule(Inbound[] rules, string domain, string protocol, string ports)
    {
        string ruleName = "";
        if (ports == "*") ruleName = $"{domain}-{protocol}";
        else ruleName = $"{domain}-{protocol}-{ports}";

        return rules.FirstOrDefault(rule => rule.label == ruleName);
    }

    private static void AddNewRule(Rules rules, Inbound newRule)
    {
        // Check if the inbound rules are empty
        if (rules.inbound == null)
        {
            // Create a new array with the new rule
            rules.inbound = new[] { newRule };
            return;
        }

        // Check if the new rule already exists
        var existingRule = rules.inbound.FirstOrDefault(r => r.label == newRule.label);
        if (existingRule != null)
        {
            // Update the existing rule
            existingRule.ports = newRule.ports;
            existingRule.protocol = newRule.protocol;
            existingRule.action = newRule.action;
            existingRule.addresses = newRule.addresses;
        }
        else
        {
            // Add the new rule to the existing array
            rules.inbound = rules.inbound.Concat(new[] { newRule }).ToArray();
        }
    }

    private static void UpdateRule(Inbound matchingRule, string ipAddress, string ports)
    {
        if (ports == "*") ports = "1-65535";
        matchingRule.ports = ports;
        matchingRule.addresses = new Addresses
        {
            ipv4 = new[] { ipAddress },
            ipv6 = null
        };
    }

    private static Inbound CreateNewRule(string domain, string ip, string protocol, string ports)
    {
        string label = $"{domain}-{protocol}-{ports}";
        if (ports == "*")
        {
            ports = "1-65535";
            label = $"{domain}-{protocol}";
        }
        return new Inbound
        {
            ports = ports,
            protocol = protocol,
            addresses = new Addresses
            {
                ipv4 = new[] { $"{ip}" },
                ipv6 = null
            },
            action = "ACCEPT",
            label = label
        };
    }

    static string GetIP(string domainName)
    {

        // Resolve the domain name to an IP address
        IPAddress[] addresses = Dns.GetHostAddresses(domainName);
        if (addresses.Length == 0)
        {
            Console.WriteLine($"Could not resolve {domainName}");
            return "";
        }
        else
        {
            Console.WriteLine($"{domainName} is reachable at {addresses[0]}");
            return addresses[0].ToString();
        }

    }
}