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

        string apiUrl = "https://api.linode.com/v4/networking/firewalls";

        // Create an HttpClient instance and set the authorization header
        using (HttpClient client = new HttpClient())
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", linodePersonalAccessToken);

            // Send a GET request to the API endpoint and read the response
            HttpResponseMessage response = await client.GetAsync(apiUrl);
            string responseBody = await response.Content.ReadAsStringAsync();
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull};

            var json = JsonSerializer.Deserialize<Firewalls>(responseBody, options);


            foreach (var domain in fullAccessDomains)
            {
                string resolvedIPFormatted = $"{GetIP(domain)}/32";

                //Skip this domain if it didn't resolve as expected.
                if (String.IsNullOrEmpty(resolvedIPFormatted))
                {
                    Console.WriteLine($"Could not resolve domain {domain}... Have to skip it");
                    continue;
                }

                foreach (var firewall in json.data)
                {
                    bool updateNeeded = false;
                    var rules = firewall.rules;

                    //Check for the TCP Rules
                    var matchingRuleTCP = GetMatchingRule(rules.inbound, domain, "TCP");
                    if (matchingRuleTCP == null)
                    {
                        var newRule = CreateNewRule(domain, resolvedIPFormatted, "TCP");
                        AddNewRule(rules, newRule);
                        Console.WriteLine($"{domain}-TCP {resolvedIPFormatted} MISSING for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else if (!matchingRuleTCP.addresses.ipv4.Contains(resolvedIPFormatted))
                    {
                        UpdateRule(matchingRuleTCP, resolvedIPFormatted);
                        Console.WriteLine($"{domain}-TCP {resolvedIPFormatted} IP MISMATCH for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else
                    {
                        Console.WriteLine($"{domain}-TCP {resolvedIPFormatted} rule exists for firewall {firewall.label} skipping...");
                    }

                    //Check for the UDP Rules
                    var matchingRuleUDP = GetMatchingRule(rules.inbound, domain, "UDP");
                    if (matchingRuleUDP == null)
                    {
                        var newRule = CreateNewRule(domain, resolvedIPFormatted, "UDP");
                        AddNewRule(rules, newRule);
                        Console.WriteLine($"{domain}-UDP {resolvedIPFormatted} MISSING for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else if (!matchingRuleUDP.addresses.ipv4.Contains(resolvedIPFormatted))
                    {
                        UpdateRule(matchingRuleUDP, resolvedIPFormatted);
                        Console.WriteLine($"{domain}-UDP {resolvedIPFormatted} IP MISMATCH for firewall {firewall.label} updating...");

                        updateNeeded = true;
                    }
                    else
                    {
                        Console.WriteLine($"{domain}-UDP {resolvedIPFormatted} rule exists for firewall {firewall.label} skipping...");
                    }

                    //Update the firewalls if needed!
                    if (updateNeeded)
                    {
                        var updateRulesJson = JsonSerializer.Serialize(rules, options);
                        var content = new StringContent(updateRulesJson, System.Text.Encoding.UTF8, "application/json");
                        var updateResponse = await client.PutAsync($"https://api.linode.com/v4/networking/firewalls/{firewall.id}/rules", content);
                        var updateResponseBody = await updateResponse.Content.ReadAsStringAsync();
                        PrintUpdateResponse(updateResponseBody, firewall.label);
                    }
                }
            }

        }


        Console.Read();
    }

    public static void PrintUpdateResponse(string updateResponse, string firewallName)
    {
        Console.WriteLine("");
        Console.WriteLine($"----- Update Response For Firewall {firewallName} -----");
        Console.WriteLine(updateResponse);
        Console.WriteLine("");


    }

    static Inbound GetMatchingRule(Inbound[] rules, string domain, string protocol)
    {
        return rules.FirstOrDefault(rule => rule.label == $"{domain}-{protocol}");
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

    private static void UpdateRule(Inbound matchingRule, string ipAddress)
    {
        matchingRule.ports = "1-65535";
        matchingRule.addresses = new Addresses
        {
            ipv4 = new[] { ipAddress },
            ipv6 = null
        };
    }

    private static Inbound CreateNewRule(string domain, string ip, string protocol)
    {
        return new Inbound
        {
            ports = "1-65535",
            protocol = protocol,
            addresses = new Addresses
            {
                ipv4 = new[] { $"{ip}" },
                ipv6 = null
            },
            action = "ACCEPT",
            label = $"{domain}-{protocol}"
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