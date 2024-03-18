using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace LinodeFirewallRulesUpdater
{
    public class FirewallUpdater
    {
        private readonly HttpClient _client;
        private readonly string _linodePersonalAccessToken;
        private readonly List<Program.DomainInfo> _domainInfos;

        public FirewallUpdater(HttpClient client, string linodePersonalAccessToken, List<Program.DomainInfo> domainInfos)
        {
            _client = client;
            _linodePersonalAccessToken = linodePersonalAccessToken;
            _domainInfos = domainInfos;
            _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", linodePersonalAccessToken);
        }

        public async Task UpdateFirewalls()
        {
            string apiUrl = "https://api.linode.com/v4/networking/firewalls";
            HttpResponseMessage response = await _client.GetAsync(apiUrl);
            string responseBody = await response.Content.ReadAsStringAsync();
            var firewalls = JsonSerializer.Deserialize<Firewalls>(responseBody);

            foreach (var firewall in firewalls.data)
            {
                foreach (var domainInfo in _domainInfos)
                {
                    if (!firewall.label.Contains(domainInfo.FirewallMask) && domainInfo.FirewallMask != "*")
                    {
                        continue;
                    }

                    bool updateNeeded = false;
                    var rules = firewall.rules;

                    foreach (var protocol in new[] { "TCP", "UDP" })
                    {
                        var matchingRule = GetMatchingRule(rules.inbound, domainInfo.DomainName, protocol, domainInfo.Ports);
                        string resolvedIPFormatted = $"{domainInfo.IP}/32";

                        if (matchingRule == null)
                        {
                            var newRule = CreateNewRule(domainInfo.DomainName, resolvedIPFormatted, protocol, domainInfo.Ports);
                            AddNewRule(rules, newRule);
                            updateNeeded = true;
                        }
                        else if (!matchingRule.addresses.ipv4.Contains(resolvedIPFormatted))
                        {
                            UpdateRule(matchingRule, resolvedIPFormatted, domainInfo.Ports);
                            updateNeeded = true;
                        }
                    }

                    if (updateNeeded)
                    {
                        var updateRulesJson = JsonSerializer.Serialize(rules, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
                        var content = new StringContent(updateRulesJson, System.Text.Encoding.UTF8, "application/json");
                        var updateResponse = await _client.PutAsync($"{apiUrl}/{firewall.id}/rules", content);
                        var updateResponseBody = await updateResponse.Content.ReadAsStringAsync();
                        Program.PrintUpdateResponse(updateResponseBody, firewall.label);
                    }
                    else
                    {
                        Console.WriteLine($"No updates needed for firewall '{firewall.label}' / {domainInfo.DomainName} ");
                    }
                }
            }
        }

        static Inbound GetMatchingRule(Inbound[] rules, string domain, string protocol, string ports)
        {
            string ruleName = "";
            if (ports == "*") ruleName = $"{domain}-{protocol}";
            else ruleName = $"{domain}-{protocol}-{ports}";

            return rules.FirstOrDefault(rule => rule.label == ruleName);
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

        public class Firewalls
        {
            public Datum[] data { get; set; }
            public int page { get; set; }
            public int pages { get; set; }
            public int results { get; set; }
        }

        public class Datum
        {
            public int id { get; set; }
            public string label { get; set; }
            public DateTime created { get; set; }
            public DateTime updated { get; set; }
            public string status { get; set; }
            public Rules rules { get; set; }
            public object[] tags { get; set; }
        }

        public class Rules
        {
            public Inbound[] inbound { get; set; }
            public string inbound_policy { get; set; }
            public object[] outbound { get; set; }
            public string outbound_policy { get; set; }
        }

        public class Inbound
        {
            public string ports { get; set; }
            public string protocol { get; set; }
            public Addresses addresses { get; set; }
            public string action { get; set; }
            public string label { get; set; }
        }

        public class Addresses
        {
            public string[] ipv4 { get; set; }
            public string[] ipv6 { get; set; }
        }
    }
}
