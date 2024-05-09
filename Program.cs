using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;

namespace LinodeFirewallRulesUpdater
{
    public class Program
    {
        private static readonly HttpClient client = new HttpClient();
        private static readonly string linodePersonalAccessToken = ConfigurationManager.AppSettings["LinodePersonalAccessToken"];
        private static readonly string[] fullAccessDomains = ConfigurationManager.AppSettings["FullAccessDomains"].Split(',');
        private static readonly string duckDNSToken = ConfigurationManager.AppSettings["DuckDNSToken"] ?? "";
        private static readonly string duckDNSDomains = ConfigurationManager.AppSettings["DuckDNSDomains"] ?? "";
        private static readonly string LocalSystemID = ConfigurationManager.AppSettings["LocalSystemID"] ?? "";

        static async Task Main(string[] args)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", linodePersonalAccessToken);

            // Resolve all IP addresses at the beginning
            var domainConfigs = await GetDomainInfos(fullAccessDomains);


            // Get public IP address from ipify API
            Console.WriteLine("Fetching public IP Address...");
            string publicIP = await client.GetStringAsync("https://api.ipify.org");
            Console.WriteLine($"Public IP Address: {publicIP}");

            // Add the local system to the domainConfigs (Mainly for the laptop cases)
            if (!string.IsNullOrEmpty(LocalSystemID))
            {
                domainConfigs.Add(new DomainInfo
                {
                    DomainName = LocalSystemID,
                    IP = publicIP,
                    FirewallMask = "*",
                    Ports = "*"
                });
                Console.WriteLine($"Added local system '{LocalSystemID}' to the domain configs...");

            }

            if (!string.IsNullOrEmpty(duckDNSToken) && !string.IsNullOrEmpty(duckDNSDomains))
            {
                await UpdateDuckDNS(duckDNSToken, duckDNSDomains, publicIP);
            }

            // Using the FirewallUpdater class
            var firewallUpdater = new FirewallUpdater(client, linodePersonalAccessToken, domainConfigs);
            await firewallUpdater.UpdateFirewalls();

            // Using the DatabaseUpdater class
            var databaseUpdater = new DatabaseUpdater(client, domainConfigs, linodePersonalAccessToken);
            await databaseUpdater.UpdateDatabases();

            if (args.Contains("-s")) Console.ReadLine();
        }



        private static async Task UpdateDuckDNS(string token, string domains, string publicIP)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(domains)) return;

            try
            {
                // Update DuckDNS with the fetched IP address
                Console.WriteLine("Updating DuckDNS with this IP Address...");
                var response = await client.GetAsync($"https://www.duckdns.org/update?domains={domains}&token={token}&ip={publicIP}");
                var responseBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Response from DuckDNS: {responseBody}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred: {ex.Message}");
            }
        }

        public static void PrintUpdateResponse(string updateResponse, string firewallName)
        {
            Console.WriteLine("");
            Console.WriteLine($"----- Update Response For Firewall {firewallName} -----");
            Console.WriteLine(updateResponse);
            Console.WriteLine("");


        }
        public static async Task<List<DomainInfo>> GetDomainInfos(string[] domainConfigs)
        {
            var domainInfos = new List<DomainInfo>();

            foreach (var config in domainConfigs)
            {
                string[] parts = config.Split('|');
                if (parts.Length >= 3)
                {
                    string domainName = parts[0];
                    string ports = parts[1];
                    string firewallMask = parts[2];

                    string ip = await ResolveIP(domainName);

                    domainInfos.Add(new DomainInfo
                    {
                        DomainName = domainName,
                        IP = ip,
                        Ports = ports,
                        FirewallMask = firewallMask
                    });

                    Console.WriteLine($"- Host: {domainName}");
                    Console.WriteLine($"\t Ports:{ports}");
                    Console.WriteLine($"\t Mask:{firewallMask}");
                    Console.WriteLine($"\t IP:{ip}");
                    Console.WriteLine($"\t");
                }
            }


            return domainInfos;
        }


        static string GetIP(string domainName)
        {
            try
            {
                var addresses = Dns.GetHostAddresses(domainName);
                if (addresses.Length > 0)
                {
                    return addresses[0].ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error resolving {domainName}: {ex.Message}");
            }
            return null;
        }
        private static async Task<string> ResolveIP(string domainName)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domainName);
                if (addresses.Length > 0)
                {
                    return addresses[0].ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error resolving {domainName}: {ex.Message}");
            }
            return null;
        }

        public class DomainInfo
        {
            public string DomainName { get; set; }
            public string IP { get; set; }
            public string Ports { get; set; }
            public string FirewallMask { get; set; }
        }
    }
}
