using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
namespace LinodeFirewallRulesUpdater
{
    public class DatabaseUpdater
    {
        private readonly HttpClient _client;
        private readonly List<Program.DomainInfo> _domainInfos;
        private readonly string _apiUrlBase;

        public DatabaseUpdater(HttpClient client, List<Program.DomainInfo> domainInfos, string linodePersonalAccessToken)
        {
            _client = client;
            _domainInfos = domainInfos;
            _apiUrlBase = "https://api.linode.com/v4/databases";
            _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", linodePersonalAccessToken);
        }

        public async Task UpdateDatabases()
        {
            HttpResponseMessage listDatabasesResponse = await _client.GetAsync(_apiUrlBase + "/mysql/instances");
            string listDatabasesResponseBody = await listDatabasesResponse.Content.ReadAsStringAsync();
            var databases = JsonSerializer.Deserialize<DatabaseList>(listDatabasesResponseBody);

            foreach (var database in databases.data)
            {
                Console.WriteLine($"Processing whitelist for database {database.label}...");
                HashSet<string> whitelistIps = new HashSet<string>(database.allow_list);

                foreach (var domainInfo in _domainInfos)
                {
                    string ipFormatted = $"{domainInfo.IP}/32";
                    if (!whitelistIps.Contains(ipFormatted))
                    {
                        whitelistIps.Add(ipFormatted);
                    }
                }

                if (whitelistIps.Count > database.allow_list.Length)
                {
                    string updateUrl = $"{_apiUrlBase}/mysql/instances/{database.id}";
                    database.allow_list = whitelistIps.ToArray();
                    var updateContent = new StringContent(JsonSerializer.Serialize(database), System.Text.Encoding.UTF8, "application/json");

                    HttpResponseMessage updateResponse = await _client.PutAsync(updateUrl, updateContent);
                    if (updateResponse.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Whitelist updated successfully for {database.label}.");
                    }
                    else
                    {
                        Console.WriteLine($"Error updating whitelist for {database.label}: {updateResponse.StatusCode}");
                    }
                }
                else
                {
                    Console.WriteLine($"No changes needed for the whitelist of {database.label}.");
                }
            }
        }

        public class DatabaseList
        {
            public Database[] data { get; set; }
        }

        public class Database
        {
            public int id { get; set; }
            public string label { get; set; }
            public string[] allow_list { get; set; }

        }
    }

}
