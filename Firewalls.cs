using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LinodeFirewallRulesUpdater
{
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
