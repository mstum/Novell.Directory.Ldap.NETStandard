using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Novell.Directory.Ldap.Sasl
{
    public class KerberosSaslClientFactory : ISaslClientFactory
    {
        public IReadOnlyList<string> SupportedMechanisms { get; }
            = new ReadOnlyCollection<string>(new string[] { SaslConstants.Mechanism.GssApi });

        public ISaslClient CreateClient(string mechanism, string authorizationId, string protocol, string serverName, byte[] credentials, Hashtable saslBindProperties)
        {
            switch (mechanism?.ToUpperInvariant())
            {
                case SaslConstants.Mechanism.GssApi:
                    return new KerberosSaslClient();
                default:
                    return null;
            }
        }
    }
}
