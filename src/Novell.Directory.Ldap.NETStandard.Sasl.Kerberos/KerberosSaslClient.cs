using Novell.Directory.Ldap.Sasl.Clients;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl
{
    public class KerberosSaslClient : BaseSaslClient
    {
        public static KerberosSaslClient CreateClient(string authorizationId, string serverName, byte[] credentials, Hashtable props)
        {
            return new KerberosSaslClient(authorizationId, serverName, credentials, props);
        }

        public override DebugId DebugId { get; } = DebugId.ForType<KerberosSaslClient>();

        public override string MechanismName => SaslConstants.Mechanism.GssApi;

        public override bool HasInitialResponse => throw new NotImplementedException();

        public override bool IsComplete => throw new NotImplementedException();

        public override byte[] EvaluateChallenge(byte[] challenge)
        {
            throw new NotImplementedException();
        }

        private KerberosSaslClient(string authorizationId, string serverName, byte[] credentials, Hashtable props)
            : base(serverName, props)
        {

        }
    }
}
