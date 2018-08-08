using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl
{
    public class KerberosSaslClient : ISaslClient
    {
        public string MechanismName => SaslConstants.Mechanism.GssApi;

        public bool HasInitialResponse => false;

        public bool IsComplete { get; private set; }

        public void Dispose()
        {
        }

        public byte[] EvaluateChallenge(byte[] challenge)
        {
            throw new NotImplementedException();
        }
    }
}
