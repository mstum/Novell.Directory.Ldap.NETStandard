using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl
{
    public class KerberosSaslClient : ISaslClient
    {
        public string MechanismName => SaslConstants.Mechanism.GssApi;

        public bool HasInitialResponse => throw new NotImplementedException();

        public bool IsComplete => throw new NotImplementedException();

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public byte[] EvaluateChallenge(byte[] challenge)
        {
            throw new NotImplementedException();
        }
    }
}
