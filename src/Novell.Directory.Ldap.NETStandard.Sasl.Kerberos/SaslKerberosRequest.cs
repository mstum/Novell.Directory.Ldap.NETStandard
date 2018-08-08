using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl
{
    public class SaslKerberosRequest : SaslRequest
    {
        public SaslKerberosRequest()
            : base(SaslConstants.Mechanism.GssApi)
        {
        }
    }
}
