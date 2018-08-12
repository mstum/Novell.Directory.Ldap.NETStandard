using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class KerberosDecoder
    {
        public KerberosAsn1Object Decode(Asn1Tagged input, IAsn1Decoder decoder)
        {
            var id = input.GetIdentifier();
            if (id.IsSameTagAs(AsRequest.Id))
            {
                return new AsRequest(input, decoder);
            }

            return null;
        }
    }
}
