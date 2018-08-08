using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class KerberosDeserializer : DerDeserializer
    {
        protected override Asn1Object DecodeApplicationTag(Stream inRenamed, Asn1Length length, Asn1Identifier asn1Id, DecodingContext context)
        {
            return base.DecodeApplicationTag(inRenamed, length, asn1Id, context);
        }
    }
}
