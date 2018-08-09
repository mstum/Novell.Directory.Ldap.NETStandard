using System.IO;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public abstract class KerberosAsn1Object : Asn1Object
    {
        protected KerberosAsn1Object(Asn1Identifier id) : base(id)
        {
        }
    }
}
