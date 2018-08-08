using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// KerberosTime ::= GeneralizedTime -- with no fractional seconds
    /// </summary>
    public class KerberosTime : Asn1GeneralizedTime
    {
    }
}
