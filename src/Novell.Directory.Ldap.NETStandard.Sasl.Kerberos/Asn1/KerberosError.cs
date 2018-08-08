using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
    ///         pvno            [0] INTEGER (5),
    ///         msg-type        [1] INTEGER (30),
    ///         ctime           [2] KerberosTime OPTIONAL,
    ///         cusec           [3] Microseconds OPTIONAL,
    ///         stime           [4] KerberosTime,
    ///         susec           [5] Microseconds,
    ///         error-code      [6] Int32,
    ///         crealm          [7] Realm OPTIONAL,
    ///         cname           [8] PrincipalName OPTIONAL,
    ///         realm           [9] Realm -- service realm --,
    ///         sname           [10] PrincipalName -- service name --,
    ///         e-text          [11] KerberosString OPTIONAL,
    ///         e-data          [12] OCTET STRING OPTIONAL
    /// }
    /// </remarks>
    public class KerberosError : KerberosAsn1Object
    {
        public const int Tag = 30;
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, Tag);

        public KerberosError(Asn1Object asn1Obj) : base(Id)
        {
        }

        public int ProtocolVersionNumber { get; }
        public MessageType MessageType { get; }
    }
}
