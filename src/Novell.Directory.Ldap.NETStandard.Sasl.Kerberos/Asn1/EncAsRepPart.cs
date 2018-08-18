using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
    /// </summary>
    public class EncAsRepPart : EncKdcRepPart
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 25);

        public EncAsRepPart()
            : base(Id)
        {
        }

        public EncAsRepPart(Asn1DecoderProperties props)
            : base(Id, props)
        {
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
