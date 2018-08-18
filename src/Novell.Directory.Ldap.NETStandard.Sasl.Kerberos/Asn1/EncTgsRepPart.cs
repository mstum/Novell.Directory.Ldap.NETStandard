using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
    /// </summary>
    public class EncTgsRepPart : EncKdcRepPart
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 26);

        public EncTgsRepPart()
            : base(Id)
        {
        }

        public EncTgsRepPart(Asn1DecoderProperties props)
            : base(Id, props)
        {
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
