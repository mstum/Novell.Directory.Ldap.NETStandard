using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
    /// </summary>
    public class EncTgsRepPart : EncKdcRepPart
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 26);

        public EncTgsRepPart()
            : base(Id)
        {
        }

        public EncTgsRepPart(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id, input, decoder)
        {
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
