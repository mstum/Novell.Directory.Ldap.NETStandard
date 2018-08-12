using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// AS-REP          ::= [APPLICATION 11] KDC-REP
    /// </summary>
    public class AsResponse : KdcResponse
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 11);

        // EncASRepPart

        public AsResponse()
            : base(Id)
        {
        }

        public AsResponse(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id, input, decoder)
        {
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
