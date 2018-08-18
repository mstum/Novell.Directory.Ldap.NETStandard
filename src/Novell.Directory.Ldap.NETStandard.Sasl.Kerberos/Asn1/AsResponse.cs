using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// AS-REP          ::= [APPLICATION 11] KDC-REP
    /// </summary>
    public class AsResponse : KdcResponse
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 11);

        // TODO: EcryptedData to EncASRepPart

        public AsResponse()
            : base(Id)
        {
        }

        public AsResponse(Asn1DecoderProperties props)
            : base(Id, props)
        {
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
