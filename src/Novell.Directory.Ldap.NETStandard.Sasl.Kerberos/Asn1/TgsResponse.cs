using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// TGS-REP         ::= [APPLICATION 13] KDC-REP
    /// </summary>
    public class TgsResponse : KdcResponse
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 13);

        // TODO: EcryptedData to EncTGSRepPart

        public TgsResponse()
            : base(Id)
        {
        }

        public TgsResponse(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id, input, decoder)
        {
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
