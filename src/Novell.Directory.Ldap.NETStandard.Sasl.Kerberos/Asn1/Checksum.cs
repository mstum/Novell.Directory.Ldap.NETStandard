using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// Checksum        ::= SEQUENCE {
    ///         cksumtype       [0] Int32,
    ///         checksum        [1] OCTET STRING
    /// }
    /// </summary>
    public class Checksum : KerberosAsn1Object
    {
        public ChecksumType Type { get; set; }
        public byte[] Value { get; set; }

        public Checksum(Asn1Tagged input, IAsn1Decoder decoder)
             : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        Type = (ChecksumType)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        Value = ostring.ByteValue();
                        break;
                }
            }
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
