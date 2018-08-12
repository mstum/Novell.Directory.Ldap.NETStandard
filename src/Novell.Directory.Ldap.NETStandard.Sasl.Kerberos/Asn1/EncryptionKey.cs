using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// EncryptionKey   ::= SEQUENCE {
    ///        keytype         [0] Int32 -- actually encryption type --,
    ///        keyvalue        [1] OCTET STRING
    ///}
    /// </summary>
    public class EncryptionKey : KerberosAsn1Object
    {
        /// <summary>
        /// This field specifies the encryption type of the encryption key
        /// that follows in the keyvalue field.  Although its name is
        /// "keytype", it actually specifies an encryption type.  Previously,
        /// multiple cryptosystems that performed encryption differently but
        /// were capable of using keys with the same characteristics were
        /// permitted to share an assigned number to designate the type of
        /// key; this usage is now deprecated.
        /// </summary>
        public EncryptionType Type { get; set; }

        public byte[] KeyValue { get; set; }

        public EncryptionKey() : base(Asn1Sequence.Id)
        {
        }

        public EncryptionKey(Asn1Tagged input, IAsn1Decoder decoder) : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();

                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        var type = ostring.DecodeAs<Asn1Integer>(decoder);
                        Type = (EncryptionType)type.IntValue();
                        break;
                    case 1:
                        KeyValue = ostring.ByteValue();
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
