using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public EncryptionKey(Asn1DecoderProperties props) : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();

                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        Type = (EncryptionType)DecodeInteger(ostring, decoder);
                        break;
                    case 1:
                        KeyValue = ostring.ByteValue();
                        break;
                }
            }
        }

        private Asn1Object DecodeContentTagHandler(Asn1DecoderProperties props)
        {
            var id = props.Identifier;
            var dec = props.Decoder;
            if (id.IsContext)
            {
                switch (id.Tag)
                {
                }
            }
            return null;
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
