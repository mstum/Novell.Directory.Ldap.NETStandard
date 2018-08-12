using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// EncryptedData   ::= SEQUENCE {
    ///         etype   [0] Int32 -- EncryptionType --,
    ///         kvno    [1] UInt32 OPTIONAL,
    ///         cipher  [2] OCTET STRING -- ciphertext
    /// }
    /// </summary>
    public class EncryptedData : KerberosAsn1Object
    {
        public EncryptionType Type { get; set; }

        /// <summary>
        /// This field contains the version number of the key under which data
        /// is encrypted.  It is only present in messages encrypted under long
        /// lasting keys, such as principals' secret keys.
        /// </summary>
        public uint KeyVersionNumber { get; set; }
        public byte[] CipherText { get; set; }

        public EncryptedData() : base(Asn1Sequence.Id)
        {
        }

        public EncryptedData(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Asn1Sequence.Id)
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
                        KeyVersionNumber = (uint)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        CipherText = ostring.ByteValue();
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
