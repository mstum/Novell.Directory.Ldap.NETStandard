using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public EncryptedData(Asn1DecoderProperties props)
            : this()
        {
            props.Decode(DecodeContentTagHandler);
        }

        private Asn1Object DecodeContentTagHandler(Asn1DecoderProperties props)
        {
            var id = props.Identifier;
            var dec = props.Decoder;
            if (id.IsContext)
            {
                switch (id.Tag)
                {
                    case 0:
                        // etype   [0] Int32 -- EncryptionType --,
                        var asn1EType = DecodeAs<Asn1Integer>(props);
                        Type = (EncryptionType)asn1EType.IntValue();
                        return asn1EType;
                    case 1:
                        // kvno    [1] UInt32 OPTIONAL,
                        var asn1kvno = DecodeAs<Asn1Integer>(props);
                        KeyVersionNumber = (uint)asn1kvno.LongValue();
                        return asn1kvno;
                    case 2:
                        // cipher  [2] OCTET STRING -- ciphertext
                        var cipher = DecodeAs<Asn1OctetString>(props);
                        CipherText = cipher.ByteValue();
                        return cipher;
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
