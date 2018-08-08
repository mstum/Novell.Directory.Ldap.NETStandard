using System;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Asn1
{
    /// <summary>
    /// VisibleString (ISO646String) [UNIVERSAL 26] (Printing character sets of international ASCII, and space)
    /// </summary>
    public class Asn1VisibleString : Asn1Object
    {
        /// <summary>
        /// ISO 646, USA Version X3.4 - 1968 + SPACE
        /// ASCII from the ! (0x21 / 33dec) to the ~ (0x7E / 126dec) and the Space char (0x20 / 32dec)
        /// </summary>
        private readonly static byte MinByte = 0x20;
        private readonly static byte MaxByte = 0x7E;
        private byte[] _content;

        public const int Tag = 26;
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Universal, true, Tag);

        public Asn1VisibleString() : base(Id)
        {
        }

        public Asn1VisibleString(Asn1Identifier id) : base(id)
        {
        }

        public Asn1VisibleString(IAsn1Decoder dec, Stream inRenamed, int len)
            : base(Id)
        {
            Decode(inRenamed, len);
        }

        public Asn1VisibleString(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len)
            : base (id)
        {
            Decode(inRenamed, len);
        }

        private void Decode(Stream inRenamed, int len)
        {
            var chars = new byte[len];
            for (var i = 0; i < len; i++)
            {
                var ret = (byte)inRenamed.ReadByte();
                if (ret < MinByte || ret > MaxByte)
                {
                    throw new Asn1DecodingException("Invalid Character for ASN.1 VisibleString: 0x" + ret.ToString("X2"));
                }

                chars[i] = ret;
            }
            _content = chars;
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }

        public byte[] ByteValue()
        {
            return _content;
        }

        public string StringValue()
            => Encoding.ASCII.GetString(_content);

        public override string ToString()
        {
            return base.ToString() + "VISIBLE STRING: " + StringValue();
        }
    }
}
