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
        protected readonly static byte MinByte = 0x20;
        protected readonly static byte MaxByte = 0x7E;
        protected byte[] Content { get; set; }

        public const int Tag = 26;
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Universal, true, Tag);

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

        protected virtual void Decode(Stream inRenamed, int len)
        {
            var chars = new byte[len];
            for (var i = 0; i < len; i++)
            {
                var retVal = inRenamed.ReadByte();
                if (retVal == -1)
                {
                    throw new Asn1DecodingException("Encountered EOF before the string was fully decoded.");
                }

                if (retVal < MinByte || retVal > MaxByte)
                {
                    throw new Asn1DecodingException("Invalid Character for ASN.1 VisibleString: 0x" + retVal.ToString("X2"));
                }

                chars[i] = (byte)retVal;
            }
            Content = chars;
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }

        public virtual byte[] ByteValue()
        {
            return Content;
        }

        public virtual string StringValue()
            => Encoding.ASCII.GetString(Content);

        protected virtual string ToStringName => "VISIBLE STRING: ";

        public override string ToString()
        {
            return base.ToString() + ToStringName + StringValue();
        }
    }
}
