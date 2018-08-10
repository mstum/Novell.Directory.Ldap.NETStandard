using System;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Asn1
{
    /// <summary>
    /// GeneralString [UNIVERSAL 27] (All registered C and G sets, space and delete)
    /// </summary>
    public class Asn1GeneralString : Asn1Object
    {
        protected byte[] Content { get; set; }

        public const int Tag = 27;
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Universal, true, Tag);

        public Asn1GeneralString() : base(Id)
        {
        }

        public Asn1GeneralString(Asn1Identifier id) : base(id)
        {
        }

        public Asn1GeneralString(IAsn1Decoder dec, Stream inRenamed, int len)
            : base(Id)
        {
            Decode(inRenamed, len);
        }

        public Asn1GeneralString(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len)
            : base(id)
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

                // TODO: Validate if character is in range:
                // (All registered C and G sets, space and delete)

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

        public override string ToString()
        {
            return base.ToString() + "GENERAL STRING: " + StringValue();
        }
    }
}
