using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// A Deserializer for ASN.1 objects encoded under
    /// Distinguished Encoding Rules (DER)
    /// </summary>
    /// <remarks>
    /// While Novell uses "Encoder/Decoder", standard .NET
    /// terminology would call these Serializer/Deserializer
    /// because that's what they are.
    /// </remarks>
    public class DerDeserializer : IAsn1Decoder
    {
        public Asn1Object Decode(byte[] valueRenamed, DecodingContext context)
        {
            Asn1Object asn1 = null;

            var inRenamed = new MemoryStream(valueRenamed);
            try
            {
                asn1 = Decode(inRenamed, context);
            }
            catch (IOException ioe)
            {
                Logger.Log.LogWarning("Exception swallowed", ioe);
            }

            return asn1;
        }

        public Asn1Object Decode(Stream inRenamed, DecodingContext context)
        {
            var len = new int[1];
            return Decode(inRenamed, len, context);
        }

        public Asn1Object Decode(Stream inRenamed, int[] length, DecodingContext context)
        {
            context = context ?? new DecodingContext();
            var id = new Asn1Identifier(inRenamed);
            var asn1Len = new Asn1Length(inRenamed);
            context.AddToContext(id);

            length[0] = id.EncodedLength + asn1Len.EncodedLength + asn1Len.Length;
            Asn1Object result;

            if (id.IsUniversal)
            {
                switch (id.Tag)
                {
                    case Asn1Sequence.Tag:
                        result = new Asn1Sequence(this, context, inRenamed, asn1Len.Length);
                        break;

                    case Asn1Set.Tag:
                        result = new Asn1Set(this, context, inRenamed, asn1Len.Length);
                        break;

                    case Asn1Boolean.Tag:
                        result = new Asn1Boolean(this, context, inRenamed, asn1Len.Length);
                        break;

                    case Asn1Integer.Tag:
                        result = new Asn1Integer(this, context, inRenamed, asn1Len.Length);
                        break;

                    case Asn1OctetString.Tag:
                        result = new Asn1OctetString(this, context, inRenamed, asn1Len.Length);
                        break;

                    case Asn1Enumerated.Tag:
                        result = new Asn1Enumerated(this, context, inRenamed, asn1Len.Length);
                        break;

                    case Asn1Null.Tag:
                        result = new Asn1Null(); // has no content to decode.
                        break;

                    default:
                        throw new InvalidOperationException("Unhandled Tag when decoding: [UNIVERSAL " + id.Tag + "]");
                }
            }
            else
            {
                // APPLICATION or CONTEXT-SPECIFIC tag
                result = DecodeApplicationTag(inRenamed, asn1Len, id, context);
            }

            context.PopFromContext();
            return result;
        }

        // TODO: Is there a better way to extend this rather than having to subclass the decoder?
        protected virtual Asn1Object DecodeApplicationTag(Stream inRenamed, Asn1Length length, Asn1Identifier asn1Id, DecodingContext context)
        {
            return new Asn1Tagged(this, context, inRenamed, length.Length, asn1Id);
        }

        public bool DecodeBoolean(Stream inRenamed, int len)
        {
            var lber = new byte[len];

            var i = SupportClass.ReadInput(inRenamed, ref lber, 0, lber.Length);

            if (i != len)
            {
                throw new EndOfStreamException("LBER: BOOLEAN: decode error: EOF");
            }

            return lber[0] == 0x00 ? false : true;
        }

        public string DecodeCharacterString(Stream inRenamed, int len)
        {
            var octets = new byte[len];

            for (var i = 0; i < len; i++)
            {
                var ret = inRenamed.ReadByte(); // blocks
                if (ret == -1)
                {
                    throw new EndOfStreamException("LBER: CHARACTER STRING: decode error: EOF");
                }

                octets[i] = (byte)ret;
            }

            var dchar = Encoding.UTF8.GetChars(octets);
            var rval = new string(dchar);

            return rval;
        }

        public long DecodeNumeric(Stream inRenamed, int len)
        {
            long l = 0;
            var r = inRenamed.ReadByte();

            if (r < 0)
            {
                throw new EndOfStreamException("LBER: NUMERIC: decode error: EOF");
            }

            if ((r & 0x80) != 0)
            {
                // check for negative number
                l = -1;
            }

            l = (l << 8) | r;

            for (var i = 1; i < len; i++)
            {
                r = inRenamed.ReadByte();
                if (r < 0)
                {
                    throw new EndOfStreamException("LBER: NUMERIC: decode error: EOF");
                }

                l = (l << 8) | r;
            }

            return l;
        }

        public byte[] DecodeOctetString(Stream inRenamed, int len)
        {
            var octets = new byte[len];
            var totalLen = 0;

            while (totalLen < len)
            {
                // Make sure we have read all the data
                var inLen = SupportClass.ReadInput(inRenamed, ref octets, totalLen, len - totalLen);
                totalLen += inLen;
            }

            return octets;
        }
    }
}
