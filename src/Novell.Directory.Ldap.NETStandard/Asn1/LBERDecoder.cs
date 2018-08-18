/******************************************************************************
* The MIT License
* Copyright (c) 2003 Novell Inc.  www.novell.com
*
* Permission is hereby granted, free of charge, to any person obtaining  a copy
* of this software and associated documentation files (the Software), to deal
* in the Software without restriction, including  without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to  permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*******************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Novell.Directory.Ldap.Asn1
{
    public class LberDecoder : IAsn1Decoder
    {
        public Asn1EncodingType EncodingType => Asn1EncodingType.BER;

        private readonly ILogger _logger;
        private readonly Stack<DecodeAsn1Object> _additionalDecoders = new Stack<DecodeAsn1Object>();
        private readonly Asn1Identifier _asn1Id = new Asn1Identifier();
        private readonly Asn1Length _asn1Len = new Asn1Length();

        public LberDecoder(ILogger logger = null)
        {
            _logger = logger.OrNullLogger();
        }

        public void AddDecoder(DecodeAsn1Object decoder)
            => _additionalDecoders.Push(decoder ?? throw new ArgumentNullException(nameof(decoder)));

        public Asn1Object Decode(byte[] input, DecodeAsn1Object contextItemDecoder)
        {
            Asn1Object asn1 = null;

            using (var inputStream = input.CreateReadStream())
            {
                try
                {
                    asn1 = Decode(inputStream, contextItemDecoder);
                }
                catch (IOException ioe)
                {
                    _logger.LogWarning("Error when Decoding", ioe);
                }
            }

            return asn1;
        }

        public Asn1Object Decode(Stream input, DecodeAsn1Object contextItemDecoder)
        {
            var len = new int[1];
            return Decode(input, len, contextItemDecoder);
        }

        public Asn1Object Decode(Stream input, int[] length, DecodeAsn1Object contextItemDecoder)
        {
            var asn1Len = AdvanceStream(input, length);

            if (_asn1Id.IsUniversal)
            {
                return HandleUniversal(_asn1Id, input, asn1Len, contextItemDecoder);
            }
            else if (_asn1Id.IsApplication)
            {
                return HandleApplication(_asn1Id, input, asn1Len);
            }
            else if (_asn1Id.IsContext || _asn1Id.IsPrivate)
            {
                if (contextItemDecoder != null)
                {
                    var props = CreateProps(_asn1Id, input, asn1Len);
                    var result = contextItemDecoder.Invoke(props);
                    if (result != null)
                    {
                        return result;
                    }
                }

                // If the Context Decoder couldn't do it, try the Application decoder
                return HandleApplication(_asn1Id, input, asn1Len);
            }

            // Fallback, just return an Asn1Tagged
            return new Asn1Tagged(this, input, asn1Len, _asn1Id.Clone());
        }

        private Asn1Object HandleApplication(Asn1Identifier asn1Id, Stream input, int asn1Len)
        {
            if (_additionalDecoders.IsNotEmpty())
            {
                var props = CreateProps(asn1Id, input, asn1Len);
                foreach (var handler in _additionalDecoders)
                {
                    var result = handler.Invoke(props);
                    if (result != null)
                    {
                        return result;
                    }
                }
            }

            // Fallback, just return an Asn1Tagged
            return new Asn1Tagged(this, input, asn1Len, asn1Id.Clone());
        }

        private Asn1Object HandleUniversal(Asn1Identifier asn1Id, Stream input, int asn1Len, DecodeAsn1Object contextItemDecoder)
        {
            // Universal tags are reverved for use within the ASN.1 Spec, so we're always handling them ourselves.
            switch (asn1Id.Tag)
            {
                case Asn1Sequence.Tag:
                    return new Asn1Sequence(this, input, asn1Len, contextItemDecoder);

                case Asn1Set.Tag:
                    return new Asn1Set(this, input, asn1Len, contextItemDecoder);

                case Asn1Boolean.Tag:
                    return new Asn1Boolean(this, input, asn1Len);

                case Asn1Integer.Tag:
                    return new Asn1Integer(this, input, asn1Len);

                case Asn1OctetString.Tag:
                    return new Asn1OctetString(this, input, asn1Len);

                case Asn1Enumerated.Tag:
                    return new Asn1Enumerated(this, input, asn1Len);

                case Asn1Null.Tag:
                    return new Asn1Null(); // has no content to decode.

                case Asn1VisibleString.Tag:
                    return new Asn1VisibleString(this, input, asn1Len);

                case Asn1GeneralizedTime.Tag:
                    return new Asn1GeneralizedTime(this, input, asn1Len);

                case Asn1GeneralString.Tag:
                    return new Asn1GeneralString(this, input, asn1Len);

                case Asn1BitString.Tag:
                    return new Asn1BitString(this, input, asn1Len);

                default:
                    var errorMsg = "Unsupported Universal Tag: " + _asn1Id;
                    _logger.LogWarning(errorMsg);
                    throw new Asn1DecodingException(errorMsg, _asn1Id);
            }
        }

        private int AdvanceStream(Stream input, int[] length)
        {
            _asn1Id.Reset(input);
            _asn1Len.Reset(input);
            _logger.LogDebug("Advanced Stream, current tag: " + _asn1Id);

            var asn1Len = _asn1Len.Length;
            length[0] = _asn1Id.EncodedLength + _asn1Len.EncodedLength + asn1Len;
            return asn1Len;
        }

        private Asn1DecoderProperties CreateProps(Asn1Identifier asn1Id, Stream input, int asn1Len)
            => new Asn1DecoderProperties(this, asn1Id.Clone(), input, asn1Len, _logger);

        public bool DecodeBoolean(Stream input, int len)
        {
            var lber = new byte[len];
            var i = SupportClass.ReadInput(input, lber, 0, lber.Length);

            if (i != len)
            {
                throw new EndOfStreamException("LBER: BOOLEAN: decode error: EOF");
            }

            return lber[0] == 0x00 ? false : true;
        }

        public string DecodeCharacterString(Stream input, int len)
        {
            var octets = new byte[len];

            for (var i = 0; i < len; i++)
            {
                var ret = input.ReadByte(); // blocks
                if (ret == -1)
                {
                    throw new EndOfStreamException("LBER: CHARACTER STRING: decode error: EOF");
                }

                octets[i] = (byte)ret;
            }

            var result = Encoding.UTF8.GetString(octets);
            return result;
        }

        public long DecodeNumeric(Stream input, int len)
        {
            long l = 0;
            var r = (long)input.ReadByte();

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
                r = input.ReadByte();
                if (r < 0)
                {
                    throw new EndOfStreamException("LBER: NUMERIC: decode error: EOF");
                }

                l = (l << 8) | r;
            }

            return l;
        }

        public byte[] DecodeOctetString(Stream input, int len)
        {
            var octets = new byte[len];
            var totalLen = 0;

            while (totalLen < len)
            {
                // Make sure we have read all the data
                var inLen = SupportClass.ReadInput(input, octets, totalLen, len - totalLen);
                totalLen += inLen;
            }

            return octets;
        }

        /* X.690
         *
         * Encoding order:
         * a) identifier octets (see 8.1.2);
         * b) length octets (see 8.1.3);
         * c) contents octets (see 8.1.4);
         * d) end-of-contents octets (see 8.1.5) if required
         *
         * Tag class, Bits      8   7
         * ==========================
         * Universal            0   0
         * Application          0   1
         * ContextSpecific      1   0
         * Private              1   1
         *
         * bit 6: Primitive = 0, Constructed = 1
         * bits 5 to 1 shall encode the number of the tag as a binary integer with bit 5 as the most significant bit
         * For tags with a number greater than or equal to 31, the identifier
         * shall comprise a leading octet followed by one or more subsequent octets.
         *
         * The leading octet shall be encoded as follows:
         * bits 8 and 7 shall be encoded to represent the class of the tag as listed in Table 1;
         * bit 6 shall be a zero or a one according to the rules of 8.1.2.5;
         * bits 5 to 1 shall be encoded as 11111
         *
         * The subsequent octets shall encode the number of the tag as follows:
         * bit 8 of each octet shall be set to one unless it is the last octet of the identifier octets;
         *
         * bits 7 to 1 of the first subsequent octet, followed by bits 7 to 1 of the second subsequent octet, followed
         * in turn by bits 7 to 1 of each further octet, up to and including the last subsequent octet in the identifier
         * octets shall be the encoding of an unsigned binary integer equal to the tag number, with bit 7 of the first
         * subsequent octet as the most significant bit;
         *
         * bits 7 to 1 of the first subsequent octet shall not all be zero.
         *
         *  8   7   6   5   4   3   2   1
         * [x] [x] [x] [1] [1] [1] [1] [1] Leading Octet
         * [1] [1] [1] [1] [1] [1] [1] [1] First Subsequent Octet. Bit 8 = 1 means that there's at least one more octet.
         * [0] [0] [0] [0] [1] [1] [1] [0] Second (and here, last subsequent octet)
         *
         * The Tag in this case is 16270 dec.
         * 0 from the leading Octet (We don't count those 5 bits)
         * We then combine the Bits 7-1 from each further octet to one one long, so in this case
         * 1111111 from Octet 2
         * 0001110 from Octet 3
         * => 11111110001110 => 16270 dec
         *
         * Another example: [APPLICATION 141] = 7F 81 0D
         * 01111111 10000001 00001101
         *
         * 01: Application Tag
         * 1: Constructed
         * 11111: Long Tag
         *
         * 1: There's another Octet later
         * 0000001: Tag part
         *
         * 0: Last Octet
         * 0001101: Tag part
         *
         * 00000010001101 = 141 dec
         *
         * // 0011 0000
         * 61 Hex = 0110 0001
         * 01: Application Tag
         * 1: Constructed
         * 00001: Tag 1
         *
         * Simpletest:
         * 61 0F 30 0D A0 03 02 01 7B A1 06 0C 04 54 65 73 74
         *
         * 61 [APPLICATION 1], constructed
         * 0F Length: 15 Bytes
         * 30 [UNIVERSAL 16], constructed (= Sequence and Sequence-of types)
         * 0D Length: 13 Bytes
         * A0 [ContextSpecific 0], constructed (Because the tag is assigned explicitly) - A0 = 1010 0000
         * 03 Length: 3
         * 02 [UNIVERSAL 2], primitive (= Integer type)
         * 01 Length: 1 Byte
         * 7B Integer Value: 123
         * A1 [ConextSpecific 1], constructed - A1 = 1010 0001
         * 06 Length: 6
         * 0C [UNIVERSAL 12], primitive (= UTF8String type)
         * 04 Length: 4
         * 54 T
         * 65 e
         * 73 s
         * 74 t
         */
    }
}
