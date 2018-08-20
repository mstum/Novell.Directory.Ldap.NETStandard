using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;

namespace Novell.Directory.Ldap.Asn1
{
    /// <summary>
    /// This should return NULL if an object is not supported
    /// </summary>
    public delegate Asn1Object DecodeAsn1Object(Asn1DecoderProperties props);

    public class Asn1DecoderProperties
    {
        public DecodeAsn1Object ContextDecoder { get; set; }

        public IAsn1Decoder Decoder { get; set; }
        public Asn1Identifier Identifier { get; set; }
        public Stream Input { get; set; }
        public int Length { get; set; }
        public ILogger Logger { get; set; }

        public Stack<Asn1Object> Context { get; set; }

        public Asn1Object Decode(DecodeAsn1Object newContextDecoder)
        {
            DecodeAsn1Object prev = ContextDecoder;
            ContextDecoder = newContextDecoder;
            var result = Decoder.Decode(Input, this);
            ContextDecoder = prev;
            return result;
        }

        public T DecodeAs<T>(DecodeAsn1Object newContextDecoder = null) where T : Asn1Object
            => Decode(newContextDecoder) as T;
    }

    public interface IAsn1Decoder
    {
        Asn1EncodingType EncodingType { get; }

        void AddDecoder(DecodeAsn1Object decoder);

        Asn1Object Decode(byte[] input, Asn1DecoderProperties contextItemDecoder);

        Asn1Object Decode(Stream input, Asn1DecoderProperties contextItemDecoder);

        /// <summary>
        ///     Decode an encoded value into an Asn1Object from an InputStream.
        /// </summary>
        /// <param name="length">
        ///     The decoded components encoded length. This value is
        ///     handy when decoding structured types. It allows you to accumulate
        ///     the number of bytes decoded, so you know when the structured
        ///     type has decoded all of its components.
        /// </param>
        /// <param name="input">
        ///     An input stream containig the encoded ASN.1 data.
        /// </param>
        Asn1Object Decode(Stream input, int[] length, Asn1DecoderProperties contextItemDecoder);

        // TODO: Are these useful?
        bool DecodeBoolean(Stream input, int len);
        long DecodeNumeric(Stream input, int len);
        byte[] DecodeOctetString(Stream input, int len);
        string DecodeCharacterString(Stream input, int len);
    }
}
