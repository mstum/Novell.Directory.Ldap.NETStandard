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
        public IAsn1Decoder Decoder { get; }
        public Asn1Identifier Identifier { get; }
        public Stream Input { get; }
        public int Length { get; }
        public ILogger Logger { get; }

        public Asn1DecoderProperties(IAsn1Decoder decoder, Asn1Identifier id, Stream input, int length, ILogger logger)
        {
            Decoder = decoder;
            Identifier = id;
            Input = input;
            Length = length;
            Logger = logger.OrNullLogger();
        }

        public Asn1Object Decode(DecodeAsn1Object contextItemDecoder = null)
            => Decoder.Decode(Input, contextItemDecoder);

        public T DecodeAs<T>(DecodeAsn1Object contextItemDecoder = null) where T : Asn1Object
            => Decode(contextItemDecoder) as T;
    }

    public interface IAsn1Decoder
    {
        Asn1EncodingType EncodingType { get; }

        void AddDecoder(DecodeAsn1Object decoder);

        Asn1Object Decode(byte[] input, DecodeAsn1Object contextItemDecoder);

        Asn1Object Decode(Stream input, DecodeAsn1Object contextItemDecoder);

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
        Asn1Object Decode(Stream input, int[] length, DecodeAsn1Object contextItemDecoder);

        // TODO: Are these useful?
        bool DecodeBoolean(Stream input, int len);
        long DecodeNumeric(Stream input, int len);
        byte[] DecodeOctetString(Stream input, int len);
        string DecodeCharacterString(Stream input, int len);
    }
}
