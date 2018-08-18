using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;

namespace Novell.Directory.Ldap.Asn1
{
    public static class Asn1CodecFactory
    {
        private static readonly ConcurrentBag<DecodeAsn1Object> _decoders = new ConcurrentBag<DecodeAsn1Object>();

        public static void AddGlobalDecoder(DecodeAsn1Object decoder)
        {
            _decoders.Add(decoder);
        }

        public static IAsn1Decoder CreateDecoder(Asn1EncodingType encodingType, ILogger logger = null)
        {
            IAsn1Decoder decoder;
            switch (encodingType)
            {
                case Asn1EncodingType.BER:
                    decoder = new LberDecoder(logger);
                    break;
                default:
                    throw new ArgumentOutOfRangeException("Unsupported encoding: " + encodingType);
            }

            foreach (var dc in _decoders)
            {
                decoder.AddDecoder(dc);
            }
            return decoder;
        }

        public static IAsn1Encoder CreateEncoder(Asn1EncodingType encodingType, ILogger logger = null)
        {
            IAsn1Encoder encoder;
            switch (encodingType)
            {
                case Asn1EncodingType.BER:
                    encoder = new LberEncoder();
                    break;
                default:
                    throw new ArgumentOutOfRangeException("Unsupported encoding: " + encodingType);
            }
            return encoder;
        }

    }

    public enum Asn1EncodingType
    {
        /// <summary>
        /// Basic Encoding Rules (BER) (X.690)
        /// </summary>
        BER
        
        // TODO:
        // Distinguished Encoding Rules (DER) (X.690)
        //
        // WISH LIST:
        // Canonical Encoding Rules (CER) (X.690)
        // Packed Encoding Rules (PER) (X.691)
        // Unaligned Packed Encoding Rules (UPER) (X.691)
        // Canonical Packed Encoding Rules (CPER) (X.691)
        // Canonical Unaligned Packed Encoding Rules (CUPER) (X.691)
        // XML Encoding Rules (XER) (X.693)
        // Canonical XML Encoding Rules (CXER) (X.693)
        // Extended XML Encoding Rules (E-XER) (X.693)
        // Octet Encoding Rules (OER) (X.696)
        // Canonical Octet Encoding Rules (COER) (X.696)
        // JSON Encoding Rules (JER) (X.697) - https://www.itu.int/rec/T-REC-X.697/en
        // Generic String Encoding Rules (GSER) (RFC 3641)
    }
}
