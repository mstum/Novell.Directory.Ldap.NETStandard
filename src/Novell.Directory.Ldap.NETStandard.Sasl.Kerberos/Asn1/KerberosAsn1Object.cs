using System;
using System.Collections.Generic;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public abstract class KerberosAsn1Object : Asn1Object
    {
        protected KerberosAsn1Object(Asn1Identifier id) : base(id)
        {
        }

        protected IEnumerable<Asn1Tagged> IterateThroughSequence(Asn1Tagged input, IAsn1Decoder decoder, bool contextTagsOnly)
        {
            var val = input.TaggedValue as Asn1OctetString;
            var sequence = decoder.Decode(val.ByteValue()) as Asn1Sequence;

            var size = sequence.Size();
            for (int i = 0; i < size; i++)
            {
                var item = sequence.get_Renamed(i);
                if (contextTagsOnly && !item.GetIdentifier().IsContext)
                {
                    continue;
                }
                yield return item as Asn1Tagged;
            }
        }

        protected IEnumerable<Asn1Tagged> IterateThroughSequence(Asn1Sequence sequence)
        {
            var size = sequence.Size();
            for (int i = 0; i < size; i++)
            {
                var item = sequence.get_Renamed(i);
                yield return item as Asn1Tagged;
            }
        }

        protected T[] IterateAndTransform<T>(Asn1Tagged sequence, IAsn1Decoder decoder, Func<int, Asn1Object, T> processWithIndex)
        {
            var seq = SequenceFromTaggedItem(sequence, decoder);
            return IterateAndTransform(seq, processWithIndex);
        }

        protected T[] IterateAndTransform<T>(Asn1OctetString sequence, IAsn1Decoder decoder, Func<int, Asn1Object, T> processWithIndex)
        {
            var seq = SequenceFromOctetString(sequence, decoder);
            return IterateAndTransform(seq, processWithIndex);
        }

        protected T[] IterateAndTransform<T>(Asn1Sequence sequence, Func<int, Asn1Object, T> processWithIndex)
        {
            var size = sequence.Size();
            var result = new T[size];
            for (int i = 0; i < size; i++)
            {
                var item = sequence.get_Renamed(i);
                var r = processWithIndex(i, item);
                result[i] = r;
            }
            return result;
        }

        protected long DecodeInteger(Asn1OctetString ostring, IAsn1Decoder decoder)
        {
            var result = ostring.DecodeAs<Asn1Integer>(decoder);
            return result.LongValue();
        }

        protected Asn1Sequence SequenceFromTaggedItem(Asn1Tagged item, IAsn1Decoder decoder)
        {
            var ostring = item.TaggedValue as Asn1OctetString;
            return SequenceFromOctetString(ostring, decoder);
        }

        protected Asn1Sequence SequenceFromOctetString(Asn1OctetString ostring, IAsn1Decoder decoder)
        {
            return decoder.Decode(ostring.ByteValue()) as Asn1Sequence;
        }
    }
}
