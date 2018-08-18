using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// LastReq         ::=     SEQUENCE OF SEQUENCE {
    ///         lr-type         [0] Int32,
    ///         lr-value        [1] KerberosTime
    /// }
    /// </summary>
    public class LastReq : KerberosAsn1Object
    {
        public int Type { get; set; }
        public DateTime Value { get; set; }

        public LastReq()
            : base(Asn1Sequence.Id)
        {
        }

        public LastReq(Asn1DecoderProperties props)
            : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        Type = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        var val = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        Value = val.GeneralizedTime;
                        break;
                }
            }
        }

        private Asn1Object DecodeContentTagHandler(Asn1DecoderProperties props)
        {
            var id = props.Identifier;
            var dec = props.Decoder;
            if (id.IsContext)
            {
                switch (id.Tag)
                {
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
