using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// KerberosTime ::= GeneralizedTime -- with no fractional seconds
    /// </summary>
    public class KerberosTime : Asn1GeneralizedTime
    {
        public KerberosTime()
        {
        }

        public KerberosTime(IAsn1Decoder dec, Stream inRenamed, int len) : base(dec, inRenamed, len)
        {
        }

        public KerberosTime(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len) : base(id, dec, inRenamed, len)
        {
        }

        protected KerberosTime(Asn1Identifier id) : base(id)
        {
        }

        protected override void Decode(Stream inRenamed, int len)
        {
            base.Decode(inRenamed, len);

            // No fractional seconds in KerberosTime
            if (GeneralizedTime.Millisecond != 0)
            {
                var newDt = new DateTime(GeneralizedTime.Year, GeneralizedTime.Month, GeneralizedTime.Day,
                    GeneralizedTime.Hour, GeneralizedTime.Minute, GeneralizedTime.Second, millisecond: 0,
                    kind: GeneralizedTime.Kind);
                GeneralizedTime = newDt;
            }
        }
    }
}
