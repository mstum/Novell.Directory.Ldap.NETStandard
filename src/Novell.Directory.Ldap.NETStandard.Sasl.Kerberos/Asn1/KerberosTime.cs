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

        public KerberosTime(IAsn1Decoder dec, Stream inRenamed, int len)
            : base(dec, inRenamed, len)
        {
        }

        public KerberosTime(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len)
            : base(id, dec, inRenamed, len)
        {
        }

        public KerberosTime(Asn1GeneralizedTime asn1Time)
        {
            GeneralizedTime = RemoveFractionalSeconds(asn1Time.GeneralizedTime);
        }

        protected KerberosTime(Asn1Identifier id) : base(id)
        {
        }

        protected override void Decode(Stream inRenamed, int len)
        {
            base.Decode(inRenamed, len);
            GeneralizedTime = RemoveFractionalSeconds(GeneralizedTime);
        }

        private static DateTime RemoveFractionalSeconds(DateTime inputTime)
        {
            // No fractional seconds in KerberosTime
            if (inputTime.Millisecond != 0)
            {
                var newDt = new DateTime(inputTime.Year, inputTime.Month, inputTime.Day,
                    inputTime.Hour, inputTime.Minute, inputTime.Second, millisecond: 0,
                    kind: inputTime.Kind);
                return newDt;
            }
            return inputTime;
        }
    }
}
