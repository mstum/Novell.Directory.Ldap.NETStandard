﻿using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Sasl.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public class KerberosNetTests
    {
        [Fact]
        public void KrbAsReq()
        {
            //var msg = new KrbAsReq();
            /*var appId10 = new Asn1Identifier(Asn1Identifier.Application, true, 10);
            var kdcReq = new Asn1Sequence();
            kdcReq.Add(new Asn1Null());
            kdcReq.Add(new Asn1Integer(5)); // pvno            [1] INTEGER (5)
            /*kdcReq.Add(new Asn1Integer(10)); // msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --)
            kdcReq.Add(new Asn1Sequence()); // padata          [3] SEQUENCE OF PA-DATA OPTIONAL -- NOTE: not empty --

            var kdcReqBody = new Asn1Sequence();

            kdcReq.Add(kdcReqBody); // req-body        [4] KDC-REQ-BODY*/

            //var tagged = new Asn1Tagged(appId10, kdcReq);
            /*using (var ms = new MemoryStream())
            {
                //kdcReq.Encode(new LberEncoder(), ms);
                ms.Position = 0;
                var arr = ms.ToArray();
                var asn1 = new Kerberos.NET.Crypto.Asn1Element(arr);
                var msg = new KdcReq(asn1);
            }*/

            var b = new byte[] { 0x6a, 0x81, 0xa2, 0x30, 0x81, 0x9f, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa4, 0x81, 0x92, 0x30, 0x81, 0x8f, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x11, 0x30, 0x0f, 0x1b, 0x0d, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x6f, 0x72, 0xa2, 0x14, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xa3, 0x27, 0x30, 0x25, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1e, 0x30, 0x1c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xa5, 0x11, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa7, 0x06, 0x02, 0x04, 0x3a, 0xc4, 0x87, 0x9c, 0xa8, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17 };

            var decoder = new LberDecoder();
            var tagged = decoder.Decode(b);

            var kerbDec = new KerberosDecoder();
            var result = kerbDec.Decode(tagged);

            /*var taggedId = tagged.GetIdentifier();
            switch (taggedId)
            {
                case var x when (taggedId.IsApplication && taggedId.Tag == 10):
                    {
                        var val = (tagged.TaggedValue as Asn1OctetString).ByteValue();
                        var seq = decoder.Decode(val);

                        var r = new AsReq(new Asn1Object[] { tagged.TaggedValue }, 1);
                        var v = r.ToString();
                    }
                    break;
                default:
                    throw new InvalidOperationException("Unknown Kerberos Response: " + tagged.ToString());
            }*/




        }
    }
}
