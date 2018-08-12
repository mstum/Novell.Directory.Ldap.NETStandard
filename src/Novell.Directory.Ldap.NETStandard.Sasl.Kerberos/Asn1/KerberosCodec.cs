using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class KerberosCodec
    {
        public KerberosAsn1Object Decode(Asn1Tagged input, IAsn1Decoder decoder)
        {
            // Valid Kerberos PDUs (Top-Level Objects):
            //  1 Ticket
            // 10 AS-REQ
            // 11 AS-REP
            // 12 TGS-REQ
            // 13 TGS-REP
            // 14 AP-REQ
            // 15 AP-REP
            // 20 KRB-SAFE
            // 21 KRB-PRIV
            // 22 KRB-CRED
            // 30 KRB-ERROR
            //
            // All other Kerberos Object are meant to be contained, and will thus throw an exception
            var id = input.GetIdentifier();

            if (id.IsSameTagAs(Ticket.Id))
            {
                return new Ticket(input, decoder);
            }
            if (id.IsSameTagAs(AsRequest.Id))
            {
                return new AsRequest(input, decoder);
            }
            if (id.IsSameTagAs(AsResponse.Id))
            {
                return new AsResponse(input, decoder);
            }
            if (id.IsSameTagAs(TgsRequest.Id))
            {
                return new TgsRequest(input, decoder);
            }
            if (id.IsSameTagAs(TgsResponse.Id))
            {
                return new TgsResponse(input, decoder);
            }

            // 14 AP-REQ
            // 15 AP-REP
            // 20 KRB-SAFE
            // 21 KRB-PRIV
            // 22 KRB-CRED

            if (id.IsSameTagAs(KerberosError.Id))
            {
                return new KerberosError(input, decoder);
            }

            throw new InvalidOperationException("Trying to decode a Non-PDU object: " + id.ToString());
        }
    }
}
