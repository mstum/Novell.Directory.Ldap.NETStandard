using Novell.Directory.Ldap.Asn1;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    public static class KerberosCodec
    {
        public static Asn1Object DecodeKerberosObject(Asn1DecoderProperties props)
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
            // Anything else won't be decoded by this method as it's
            // meant to be part of one of the PDUs.

            var id = props.Identifier;

            if (id.IsSameTagAs(Ticket.Id))
            {
                return new Ticket(props);
            }
            if (id.IsSameTagAs(AsRequest.Id))
            {
                return new AsRequest(props);
            }
            if (id.IsSameTagAs(AsResponse.Id))
            {
                return new AsResponse(props);
            }
            if (id.IsSameTagAs(TgsRequest.Id))
            {
                return new TgsRequest(props);
            }
            if (id.IsSameTagAs(TgsResponse.Id))
            {
                return new TgsResponse(props);
            }

            // 14 AP-REQ
            // 15 AP-REP
            // 20 KRB-SAFE
            // 21 KRB-PRIV
            // 22 KRB-CRED

            if (id.IsSameTagAs(KerberosError.Id))
            {
                return new KerberosError(props);
            }

            props.Logger.LogDebug($"{nameof(KerberosCodec)} does not handle ASN.1 objects with ID {id}");
            return null;
        }
    }
}
