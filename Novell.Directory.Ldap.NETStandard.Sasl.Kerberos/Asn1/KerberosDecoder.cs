using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class KerberosDecoder
    {
        public  Asn1Object DecodeTaggedObject(Stream inRenamed, int length, Asn1Identifier asn1Id, Asn1Identifier contextId)
        {
            if (asn1Id.IsSameTagAs(AsReq.Id))
            {
                // AS-REQ ::= [APPLICATION 10] KDC-REQ
                //return new AsReq(this, inRenamed, length);
            }

            if (asn1Id.IsApplication)
            {
                switch (asn1Id.Tag)
                {
                    case 1: // Ticket ::= [APPLICATION 1] SEQUENCE
                    case 2: // Authenticator ::= [APPLICATION 2] SEQUENCE
                    case 3: // EncTicketPart ::= [APPLICATION 3] SEQUENCE
                    case 11: // AS-REP ::= [APPLICATION 11] KDC-REP
                    case 12: // TGS-REQ ::= [APPLICATION 12] KDC-REQ
                    case 13: // TGS-REP ::= [APPLICATION 13] KDC-REP
                    case 14: // AP-REQ ::= [APPLICATION 14] SEQUENCE
                    case 15: // AP-REP ::= [APPLICATION 15] SEQUENCE
                    case 20: // KRB-SAFE ::= [APPLICATION 20] SEQUENCE
                    case 21: // KRB-PRIV ::= [APPLICATION 21] SEQUENCE
                    case 22: // KRB-CRED ::= [APPLICATION 22] SEQUENCE
                    case 25: // EncASRepPart ::= [APPLICATION 25] EncKDCRepPart
                    case 26: // EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart
                    case 27: // EncAPRepPart ::= [APPLICATION 27] SEQUENCE
                    case 28: // EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE
                    case 29: // EncKrbCredPart ::= [APPLICATION 29] SEQUENCE
                    case 30: // KRB-ERROR ::= [APPLICATION 30] SEQUENCE
                        break;

                    case 10: // AS-REQ ::= [APPLICATION 10] KDC-REQ
                        //return new AsReq(this, inRenamed, length);
                        break;
                }
            }

            //return base.DecodeTaggedObject(inRenamed, length, asn1Id, contextId);
            return null;
        }
    }
}
