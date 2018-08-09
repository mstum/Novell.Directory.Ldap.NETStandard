using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// KDC-REQ-BODY    ::= SEQUENCE {
    ///         kdc-options             [0] KDCOptions,
    ///         cname                   [1] PrincipalName OPTIONAL
    ///                                     -- Used only in AS-REQ --,
    ///         realm                   [2] Realm
    ///                                     -- Server's realm
    ///                                     -- Also client's in AS-REQ --,
    ///         sname                   [3] PrincipalName OPTIONAL,
    ///         from                    [4] KerberosTime OPTIONAL,
    ///         till                    [5] KerberosTime,
    ///         rtime                   [6] KerberosTime OPTIONAL,
    ///         nonce                   [7] UInt32,
    ///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
    ///                                     -- in preference order --,
    ///         addresses               [9] HostAddresses OPTIONAL,
    ///         enc-authorization-data  [10] EncryptedData OPTIONAL
    ///                                     -- AuthorizationData --,
    ///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
    ///                                         -- NOTE: not empty
    /// }
    /// </summary>
    public class KdcReqBody : KerberosAsn1Object
    {
        // KDC-REQ-BODY has no Id of it's own, since it's always part of some object
        public KdcReqBody() : base(Asn1Sequence.Id) { }

        public KdcReqBody(Asn1Tagged input, IAsn1Decoder decoder) : base(Asn1Sequence.Id)
        {
            var ostring = input.TaggedValue as Asn1OctetString;
            var seq = decoder.Decode(ostring.ByteValue()) as Asn1Sequence;

        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
