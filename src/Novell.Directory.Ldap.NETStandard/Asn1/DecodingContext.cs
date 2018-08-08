using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Asn1
{
    public class DecodingContext
    {
        private readonly object AddContextLocker = new object();

        private List<Asn1Identifier> _context
            = new List<Asn1Identifier>(8);

        /// <summary>
        /// All Parent ASN.1 Object Identifiers.
        /// Example:
        /// 
        /// AP-REQ ::= [APPLICATION 14] SEQUENCE
        /// {
        ///         pvno            [0] INTEGER (5),
        ///         msg-type        [1] INTEGER (14),
        ///         ap-options      [2] APOptions,
        ///         ticket          [3] Ticket,
        ///         authenticator   [4] EncryptedData -- Authenticator
        /// }
        /// Ticket          ::= [APPLICATION 1] SEQUENCE {
        ///         tkt-vno         [0] INTEGER (5),
        ///         realm           [1] Realm,
        ///         sname           [2] PrincipalName,
        ///         enc-part        [3] EncryptedData -- EncTicketPart
        /// }
        /// 
        /// The Context would be:
        /// [0] APPLICATION 14 (AP-REQ)
        /// [1] UNIVERSAL 16 (Sequence)
        /// [2] APPLICATION 1 (Ticket)
        /// [3] UNIVERSAL 16 (Sequence)
        /// </summary>
        public IReadOnlyCollection<Asn1Identifier> Context => _context;

        /// <summary>
        /// Add a new Asn1Identifier to the collection.
        /// Makes a copy of the <see cref="Asn1Identifier"/> class
        /// to avoid object reference issues.
        /// </summary>
        /// <param name="asn1Id"></param>
        public void AddToContext(Asn1Identifier asn1Id)
        {
            // Can't use a ConcurrentBag<Asn1Identifier>
            // because that one is unordered. Order is important.
            lock (AddContextLocker)
            {
                _context.Add(asn1Id.Clone() as Asn1Identifier);
            }
        }

        /// <summary>
        /// Removes and returns the last <see cref="Asn1Identifier"/>
        /// from the <see cref="Context"/>.
        /// </summary>
        /// <returns></returns>
        public Asn1Identifier PopFromContext()
        {
            lock (AddContextLocker)
            {
                if (_context.Count > 0)
                {
                    var ix = _context.Count - 1;
                    var result = _context[ix];
                    _context.RemoveAt(ix);
                    return result;
                }
                return null;
            }
        }
    }
}
