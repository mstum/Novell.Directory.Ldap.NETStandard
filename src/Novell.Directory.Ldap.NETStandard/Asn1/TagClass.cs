namespace Novell.Directory.Ldap.Asn1
{
    /* Restrictions on tags assigned by the user of ASN.1 are specified in 31.2
     * The "Class" shall not be UNIVERSAL except for types defined in this Recommendation | International Standard.
     * 
     * UNIVERSAL 0 Reserved for use by the encoding rules
     * UNIVERSAL 1 Boolean type
     * UNIVERSAL 2 Integer type
     * UNIVERSAL 3 Bitstring type
     * UNIVERSAL 4 Octetstring type
     * UNIVERSAL 5 Null type
     * UNIVERSAL 6 Object identifier type
     * UNIVERSAL 7 Object descriptor type
     * UNIVERSAL 8 External type and Instance-of type
     * UNIVERSAL 9 Real type
     * UNIVERSAL 10 Enumerated type
     * UNIVERSAL 11 Embedded-pdv type
     * UNIVERSAL 12 UTF8String type
     * UNIVERSAL 13 Relative object identifier type
     * UNIVERSAL 14 The time type
     * UNIVERSAL 15 Reserved for future editions of this Recommendation | International Standard
     * UNIVERSAL 16 Sequence and Sequence-of types
     * UNIVERSAL 17 Set and Set-of types
     * UNIVERSAL 18-22, 25-30 Character string types
     * UNIVERSAL 23-24 UTCTime and GeneralizedTime
     * UNIVERSAL 31-34 DATE, TIME-OF-DAY, DATE-TIME and DURATION respectively
     * UNIVERSAL 35 OID internationalized resource identifier type
     * UNIVERSAL 36 Relative OID internationalized resource identifier type
     * UNIVERSAL 37-... Reserved for addenda to this Recommendation | International Standard
     */
    public enum TagClass
    {
        Universal = 0,
        Application = 1,
        ContextSpecific = 2,
        Private = 3
    }
}
