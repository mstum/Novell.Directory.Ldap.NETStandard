# ASN.1 TODO

## Basic Types

```
[x] Boolean [UNIVERSAL 1]  
[x] Integer [UNIVERSAL 2] - Integers are unlimited range in the spec, but Int64 in this implemenation. I doubt we need a BigInteger version.  
[x] Bitstring [UNIVERSAL 3]  
[x] Octetstring [UNIVERSAL 4]  
[x] Null [UNIVERSAL 5]  
[ ] Object identifier [UNIVERSAL 6]  
[ ] Object Descriptor [UNIVERSAL 7]  
[ ] External Type and Instance-of Type [UNIVERSAL 8]  
[ ] Real [UNIVERSAL 9]  
[x] Enumerated [UNIVERSAL 10]  
[ ] Embedded-pdv [UNIVERSAL 11]  
[ ] UTF8String [UNIVERSAL 12]  
[ ] Relative Object Identifier [UNIVERSAL 13]  
[ ] time [UNIVERSAL 14]  
[x] Sequence and Sequence-of [UNIVERSAL 16]  
[x] Set and Set-of [UNIVERSAL 17]  
[ ] NumericString [UNIVERSAL 18] (0,1,2,3,4,5,6,7,8,9, and space)  
[ ] PrintableString [UNIVERSAL 19] (Upper and lower case letters, digits, space, apostrophe, left/right parenthesis, plus sign, comma, hyphen, full stop, solidus, colon, equal sign, question mark)  
[ ] TeletexString (T61String) [UNIVERSAL 20] (The Teletex character set in CCITT's T61, space, and delete)  
[ ] VideotexString [UNIVERSAL 21] (The Videotex character set in CCITT's T.100 and T.101, space, and delete)  
[ ] IA5String [UNIVERSAL 22] (International Alphabet 5 (International ASCII) - VisibleString + DELETE + C0 Set of ISO 646)  
[ ] UTCTime [UNIVERSAL 23]  
[x] GeneralizedTime [UNIVERSAL 24]  
[ ] GraphicString [UNIVERSAL 25] (All registered G sets, and space)  
[x] VisibleString (ISO646String) [UNIVERSAL 26] (Printing character sets of international ASCII, and space)  
[x] GeneralString [UNIVERSAL 27] (All registered C and G sets, space and delete)  
[ ] UniversalString [UNIVERSAL 28] (ISO/IEC 10646)
[ ] CharacterString [UNIVERSAL 29]
    [ ] RestrictedCharacterString (X.680 #41)
	[ ] UnrestrictedCharacterStringType (X.680 #44)
[ ] BMPString [UNIVERSAL 30] (BMPString is a subtype of UniversalString that has its own unique tag and contains only the characters in the Basic Multilingual Plane (those corresponding to the first 64K-2 cells, less cells whose encoding is used to address characters outside the Basic Multilingual Plane) of ISO/IEC 10646)
[ ] DATE [UNIVERSAL 31]  
[ ] TIME-OF-DAY [UNIVERSAL 32]  
[ ] DATE-TIME [UNIVERSAL 33]  
[ ] DURATION [UNIVERSAL 34]  
[ ] OID internationalized resource identifier [UNIVERSAL 35]  
[ ] Relative OID internationalized resource identifier [UNIVERSAL 36]  
```

[UNIVERSAL 15] is Reserved for future editions of this Recommendation | International Standard.  
[UNIVERSAL 37] and following is Reserved for future editions of this Recommendation | International Standard  
[UNIVERSAL 0] is Reserved for use by the encoding rules  
  
Note that CHOICE does not have a tag as every CHOICE is technically its own type, e.g.:  
ChoiceType ::= CHOICE "{" AlternativeTypeLists "}"    https://www.obj-sys.com/asn1tutorial/node11.html  Type CHOICE takes one value from a specified list of distinct types.  
The alternative types are contained in braces and may be preceded by local identifiers.  
The value notation is that for the type chosen. For example, each of the three values,  
  
> (1) nothing  TRUE,  (2) car  "Lincoln",  (3) cash  25000  

is a valid instance of

     Prize  ::=  CHOICE
       {
        car        IA5String,
        cash       INTEGER,
        nothing    BOOLEAN
       }.

Type SELECTION enables the user to choose a component type from a specified CHOICE type.  
The less than symbol "<" must precede the name of the CHOICE type.  
For example, the component cash of CHOICE type Prize can appear in a specified SEQUENCE type  

     Winner  ::=  SEQUENCE
       {
        lastName    VisibleString,
        ssn         VisibleString,
        cash   <    Prize
       }

with value notation  

       {
        lastName    `AUSTING',
        ssn         `222334444',
        cash        5000
       }## Kerberos```[-] Int32 ::= INTEGER (-2147483648..2147483647)  => just use int  [-] UInt32 ::= INTEGER (0..4294967295)  => just use uint  [x] Microseconds ::= INTEGER (0..999999)  [-] KerberosString ::= GeneralString (IA5String) => just use string  [-] Realm ::= KerberosString => just use string  [x] PrincipalName ::= SEQUENCE  [x] KerberosTime ::= GeneralizedTime -- with no fractional seconds  [x] HostAddress ::= SEQUENCE  [-] HostAddresses ::= SEQUENCE OF HostAddress => Not a special type[x] AuthorizationData ::= SEQUENCE OF SEQUENCE  [x] PA-DATA ::= SEQUENCE  [x] KerberosFlags ::= BIT STRING (SIZE (32..MAX))  => Asn1BitString[x] EncryptedData ::= SEQUENCE  [x] EncryptionKey ::= SEQUENCE  [x] Checksum ::= SEQUENCE  [x] Ticket ::= [APPLICATION 1] SEQUENCE  [x] EncTicketPart ::= [APPLICATION 3] SEQUENCE  [x] TransitedEncoding ::= SEQUENCE  [x] TicketFlags ::= KerberosFlags  [x] AS-REQ ::= [APPLICATION 10] KDC-REQ  [x] TGS-REQ ::= [APPLICATION 12] KDC-REQ  [x] KDC-REQ ::= SEQUENCE  [x] KDC-REQ-BODY ::= SEQUENCE  [x] KDCOptions ::= KerberosFlags  [x] AS-REP ::= [APPLICATION 11] KDC-REP  [x] TGS-REP ::= [APPLICATION 13] KDC-REP  [x] KDC-REP ::= SEQUENCE  [x] EncASRepPart ::= [APPLICATION 25] EncKDCRepPart  [x] EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart  [x] EncKDCRepPart ::= SEQUENCE  [x] LastReq ::= SEQUENCE OF SEQUENCE  [ ] AP-REQ ::= [APPLICATION 14] SEQUENCE  [ ] APOptions ::= KerberosFlags  [ ] Authenticator ::= [APPLICATION 2] SEQUENCE  [ ] AP-REP ::= [APPLICATION 15] SEQUENCE  [ ] EncAPRepPart ::= [APPLICATION 27] SEQUENCE  [ ] KRB-SAFE ::= [APPLICATION 20] SEQUENCE  [ ] KRB-SAFE-BODY ::= SEQUENCE  [ ] KRB-PRIV ::= [APPLICATION 21] SEQUENCE  [ ] EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE  [ ] KRB-CRED ::= [APPLICATION 22] SEQUENCE  [ ] EncKrbCredPart ::= [APPLICATION 29] SEQUENCE  [ ] KrbCredInfo ::= SEQUENCE  [x] KRB-ERROR ::= [APPLICATION 30] SEQUENCE  [ ] METHOD-DATA ::= SEQUENCE OF PA-DATA  [ ] TYPED-DATA ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE  [ ] PA-ENC-TIMESTAMP ::= EncryptedData -- PA-ENC-TS-ENC  [ ] PA-ENC-TS-ENC := SEQUENCE  [ ] ETYPE-INFO-ENTRY ::= SEQUENCE  [ ] ETYPE-INFO ::= SEQUENCE OF ETYPE-INFO-ENTRY  [ ] ETYPE-INFO2-ENTRY ::= SEQUENCE  [ ] ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY  [ ] AD-IF-RELEVANT ::= AuthorizationData  [ ] AD-KDCIssued ::= SEQUENCE  [ ] AD-AND-OR ::= SEQUENCE  [ ] AD-MANDATORY-FOR-KDC ::= AuthorizationData  ```
## Encodings/Decodings

Mandatory:  
```
[ ] Basic Encoding Rules (BER) (LBERDe/Encoder exists, but doesn't follow extensibility rules)  
[ ] Distinguished Encoding Rules (DER)  
```
  
Optional:  
```
[ ] Canonical Encoding Rules (CER)  
[ ] Packed Encoding Rules (PER)  
	[ ] PER  
	[ ] UPER (unaligned)  
	[ ] CPER (canonical)  
	[ ] CUPER (canonical unaligned)  
[ ] XML Encoding Rules (XER)  
	[ ] XER  
	[ ] CXER (Canonical)  
	[ ] E-XER (Extended)  
[ ] Octet Encoding Rules (OER)  
	[ ] OER  
	[ ] COER (Canonical)  
[ ] JSON Encoding Rules (JER) - X.697 - https://www.itu.int/rec/T-REC-X.697/en  
[ ] Generic String Encoding Rules (GSER) - RFC 3641  
```