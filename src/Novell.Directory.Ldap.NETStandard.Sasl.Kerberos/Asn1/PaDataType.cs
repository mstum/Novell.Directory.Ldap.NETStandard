using System.ComponentModel;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    public enum PaDataType
    {
        [Description("DER encoding of AP-REQ")]
        PA_TGS_REQ = 1,

        [Description("DER encoding of PA-ENC-TIMESTAMP")]
        PA_ENC_TIMESTAMP = 2,

        [Description("salt (not ASN.1 encoded)")]
        PA_PW_SALT = 3,

        // 4 is reserved

        [Description("(deprecated)")]
        PA_ENC_UNIT_TIME = 5,

        PA_SANDIA_SECUREID = 6,

        PA_SESAME = 7,

        PA_OSF_DCE = 8,

        PA_CYBERSAFE_SECUREID = 9,

        PA_AFS3_SALT = 10,

        [Description("DER encoding of ETYPE-INFO")]
        PA_ETYPE_INFO = 11,

        [Description("(sam/otp)")]
        PA_SAM_CHALLENGE = 12,

        [Description("(sam/otp)")]
        PA_SAM_RESPONSE = 13,

        [Description("(pkinit)")]
        PA_PK_AS_REQ_OLD = 14,

        [Description("(pkinit)")]
        PA_PK_AS_REP_OLD = 15,

        [Description("(pkinit)")]
        PA_PK_AS_REQ = 16,

        [Description("(pkinit)")]
        PA_PK_AS_REP = 17,

        PA_PK_OCSP_RESPONSE = 18,

        [Description("DER encoding of ETYPE-INFO2")]
        PA_ETYPE_INFO2 = 19,

        PA_USE_SPECIFIED_KVNO = 20,

        [Description("(sam/otp)")]
        PA_SAM_REDIRECT = 21,

        PA_GET_FROM_TYPED_DATA = 22, //       (embedded in typed data) - 22 as well

        TD_PADATA = 22, //       (embeds padata) - 22 as well

        [Description("(sam/otp)")]
        PA_SAM_ETYPE_INFO = 23, //       (sam/otp)

        PA_ALT_PRINC = 24, //       (crawdad@fnal.gov)

        PA_SERVER_REFERRAL = 25,

        // 26-29: Unassigned

        PA_SAM_CHALLENGE2 = 30, //       (kenh@pobox.com)

        PA_SAM_RESPONSE2 = 31, //       (kenh@pobox.com)

        // 32-40: Unassigned

        [Description("Reserved extra TGT")]
        PA_EXTRA_TGT = 41,

        // 42-100: Unassigned

        [Description("CertificateSet from CMS")]
        TD_PKINIT_CMS_CERTIFICATES = 101, //      

        [Description("PrincipalName")]
        TD_KRB_PRINCIPAL = 102,

        [Description("Realm")]
        TD_KRB_REALM = 103,

        [Description("(pkinit)")]
        TD_TRUSTED_CERTIFIERS = 104,

        [Description("(pkinit)")]
        TD_CERTIFICATE_INDEX = 105,

        [Description("application specific")]
        TD_APP_DEFINED_ERROR = 106,

        TD_REQ_NONCE = 107, //      INTEGER

        TD_REQ_SEQ = 108, //      INTEGER

        TD_DH_PARAMETERS = 109,

        // 110: Unassigned

        TD_CMS_DIGEST_ALGORITHMS = 111,

        TD_CERT_DIGEST_ALGORITHMS = 112,

        // 113-127: Unassigned

        PA_PAC_REQUEST = 128, //      (jbrezak@exchange.microsoft.com)

        PA_FOR_USER = 129,

        PA_FOR_X509_USER = 130,

        PA_FOR_CHECK_DUPS = 131,

        PA_AS_CHECKSUM = 132,

        PA_FX_COOKIE = 133,

        PA_AUTHENTICATION_SET = 134,

        PA_AUTH_SET_SELECTED = 135,

        PA_FX_FAST = 136,

        PA_FX_ERROR = 137,

        PA_ENCRYPTED_CHALLENGE = 138,

        // 139-140: Unassigned

        PA_OTP_CHALLENGE = 141,

        PA_OTP_REQUEST = 142,

        PA_OTP_CONFIRM = 143, // obsoleted

        PA_OTP_PIN_CHANGE = 144,

        PA_EPAK_AS_REQ = 145,

        PA_EPAK_AS_REP = 146,

        PA_PKINIT_KX = 147,

        PA_PKU2U_NAME = 148,

        PA_REQ_ENC_PA_REP = 149,

        PA_AS_FRESHNESS = 150,

        PA_SPAKE = 151,

        // 152-164: Unassigned

        PA_SUPPORTED_ETYPES = 165,

        PA_EXTENDED_ERROR = 166
    }
}
