using System;
using System.IO;

namespace Novell.Directory.Ldap.Asn1
{
    /// <summary>
    /// GeneralizedTime [UNIVERSAL 24]
    /// </summary>
    public class Asn1GeneralizedTime : Asn1VisibleString
    {
        public new const int Tag = 24;
        public new static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Universal, true, Tag);

        public DateTime GeneralizedTime { get; protected set; }

        public Asn1GeneralizedTime() : base(Id)
        {
        }

        protected Asn1GeneralizedTime(Asn1Identifier id) : base(id)
        {
        }

        public Asn1GeneralizedTime(IAsn1Decoder dec, Stream inRenamed, int len)
            : base(Id)
        {
            Decode(inRenamed, len);
        }

        public Asn1GeneralizedTime(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len)
            : base(id)
        {
            Decode(inRenamed, len);
        }

        protected override void Decode(Stream inRenamed, int len)
        {
            base.Decode(inRenamed, len);
            if (Content.IsEmpty())
            {
                return;
            }

            // ISO 8601 Basic Format
            // 

            const byte charZ = 0x5A;
            const byte char0 = 0x30;
            const byte char9 = 0x39;
            const byte charDot = 0x2E;
            const byte charComma = 0x2C;

            int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, millisecond = 0;
            double fraction = 0d;
            double fractionDivisor = 10d;
            bool isFractionalHour = false, isFractionalMinute = false;
            bool isUtc = false;
            var state = DecodeState.Year;

            for (int i = 0; i < Content.Length; i++)
            {
                var charByte = Content[i];
                if ((charByte < char0 || charByte > char9) && charByte != charDot && charByte != charComma && charByte != charZ)
                {
                    throw new Asn1DecodingException("Invalid byte when decoding GeneralizedTime: 0x" + charByte.ToString("X2"));
                }

                if (charByte == charZ)
                {
                    isUtc = true;
                    break;
                }

                // YYYY MM DD HH MM SS
                // 0123 45 67 89 01 2345678
                // 2018 08 07 13 44 28.1234
                switch (state)
                {
                    case DecodeState.Year:
                        if (charByte == charDot || charByte == charComma)
                        {
                            throw new Asn1DecodingException("Encountered a decimal separator in the YEAR portion of GeneralizedTime.");
                        }
                        else if (charByte >= char0 || charByte <= char9)
                        {
                            var val = charByte - char0;
                            year = (year * 10) + val;
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the YEAR portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }

                        if (i == 3)
                        {
                            state = DecodeState.Month;
                        }

                        break;
                    case DecodeState.Month:
                        if (charByte == charDot || charByte == charComma)
                        {
                            throw new Asn1DecodingException("Encountered a decimal separator in the MONTH portion of GeneralizedTime.");
                        }
                        else if (charByte >= char0 || charByte <= char9)
                        {
                            var val = charByte - char0;
                            month = (month * 10) + val;
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the MONTH portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }

                        if (i == 5)
                        {
                            state = DecodeState.Day;
                        }
                        break;
                    case DecodeState.Day:
                        if (charByte == charDot || charByte == charComma)
                        {
                            throw new Asn1DecodingException("Encountered a decimal separator in the DAY portion of GeneralizedTime.");
                        }
                        else if (charByte >= char0 || charByte <= char9)
                        {
                            var val = charByte - char0;
                            day = (day * 10) + val;
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the DAY portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }

                        if (i == 7)
                        {
                            state = DecodeState.Hour;
                        }
                        break;
                    case DecodeState.Hour:
                        if (charByte >= char0 || charByte <= char9)
                        {
                            var val = charByte - char0;
                            hour = (hour * 10) + val;
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the HOUR portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }

                        if (i == 9)
                        {
                            state = DecodeState.DoneParsingHour;
                        }
                        break;
                    case DecodeState.DoneParsingHour:
                        if (charByte == charDot || charByte == charComma)
                        {
                            isFractionalHour = true;
                            state = DecodeState.Fraction;
                            break;
                        }
                        else
                        {
                            state = DecodeState.Minute;
                            goto case DecodeState.Minute;
                        }
                    case DecodeState.Minute:
                        if (charByte >= char0 || charByte <= char9)
                        {
                            var val = charByte - char0;
                            minute = (minute * 10) + val;
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the MINUTE portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }

                        if (i == 11)
                        {
                            state = DecodeState.DoneParsingMinute;
                        }
                        break;
                    case DecodeState.DoneParsingMinute:
                        if (charByte == charDot || charByte == charComma)
                        {
                            isFractionalMinute = true;
                            state = DecodeState.Fraction;
                            break;
                        }
                        else
                        {
                            state = DecodeState.Second;
                            goto case DecodeState.Second;
                        }
                    case DecodeState.Second:
                        if (charByte == charDot || charByte == charComma)
                        {
                            state = DecodeState.Fraction;
                        }
                        else if (charByte >= char0 || charByte <= char9)
                        {
                            var val = charByte - char0;
                            second = (second * 10) + val;
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the SECOND portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }

                        if (i == 13)
                        {
                            state = DecodeState.DoneParsingSecond;
                        }
                        break;
                    case DecodeState.DoneParsingSecond:
                        if (charByte != charDot && charByte != charComma) // Z is already checked above
                        {
                            throw new Asn1DecodingException("Unexpected character after parsing seconds, expected decimal separator or Z, but found: " + (char)charByte);
                        }
                        state = DecodeState.Fraction;
                        break;
                    case DecodeState.Fraction:
                        if (charByte == charDot || charByte == charComma)
                        {
                            throw new Asn1DecodingException("Encountered more than one decimal separator in the GeneralizedTime.");
                        }
                        else if (charByte >= char0 || charByte <= char9)
                        {
                            // At some point, there's just no point getting more decimal digits
                            // If someone really needs that, they can grab the ByteValue() and parse themselves.
                            if (fractionDivisor < 1000000000)
                            {
                                var val = charByte - char0;
                                var fractionalVal = val / fractionDivisor;
                                fraction += fractionalVal;
                                fractionDivisor *= 10;
                            }
                        }
                        else
                        {
                            throw new Asn1DecodingException("Invalid byte when decoding the FRACTION portion of GeneralizedTime: 0x" + charByte.ToString("X2"));
                        }
                        break;
                }
            }

            if (isFractionalHour)
            {
                // 3600 Seconds
                // 60 Minutes
                var val = 3600 * fraction;

                int secs = 0;
                int mins = 0;
                while (val >= 60)
                {
                    mins++;
                    val -= 60;
                }
                secs = (int)Math.Floor(val);
                val -= secs;

                minute = mins;
                second = secs;
                millisecond = (int)Math.Round(val * 1000, 0);
            }
            else if (isFractionalMinute)
            {
                // 60 Seconds
                var val = 60 * fraction;
                int secs = 0;
                secs = (int)Math.Floor(val);
                val -= secs;
                second = secs;
                millisecond = (int)Math.Round(val * 1000, 0);
            }
            else
            {
                millisecond = (int)Math.Round(fraction * 1000, 0);
            }

            var dt = new DateTime(year, month, day, hour, minute, second, millisecond, isUtc ? DateTimeKind.Utc : DateTimeKind.Local);
            GeneralizedTime = dt;
        }

        private enum DecodeState
        {
            Year,
            Month,
            Day,
            Hour,
            DoneParsingHour,
            Minute,
            DoneParsingMinute,
            Second,
            Fraction,
            DoneParsingSecond
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }

        protected override string ToStringName => "GENERALIZED TIME: ";
    }
}
