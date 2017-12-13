using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Pkcs
{
    /**
     * A holding class for the Pkcs12 Pfx structure.
     */
    public class Pkcs12PfxPdu
    {
        private Pfx pfx;

        private static Pfx parseBytes(byte[] pfxEncoding)
        {
            try
            {
                return Pfx.GetInstance(Asn1Object.FromByteArray(pfxEncoding));
            }
            catch (ArgumentException e)
            {
                throw new PkcsIOException("malformed data: " + e.Message, e);
            }
        }

        public Pkcs12PfxPdu(Pfx pfx)
        {
            this.pfx = pfx;
        }

        public Pkcs12PfxPdu(byte[] pfx) : this(parseBytes(pfx))
        {
        }

        /**
         * Return the content infos in the AuthenticatedSafe contained in this Pfx.
         *
         * @return an array of ContentInfo.
         */
        public ContentInfo[] GetContentInfos()
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(Asn1OctetString.GetInstance(this.pfx.AuthSafe.Content).GetOctets());
            ContentInfo[] content = new ContentInfo[seq.Count];

            for (int i = 0; i != seq.Count; i++)
            {
                content[i] = ContentInfo.GetInstance(seq[i]);
            }

            return content;
        }

        /**
         * Return whether or not there is MAC attached to this file.
         *
         * @return true if there is, false otherwise.
         */
        public bool HasMac
        {
            get
            {
                return pfx.MacData != null;
            }
        }

        /**
         * Return the algorithm identifier describing the MAC algorithm
         *
         * @return the AlgorithmIdentifier representing the MAC algorithm, null if none present.
         */
        public AlgorithmIdentifier MacAlgorithmID
        {
            get
            {
                MacData md = pfx.MacData;

                if (md != null)
                {
                    return md.Mac.AlgorithmID;
                }

                return null;
            }
        }

        /**
         * Verify the MacData attached to the PFX is consistent with what is expected.
         *
         * @param macCalcProviderBuilder provider builder for the calculator for the MAC
         * @return true if mac data is valid, false otherwise.
         * @throws PkcsException if there is a problem evaluating the MAC.
         * @throws IllegalStateException if no MAC is actually present
         */
        public bool IsMacValid(IMacFactoryProvider<Pkcs12MacAlgDescriptor> macCalcProviderBuilder)
        {
            if (HasMac)
            {
                MacData pfxmData = pfx.MacData;
                IMacFactory<Pkcs12MacAlgDescriptor> mdFact = macCalcProviderBuilder.CreateMacFactory(new Pkcs12MacAlgDescriptor(pfxmData.Mac.AlgorithmID, pfxmData.GetSalt(), pfxmData.IterationCount.IntValue));

                try
                {
                    MacData mData = PkcsUtilities.CreateMacData(mdFact, Asn1OctetString.GetInstance(pfx.AuthSafe.Content).GetOctets());
                    
                    return Arrays.ConstantTimeAreEqual(mData.GetEncoded(), pfx.MacData.GetEncoded());
                }
                catch (IOException e)
                {
                    throw new PkcsException("unable to process AuthSafe: " + e.Message);
                }
            }

            throw new InvalidOperationException("no MAC present on PFX");
        }

        /**
         * Return the underlying ASN.1 object.
         *
         * @return a Pfx object.
         */
        public Pfx ToAsn1Structure()
        {
            return pfx;
        }

        public byte[] GetEncoded()
        {
            return ToAsn1Structure().GetEncoded();
        }

        /**
         * Return a Pfx with the outer wrapper encoded as asked for. For example, Pfx is a usually
         * a BER encoded object, to get one with DefiniteLength encoding use:
         * <pre>
         * getEncoded(Asn1Encoding.DL)
         * </pre>
         * @param encoding encoding style (Asn1Encoding.DER, Asn1Encoding.DL, Asn1Encoding.BER)
         * @return a byte array containing the encoded object.
         * @throws IOException
         */
        public byte[] GetEncoded(String encoding)
        {
            return ToAsn1Structure().GetEncoded(encoding);
        }
    }
}
