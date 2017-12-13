using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Operators;
using System.IO;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// A builder for the Pkcs#12 Pfx key and certificate store.
    /// </summary>
    public class Pkcs12PfxPduBuilder
    {
        private Asn1EncodableVector dataVector = new Asn1EncodableVector();

        /// <summary>
        /// Add a SafeBag that is to be included as is.
        /// </summary>
        /// <param name="data">the SafeBag to add.</param>
        /// <returns>this builder.</returns>
        public Pkcs12PfxPduBuilder AddData(Pkcs12SafeBag data)
        {
            dataVector.Add(new ContentInfo(PkcsObjectIdentifiers.Data, new DerOctetString(new DerSequence(data.ToAsn1Structure()).GetEncoded())));

            return this;
        }

        /// <summary>
        /// Add a SafeBag that is to be wrapped in a EncryptedData object.
        /// </summary>
        /// <param name="dataEncryptor">the encryptor to use for encoding the data.</param>
        /// <param name="data">the SafeBag to include.</param>
        /// <returns>this builder.</returns>
        public Pkcs12PfxPduBuilder AddEncryptedData(ICipherBuilder<AlgorithmIdentifier> dataEncryptor, Pkcs12SafeBag data)
        {
            return addEncryptedData(dataEncryptor, new DerSequence(data.ToAsn1Structure()));
        }

        /// <summary>
        /// Add a set of SafeBags that are to be wrapped in a EncryptedData object.
        /// </summary>
        /// <param name="dataEncryptor">The encryptor to use for encoding the data.</param>
        /// <param name="data">the SafeBags to include.</param>
        /// <returns>this builder.</returns>
        public Pkcs12PfxPduBuilder AddEncryptedData(ICipherBuilder<AlgorithmIdentifier> dataEncryptor, Pkcs12SafeBag[] data)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            for (int i = 0; i != data.Length; i++)
            {
                v.Add(data[i].ToAsn1Structure());
            }

            return addEncryptedData(dataEncryptor, new DerSequence(v));
        }

        private Pkcs12PfxPduBuilder addEncryptedData(ICipherBuilder<AlgorithmIdentifier> dataEncryptor, Asn1Sequence data)
        {
            CmsEncryptedDataGenerator envGen = new CmsEncryptedDataGenerator();

            try
            {
                dataVector.Add(envGen.generate(new CmsProcessableByteArray(data.GetEncoded()), dataEncryptor).ToAsn1Structure());
            }
            catch (CmsException e)
            {
                throw new PkcsIOException(e.Message, e.InnerException);
            }

            return this;
        }

        /// <summary>
        /// Build the Pfx structure, protecting it with a MAC calculated against the passed in password.
        /// </summary>
        /// <param name="macCalcFactory">a builder for a Pkcs12 mac calculator.</param>
        /// <returns>A Pfx object.</returns>
        public Pkcs12PfxPdu Build(IMacFactory<Pkcs12MacAlgDescriptor> macCalcFactory)
        {
            AuthenticatedSafe auth = AuthenticatedSafe.GetInstance(new DerSequence(dataVector));
            byte[] encAuth;

            try
            {
                encAuth = auth.GetEncoded();
            }
            catch (IOException e)
            {
                throw new PkcsException("unable to encode AuthenticatedSafe: " + e.Message, e);
            }

            ContentInfo mainInfo = new ContentInfo(PkcsObjectIdentifiers.Data, new DerOctetString(encAuth));
            MacData mData = null;

            if (macCalcFactory != null)
            {
                mData = PkcsUtilities.CreateMacData(macCalcFactory, encAuth);
            }

            //
            // output the Pfx
            //
            Pfx pfx = new Pfx(mainInfo, mData);

            return new Pkcs12PfxPdu(pfx);
        }
    }
}
