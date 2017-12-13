
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Builder for factories producing PBE based MAC calculators PKCS#12 style.
    /// </summary>
    public class Pkcs12MacFactoryBuilder
    {
        private readonly DigestAlgorithm prf;

        private byte[] salt = new byte[0];
        private int iterationCount = 1024;

        /// <summary>
        /// Base constructor - default SHA-1
        /// </summary>
        public Pkcs12MacFactoryBuilder(): this(FipsShs.Sha1)
        {

        }

        /// <summary>
        /// Constructor specifying the particular digest to use.
        /// </summary>
        /// <param name="digest">Digest to use as the basis of the MAC algorithm</param>
        public Pkcs12MacFactoryBuilder(DigestAlgorithm digest)
        {
            this.prf = digest;
        }

        /// <summary>
        /// Set the initialisation vector for the underlying key deriviation used.
        /// </summary>
        /// <param name="iv">IV or salt for key derivation</param>
        /// <returns>The current builder.</returns>
        public Pkcs12MacFactoryBuilder WithIV(byte[] iv)
        {
            this.salt = Arrays.Clone(salt);

            return this;
        }

        /// <summary>
        /// Set the iteration count for the underlying key deriviation used.
        /// </summary>
        /// <param name="iterationCount"></param>
        /// <returns>The current builder.</returns>
        public Pkcs12MacFactoryBuilder WithIterationCount(int iterationCount)
        {
            this.iterationCount = iterationCount;

            return this;
        }

        /// <summary>
        /// Build a MAC factory based on the current configuration, keyed using password.
        /// </summary>
        /// <param name="password">the password to derive the MAC key from.</param>
        /// <returns>a new MAC factory for PKCS#12</returns>
        public IMacFactory<Pkcs12MacAlgDescriptor> Build(char[] password)
        {
            IPasswordBasedDeriver<Pbkd.PbkdParameters> deriver = CryptoServicesRegistrar.CreateService(Pbkd.Pkcs12).From(PasswordConverter.PKCS12, password)
                .WithPrf(prf).WithSalt(salt).WithIterationCount(iterationCount).Build();

            return new Pkcs12MacFactory(new Pkcs12MacAlgDescriptor((AlgorithmIdentifier)Utils.pkcs12MacAlgIds[prf], salt, iterationCount), password);
        }
    }
}
