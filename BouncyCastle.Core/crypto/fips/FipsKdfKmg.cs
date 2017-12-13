using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// A key material generator based around a KDF.
    /// </summary>
    public class FipsKdfKmg : IKMGenerator
    { 
        private readonly FipsKdf.AgreementKdfBuilder kdfBuilder;
        private readonly byte[] iv;
        private readonly int outputSize;

        /// <summary>
        /// Construct a KDF to process the agreed value with. The outputSize parameter determines how many bytes
        /// will be generated.
        /// </summary>
        /// <param name="kdfBuilder">KDF algorithm builder to use for parameter creation.</param>
        /// <param name="iv">The iv parameter for KDF initialization.</param>
        /// <param name="outputSize">The size of the output to be generated from the KDF.</param>
        public FipsKdfKmg(FipsKdf.AgreementKdfBuilderService kdfBuilder, byte[] iv, int outputSize)
        {
            this.kdfBuilder = CryptoServicesRegistrar.CreateService(kdfBuilder);
            this.iv = Arrays.Clone(iv);
            this.outputSize = outputSize;
        }

        /// <summary>
        /// Construct a KDF using the given PRF to process the agreed value with. The outputSize parameter determines how many bytes
        /// will be generated.
        /// </summary>
        /// <param name="kdfBuilder">KDF algorithm builder to use for parameter creation.</param>
        /// <param name="prf">The PRF to use in the KDF.</param>
        /// <param name="iv">The iv parameter for KDF initialization.</param>
        /// <param name="outputSize">The size of the output to be generated from the KDF.</param>
        public FipsKdfKmg(FipsKdf.AgreementKdfBuilderService kdfBuilder, FipsPrfAlgorithm prf, byte[] iv, int outputSize)
        {
            this.kdfBuilder = CryptoServicesRegistrar.CreateService(kdfBuilder).WithPrf(prf);
            this.iv = Arrays.Clone(iv);
            this.outputSize = outputSize;
        }

        /// <summary>
        /// Generate a byte array containing key material based on the passed in agreed value.
        /// </summary>
        /// <param name="agreed">The agreed value calculated during the agreement process.</param>
        /// <returns>A byte[] array containing the generated key material to use.</returns>
        public byte[] Generate(byte[] agreed)
        {
            IKdfCalculator<FipsKdf.AgreementKdfParameters> kdfCalculator = kdfBuilder.WithIV(iv).From(agreed);

            return kdfCalculator.GetResult(outputSize).Collect();
        }
    }
}
