using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Verifier class for signature verification in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
    public class PkixVerifierFactory : IVerifierFactory<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algID;
        private readonly IVerifierFactory<IParameters<Algorithm>> baseFactory;

        /// <summary>
        /// Base constructor.
        /// </summary>
        public PkixVerifierFactory(AlgorithmIdentifier algorithm, IVerifierFactory<IParameters<Algorithm>> baseFactory)
        {
            this.algID = algorithm;
            this.baseFactory = baseFactory;
        }

        /// <summary>
        /// Return the algorithm details for the wrapped verifier factory object as an AlgorithmIdentifier object.
        /// </summary>
        public AlgorithmIdentifier AlgorithmDetails
        {
            get { return this.algID; }
        }

        /// <summary>
        /// Return a calculator generated from the wrapped verifier factory object.
        /// </summary>
        /// <returns>A calculator to use for verifying a signature</returns>
        public IStreamCalculator<IVerifier> CreateCalculator()
        {
            return baseFactory.CreateCalculator();
        }
    }
}
