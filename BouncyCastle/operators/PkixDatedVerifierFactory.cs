using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Verifier class for signature verification in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details which is also backed by a certificate.
    /// </summary>
    public class PkixDatedVerifierFactory : IDatedVerifierFactory<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algID;
        private readonly IVerifierFactory<IParameters<Algorithm>> baseFactory;
        private readonly X509Certificate certificate;

        /// <summary>
        /// Base constructor.
        /// </summary>
        public PkixDatedVerifierFactory(AlgorithmIdentifier algorithm, IVerifierFactory<IParameters<Algorithm>> baseFactory, X509Certificate certificate)
        {
            this.algID = algorithm;
            this.baseFactory = baseFactory;
            this.certificate = certificate;
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

        /// <summary>
        /// Check if the certificate this verifier is based on is valid at the passed in dateTime,
        /// returning true if it is.
        /// </summary>
        /// <param name="dateTime">Time to check at.</param>
        /// <returns>true if our underlying certificate is valid, false otherwise.</returns>
        public bool IsValidAt(DateTime dateTime)
        {
            return certificate.IsValid(dateTime);
        }
    }
}
