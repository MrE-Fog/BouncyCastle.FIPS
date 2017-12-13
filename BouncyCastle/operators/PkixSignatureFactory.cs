using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System.Collections.Generic;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Calculator factory class for signature generation in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
	public class PkixSignatureFactory : ISignatureFactory<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algID;
        private readonly ISignatureFactory<IParameters<Algorithm>> baseFactory;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="baseFactory">The base factory to be used in the signing operation.</param>
        public PkixSignatureFactory(ISignatureFactory<IParameters<Algorithm>> baseFactory)
        {
            this.algID = Utils.GetSigAlgID(baseFactory.AlgorithmDetails);
            this.baseFactory = baseFactory;
        }

        /// <summary>
        /// Base constructor, using an string version of the algorithm name.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="baseFactory">The underlying signature factory used in this signature factory.</param>
		public PkixSignatureFactory(string algorithm, ISignatureFactory<IParameters<Algorithm>> baseFactory)
        {
            DerObjectIdentifier sigOid = Utils.GetAlgorithmOid(algorithm);

            this.algID = Utils.GetSigAlgID(sigOid, algorithm);
            this.baseFactory = baseFactory;
        }

        public PkixSignatureFactory(AlgorithmIdentifier algorithmIdentifier, ISignatureFactory<IParameters<Algorithm>> baseFactory)
        {
            this.algID = algorithmIdentifier;
            this.baseFactory = baseFactory;
        }

        /// <summary>
        /// Return the algorithm identifier representation for the signature factory.
        /// </summary>
        public AlgorithmIdentifier AlgorithmDetails
        {
            get { return this.algID; }
        }

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return baseFactory.CreateCalculator();
        }

        /// <summary>
        /// Return a collection of the signature names supported by the signature factory.
        /// </summary>
        public ICollection<string> SignatureAlgNames
        {
            get { return Utils.GetAlgNames(); }
        }
    }
}
