using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Provider class which supports dynamic creation of signature verifiers.
    /// </summary>
	public class PkixVerifierFactoryProvider : IVerifierFactoryProvider<AlgorithmIdentifier>
    {
        internal static readonly IDictionary pkcs1Table = Platform.CreateHashtable();
        internal static readonly IDictionary ecdsaTable = Platform.CreateHashtable();
        internal static readonly IDictionary dsaTable = Platform.CreateHashtable();

        static PkixVerifierFactoryProvider()
        {
            pkcs1Table.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption, FipsShs.Sha1);
            pkcs1Table.Add(PkcsObjectIdentifiers.Sha224WithRsaEncryption, FipsShs.Sha224);
            pkcs1Table.Add(PkcsObjectIdentifiers.Sha256WithRsaEncryption, FipsShs.Sha256);
            pkcs1Table.Add(PkcsObjectIdentifiers.Sha384WithRsaEncryption, FipsShs.Sha384);
            pkcs1Table.Add(PkcsObjectIdentifiers.Sha512WithRsaEncryption, FipsShs.Sha512);

            ecdsaTable.Add(X9ObjectIdentifiers.ECDsaWithSha1, FipsEC.Dsa.WithDigest(FipsShs.Sha1));
            ecdsaTable.Add(X9ObjectIdentifiers.ECDsaWithSha224, FipsEC.Dsa.WithDigest(FipsShs.Sha224));
            ecdsaTable.Add(X9ObjectIdentifiers.ECDsaWithSha256, FipsEC.Dsa.WithDigest(FipsShs.Sha256));
            ecdsaTable.Add(X9ObjectIdentifiers.ECDsaWithSha384, FipsEC.Dsa.WithDigest(FipsShs.Sha384));
            ecdsaTable.Add(X9ObjectIdentifiers.ECDsaWithSha512, FipsEC.Dsa.WithDigest(FipsShs.Sha512));

            dsaTable.Add(X9ObjectIdentifiers.IdDsaWithSha1, FipsDsa.Dsa.WithDigest(FipsShs.Sha1));
            dsaTable.Add(NistObjectIdentifiers.DsaWithSha224, FipsDsa.Dsa.WithDigest(FipsShs.Sha224));
            dsaTable.Add(NistObjectIdentifiers.DsaWithSha256, FipsDsa.Dsa.WithDigest(FipsShs.Sha256));
            dsaTable.Add(NistObjectIdentifiers.DsaWithSha384, FipsDsa.Dsa.WithDigest(FipsShs.Sha384));
            dsaTable.Add(NistObjectIdentifiers.DsaWithSha512, FipsDsa.Dsa.WithDigest(FipsShs.Sha512));
        }

        private readonly IAsymmetricPublicKey publicKey;
        private readonly X509Certificate certificate;

        /// <summary>
        /// Base constructor - specify the public key to be used in verification.
        /// </summary>
        /// <param name="publicKey">The public key to be used in creating verifiers provided by this object.</param>
		public PkixVerifierFactoryProvider(IAsymmetricPublicKey publicKey)
        {
            this.publicKey = publicKey;
            this.certificate = null;
        }

        /// <summary>
        /// Base constructor - specify the certificate containing the public key to be used in verification.
        /// </summary>
        /// <param name="certificate">The certificate holding the public key to be used.</param>
        public PkixVerifierFactoryProvider(X509Certificate certificate)
        {
            this.publicKey = certificate.GetPublicKey();
            this.certificate = certificate;
        }

        /// <summary>
        /// Return a verifier factory that produces verifiers conforming to algorithmDetails.
        /// </summary>
        /// <param name="algorithmDetails">The configuration parameters for verifiers produced by the resulting factory.</param>
        /// <returns>A new verifier factory.</returns>
        public IVerifierFactory<AlgorithmIdentifier> CreateVerifierFactory(AlgorithmIdentifier algorithmDetails)
        {
            AsymmetricRsaPublicKey rsaKey = publicKey as AsymmetricRsaPublicKey;
            if (rsaKey != null)
            {
                IVerifierFactoryService verifierService = CryptoServicesRegistrar.CreateService(rsaKey);

                if (algorithmDetails.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
                {
                    FipsRsa.PssSignatureParameters pssParams = FipsRsa.Pss;
                    RsassaPssParameters sigParams = RsassaPssParameters.GetInstance(algorithmDetails.Parameters);

                    pssParams = pssParams.WithDigest((FipsDigestAlgorithm)Utils.digestTable[sigParams.HashAlgorithm.Algorithm]);
                    AlgorithmIdentifier mgfDigAlg = AlgorithmIdentifier.GetInstance(AlgorithmIdentifier.GetInstance(sigParams.MaskGenAlgorithm).Parameters);
                    pssParams = pssParams.WithMgfDigest((FipsDigestAlgorithm)Utils.digestTable[mgfDigAlg.Algorithm]);

                    pssParams = pssParams.WithSaltLength(sigParams.SaltLength.Value.IntValue);

                    return CreateVerifierFactory(algorithmDetails, verifierService.CreateVerifierFactory(pssParams), certificate);
                }
                else if (pkcs1Table.Contains(algorithmDetails.Algorithm))
                {
                    FipsRsa.SignatureParameters rsaParams = FipsRsa.Pkcs1v15.WithDigest((FipsDigestAlgorithm)pkcs1Table[algorithmDetails.Algorithm]);

                    return CreateVerifierFactory(algorithmDetails, verifierService.CreateVerifierFactory(rsaParams), certificate);
                }
            }

            AsymmetricDsaPublicKey dsaKey = publicKey as AsymmetricDsaPublicKey;
            if (dsaKey != null)
            {
                IVerifierFactoryService verifierService = CryptoServicesRegistrar.CreateService(dsaKey);

                FipsDsa.SignatureParameters sigParams = (FipsDsa.SignatureParameters)dsaTable[algorithmDetails.Algorithm];

                return CreateVerifierFactory(algorithmDetails, verifierService.CreateVerifierFactory(sigParams), certificate);
            }

            AsymmetricECPublicKey ecdsaKey = publicKey as AsymmetricECPublicKey;
            if (ecdsaKey != null)
            {
                IVerifierFactoryService verifierService = CryptoServicesRegistrar.CreateService(ecdsaKey);

                FipsEC.SignatureParameters sigParams = (FipsEC.SignatureParameters)ecdsaTable[algorithmDetails.Algorithm];

                return CreateVerifierFactory(algorithmDetails, verifierService.CreateVerifierFactory(sigParams), certificate);
            }

            AsymmetricSphincsPublicKey sphincsKey = publicKey as AsymmetricSphincsPublicKey;
            if (sphincsKey != null)
            {
                IVerifierFactoryService verifierService = CryptoServicesRegistrar.CreateService(sphincsKey);
                if (algorithmDetails.Algorithm.Equals(BCObjectIdentifiers.sphincs256_with_SHA512))
                {
                    return CreateVerifierFactory(algorithmDetails, verifierService.CreateVerifierFactory(Sphincs.Sphincs256), certificate);
                }
                else
                {
                    return CreateVerifierFactory(algorithmDetails, verifierService.CreateVerifierFactory(Sphincs.Sphincs256.WithDigest(FipsShs.Sha3_512)), certificate);
                } 
            }

            throw new ArgumentException("cannot match signature algorithm");
        }

        private IVerifierFactory<AlgorithmIdentifier> CreateVerifierFactory(AlgorithmIdentifier algorithm, IVerifierFactory<IParameters<Algorithm>> baseFactory, X509Certificate certificate)
        {
            if (certificate != null)
            {
                return new PkixDatedVerifierFactory(algorithm, baseFactory, certificate);
            }

            return new PkixVerifierFactory(algorithm, baseFactory);
        }
    }
}
