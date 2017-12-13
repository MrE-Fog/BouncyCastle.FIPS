using Org.BouncyCastle.Cms;
using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Operators
{
    public class PkixSignerInformationVerifierProvider : ISignerInformationVerifierProvider
    {
        private X509Certificate certificate;
        private readonly IAsymmetricPublicKey publicKey;

        public PkixSignerInformationVerifierProvider(IAsymmetricPublicKey publicKey)
        {
            this.publicKey = publicKey;
            this.certificate = null;
        }

        public PkixSignerInformationVerifierProvider(X509Certificate cert)
        {
            this.publicKey = cert.GetPublicKey();
            this.certificate = cert;
        }

        public bool IsRawSigner
        {
            get
            {
                return false;
            }
        }

        public IDigestFactory<AlgorithmIdentifier> CreateDigestFactory(AlgorithmIdentifier digestAlgorithmID)
        {
            return new PkixDigestFactory(digestAlgorithmID);
        }

        public IVerifierFactory<AlgorithmIdentifier> CreateVerifierFactory(AlgorithmIdentifier signatureAlgorithmID, AlgorithmIdentifier digestAlgorithmID)
        {
            IVerifierFactory<IParameters<Algorithm>> baseVerifier;

            AsymmetricRsaPublicKey rsaKey = publicKey as AsymmetricRsaPublicKey;
            if (rsaKey != null)
            {
                IVerifierFactoryService verifierService = CryptoServicesRegistrar.CreateService(rsaKey);

                if (signatureAlgorithmID.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
                {
                    FipsRsa.PssSignatureParameters pssParams = FipsRsa.Pss;
                    RsassaPssParameters sigParams = RsassaPssParameters.GetInstance(signatureAlgorithmID.Parameters);

                    pssParams = pssParams.WithDigest((FipsDigestAlgorithm)Utils.digestTable[sigParams.HashAlgorithm.Algorithm]);
                    AlgorithmIdentifier mgfDigAlg = AlgorithmIdentifier.GetInstance(AlgorithmIdentifier.GetInstance(sigParams.MaskGenAlgorithm).Parameters);
                    pssParams = pssParams.WithMgfDigest((FipsDigestAlgorithm)Utils.digestTable[mgfDigAlg.Algorithm]);

                    pssParams = pssParams.WithSaltLength(sigParams.SaltLength.Value.IntValue);

                    return CreateVerifierFactory(signatureAlgorithmID, verifierService.CreateVerifierFactory(pssParams), certificate);
                }
                else if (PkixVerifierFactoryProvider.pkcs1Table.Contains(signatureAlgorithmID.Algorithm))
                {
                    FipsRsa.SignatureParameters rsaParams = FipsRsa.Pkcs1v15.WithDigest((FipsDigestAlgorithm)PkixVerifierFactoryProvider.pkcs1Table[signatureAlgorithmID.Algorithm]);

                    return CreateVerifierFactory(signatureAlgorithmID, verifierService.CreateVerifierFactory(rsaParams), certificate);
                }
                else if (signatureAlgorithmID.Algorithm.Equals(PkcsObjectIdentifiers.RsaEncryption))
                {
                    FipsRsa.SignatureParameters rsaParams = FipsRsa.Pkcs1v15.WithDigest((FipsDigestAlgorithm)Utils.digestTable[digestAlgorithmID.Algorithm]);

                    return CreateVerifierFactory(signatureAlgorithmID, verifierService.CreateVerifierFactory(rsaParams), certificate);
                }
            }
            
            throw new ArgumentException("cannot match signature algorithm: " + signatureAlgorithmID.Algorithm);
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
