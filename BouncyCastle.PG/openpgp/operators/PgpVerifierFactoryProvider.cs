using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpVerifierFactoryProvider: IVerifierFactoryProvider<PgpSignatureTypeIdentifier>
    {
        private PgpPublicKey key;

        public PgpVerifierFactoryProvider(PgpPublicKey key)
        {
            this.key = key;
        }

        public IVerifierFactory<PgpSignatureTypeIdentifier> CreateVerifierFactory(PgpSignatureTypeIdentifier algorithmDetails)
        {
            return new VerifierFactory(algorithmDetails, getVerifier(key, algorithmDetails.HashAlgorithm));
        }

        private static IVerifierFactory<IParameters<Algorithm>> getVerifier(PgpPublicKey key, HashAlgorithmTag hashAlg)
        {
            return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)KeyFactory.ConvertPublic(key)).CreateVerifierFactory(FipsRsa.Pkcs1v15.WithDigest((FipsDigestAlgorithm)PgpUtils.digests[hashAlg]));
        }

        private class VerifierFactory : IVerifierFactory<PgpSignatureTypeIdentifier>
        {
            private PgpSignatureTypeIdentifier mAlgorithmDetails;
            private IVerifierFactory<IParameters<Algorithm>> verifierFactory;

            public VerifierFactory(PgpSignatureTypeIdentifier algorithmDetails, IVerifierFactory<IParameters<Algorithm>> verifierFactory)
            {
                this.mAlgorithmDetails = algorithmDetails;
                this.verifierFactory = verifierFactory;
            }

            public PgpSignatureTypeIdentifier AlgorithmDetails
            {
                get
                {
                    return mAlgorithmDetails;
                }
            }

            public IStreamCalculator<IVerifier> CreateCalculator()
            {
                return verifierFactory.CreateCalculator();
            }
        }
    }
}
