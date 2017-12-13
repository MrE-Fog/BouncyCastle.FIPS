using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class PkixDigestFactoryProvider : IDigestFactoryProvider<AlgorithmIdentifier>
    {
        public PkixDigestFactoryProvider()
        {
        }

        public IDigestFactory<AlgorithmIdentifier> CreateDigestFactory(AlgorithmIdentifier algorithmDetails)
        {
            return new PkixDigestFactory(algorithmDetails);
        }
    }
}
