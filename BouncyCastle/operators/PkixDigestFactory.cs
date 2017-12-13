using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class PkixDigestFactory : IDigestFactory<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algorithmID;
        private readonly IDigestFactory<FipsShs.Parameters> digestFact;

        public PkixDigestFactory(AlgorithmIdentifier algorithmID)
        {
            this.algorithmID = algorithmID;
            this.digestFact = CryptoServicesRegistrar.CreateService((FipsShs.Parameters)Utils.digestTable[algorithmID.Algorithm]);
        }

        public AlgorithmIdentifier AlgorithmDetails
        {
            get
            {
                return algorithmID;
            }
        }

        public int DigestLength
        {
            get
            {
                return digestFact.DigestLength;
            }
        }

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return digestFact.CreateCalculator();
        }
    }
}
