
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Operators.Parameters
{
    public class Pkcs12MacAlgDescriptor
    {
        private readonly AlgorithmIdentifier mDigestAlg;
        private readonly byte[] mSalt;
        private readonly int mIterationCount;

        public Pkcs12MacAlgDescriptor(AlgorithmIdentifier digestAlg, byte[] iv, int iterationCount)
        {
            this.mDigestAlg = digestAlg;
            this.mSalt = Arrays.Clone(iv);
            this.mIterationCount = iterationCount;
        }

        public byte[] GetIV()
        {
            return Arrays.Clone(mSalt);
        }

        public int IterationCount
        {
            get { return mIterationCount; }
        }

        public AlgorithmIdentifier DigestAlgorithm { get { return mDigestAlg; } }
    }
}
