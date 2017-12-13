using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fips
{
    public class FipsDigestKmg
        : IKMGenerator
    {
        private readonly FipsDigestAlgorithm digestAlg;

        public FipsDigestKmg(FipsDigestAlgorithm digestAlg)
        {
            this.digestAlg = digestAlg;
        }

        internal FipsDigestAlgorithm Digest
        {
            get { return digestAlg; }
        }

        public byte[] Generate(byte[] agreed)
        {
            return Digests.DoFinal(FipsShs.CreateDigest(digestAlg), agreed, 0, agreed.Length);
        }
    }
}
