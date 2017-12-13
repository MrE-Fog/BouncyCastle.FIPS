using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System.IO;

namespace Org.BouncyCastle.Operators
{
    internal class PkixCipherBuilder : ICipherBuilder<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algDetails;
        private readonly ICipherBuilder<IParameters<Algorithm>> baseBlockCipherBuilder;

        internal PkixCipherBuilder(AlgorithmIdentifier algDetails, ICipherBuilder<IParameters<Algorithm>> baseCipherBuilder)
        {
            this.algDetails = algDetails;
            this.baseBlockCipherBuilder = baseCipherBuilder;
        }

        public AlgorithmIdentifier AlgorithmDetails
        {
            get
            {
                return algDetails;
            }
        }

        public int GetMaxOutputSize(int inputLen)
        {
            return baseBlockCipherBuilder.GetMaxOutputSize(inputLen);
        }

        public ICipher BuildCipher(Stream stream)
        {
            return baseBlockCipherBuilder.BuildCipher(stream);
        }
    }
}
