using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Paddings;
using System.IO;

namespace Org.BouncyCastle.Operators
{
    internal class PkixBlockCipherBuilder : ICipherBuilder<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algDetails;
        private readonly IBlockCipherBuilder<IParameters<Algorithm>> baseBlockCipherBuilder;

        internal PkixBlockCipherBuilder(AlgorithmIdentifier algDetails, IBlockCipherBuilder<IParameters<Algorithm>> baseCipherBuilder)
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
            return baseBlockCipherBuilder.BuildPaddedCipher(stream, new Pkcs7Padding());
        }
    }
}
