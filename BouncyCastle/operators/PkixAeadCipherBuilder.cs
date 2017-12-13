using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

using System.IO;


namespace Org.BouncyCastle.Operators
{
    internal class PkixAeadCipherBuilder : IAeadCipherBuilder<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algDetails;
        private readonly IAeadCipherBuilder<IParameters<Algorithm>> baseBlockCipherBuilder;

        internal PkixAeadCipherBuilder(AlgorithmIdentifier algDetails, IAeadCipherBuilder<IParameters<Algorithm>> baseCipherBuilder)
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

        public IAeadCipher BuildAeadCipher(AeadUsage usage, Stream stream)
        {
            return baseBlockCipherBuilder.BuildAeadCipher(usage, stream);
        }

        public ICipher BuildCipher(Stream stream)
        {
            return baseBlockCipherBuilder.BuildCipher(stream);
        }
    }
}
