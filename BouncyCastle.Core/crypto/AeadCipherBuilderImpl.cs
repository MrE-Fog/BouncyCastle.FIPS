using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.IO;
using Org.BouncyCastle.Crypto.Internal.Modes;

using System.IO;


namespace Org.BouncyCastle.Crypto
{
    internal class AeadCipherBuilderImpl<TParams> : IAeadCipherBuilder<TParams> where TParams : IAuthenticationParameters<TParams, Algorithm>
    {
        private readonly bool isApprovedModeOnly;
        private readonly bool forEncryption;
        private readonly IAeadBlockCipher cipher;
        private readonly TParams parameters;

        internal AeadCipherBuilderImpl(bool forEncryption, TParams parameters, IAeadBlockCipher cipher)
        {
            this.isApprovedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.forEncryption = forEncryption;
            this.parameters = parameters;
            this.cipher = cipher;
        }

        public TParams AlgorithmDetails { get { return parameters; } }

        public int BlockSize { get { return cipher.GetBlockSize(); } }

        public int GetMaxOutputSize(int inputLen)
        {
            return cipher.GetOutputSize(inputLen);
        }

        public IAeadCipher BuildAeadCipher(AeadUsage usage, Stream stream)
        {
            CryptoServicesRegistrar.ApprovedModeCheck(isApprovedModeOnly, parameters.Algorithm.Name);

            return new AeadCipherImpl(parameters.MacSizeInBits, cipher, new CipherStream(stream, new BufferedAeadBlockCipher(cipher)));
        }

        public ICipher BuildCipher(Stream stream)
        {
            CryptoServicesRegistrar.ApprovedModeCheck(isApprovedModeOnly, parameters.Algorithm.Name);

            return new AeadCipherImpl(parameters.MacSizeInBits, cipher, new CipherStream(stream, new BufferedAeadBlockCipher(cipher)));
        }
    }
}
