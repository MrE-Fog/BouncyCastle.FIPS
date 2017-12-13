using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Modes;

namespace Org.BouncyCastle.Crypto.General
{
	internal class GeneralIVBlockCipherProvider<TParamWithIV, TAuthParamWithIV>
        :   IBlockDecryptorBuilderProvider<TParamWithIV>, IBlockEncryptorBuilderProvider<TParamWithIV>,
            IDecryptorBuilderProvider<TParamWithIV>, IEncryptorBuilderProvider<TParamWithIV>,
            IAeadDecryptorBuilderProvider<TAuthParamWithIV>, IAeadEncryptorBuilderProvider<TAuthParamWithIV>,
            IMacFactoryProvider<TAuthParamWithIV>
		where TParamWithIV: ParametersWithIV<TParamWithIV, GeneralAlgorithm> 
        where TAuthParamWithIV : AuthenticationParametersWithIV<TAuthParamWithIV, GeneralAlgorithm>
    {
		private readonly string name;

		internal readonly IEngineProvider<Org.BouncyCastle.Crypto.Internal.IBlockCipher> engineProvider;

		internal GeneralIVBlockCipherProvider (string name, IEngineProvider<Org.BouncyCastle.Crypto.Internal.IBlockCipher> engineProvider)
		{
			CryptoStatus.IsReady ();

			if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
				throw new CryptoUnapprovedOperationError("attempt to create provider for unapproved algorithm in approved only mode");
			}

			this.name = name;
			this.engineProvider = engineProvider;
		}

		internal EngineUsage getUsage(bool forEncryption)
		{
			return (forEncryption) ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
		}

        public ICipherBuilder<TParamWithIV> CreateDecryptorBuilder(TParamWithIV parameters)
        {
            return DoCreateCipherBuilder(false, parameters);
        }

        public ICipherBuilder<TParamWithIV> CreateEncryptorBuilder(TParamWithIV parameters)
        {
            return DoCreateCipherBuilder(true, parameters);
        }

        private ICipherBuilder<TParamWithIV> DoCreateCipherBuilder(bool forEncryption, TParamWithIV parameters)
		{
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("attempt to create unapproved cipher builder in approved only mode");
            }

            IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher (name, parameters.Algorithm.Mode, parameters, forEncryption, engineProvider);
            cipher.Init(forEncryption, ParametersWithIV.ApplyOptionalIV(null, parameters.GetIV()));
            return new CipherBuilderImpl<TParamWithIV> (parameters, cipher);
		}

        public IMacFactory<TAuthParamWithIV> CreateMacFactory(TAuthParamWithIV parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("attempt to create unapproved MAC factory in approved only mode");
            }

            IEngineProvider<IMac> macProvider = ProviderUtils.CreateMacProvider(name, parameters, engineProvider);

            return new MacFactory<TAuthParamWithIV>(parameters, macProvider, (parameters.MacSizeInBits + 7) / 8);
        }

        public IBlockCipherBuilder<TParamWithIV> CreateBlockEncryptorBuilder(TParamWithIV parameters)
        {
            return DoCreateBlockCipherBuilder(true, parameters);
        }

        public IBlockCipherBuilder<TParamWithIV> CreateBlockDecryptorBuilder(TParamWithIV parameters)
        {
            return DoCreateBlockCipherBuilder(false, parameters);
        }

        private IBlockCipherBuilder<TParamWithIV> DoCreateBlockCipherBuilder(bool forEncryption, TParamWithIV parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("attempt to create unapproved block cipher builder in approved only mode");
            }

            IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher(name, parameters.Algorithm.Mode, parameters, forEncryption, engineProvider);
            cipher.Init(forEncryption, ParametersWithIV.ApplyOptionalIV(null, parameters.GetIV()));
            return new BlockCipherBuilderImpl<TParamWithIV>(forEncryption, parameters, cipher);
        }

        public IAeadCipherBuilder<TAuthParamWithIV> CreateAeadEncryptorBuilder(TAuthParamWithIV parameters)
        {
            return DoCreateAeadCipherBuilder(true, parameters);
        }

        public IAeadCipherBuilder<TAuthParamWithIV> CreateAeadDecryptorBuilder(TAuthParamWithIV parameters)
        {
            return DoCreateAeadCipherBuilder(false, parameters);
        }

        private IAeadCipherBuilder<TAuthParamWithIV> DoCreateAeadCipherBuilder(bool forEncryption, TAuthParamWithIV parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("attempt to create unapproved AEAD cipher builder in approved only mode");
            }

            IAeadBlockCipher cipher = ProviderUtils.CreateAeadCipher(name, parameters.Algorithm.Mode, parameters, false, engineProvider);

            cipher.Init(forEncryption, new AeadParameters(null, parameters.MacSizeInBits, parameters.GetIV()));

            return new AeadCipherBuilderImpl<TAuthParamWithIV>(forEncryption, parameters, cipher);
        }
    }
}

