using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.General
{
    internal class GeneralBlockCipherProvider<TParam, TWrapParam, TAuthParam> :
            IKeyWrapperProvider<TWrapParam>, IKeyUnwrapperProvider<TWrapParam>,
            IMacFactoryProvider<TAuthParam>, IBlockDecryptorBuilderProvider<TParam>, IBlockEncryptorBuilderProvider<TParam>
            where TParam : Parameters<GeneralAlgorithm>
            where TWrapParam : ISymmetricWrapParameters<IParameters<GeneralAlgorithm>, GeneralAlgorithm>
            where TAuthParam : AuthenticationParameters<TAuthParam, GeneralAlgorithm>
    {
        private readonly string name;

        internal readonly IEngineProvider<Internal.IBlockCipher> engineProvider;

        internal GeneralBlockCipherProvider(string name, IEngineProvider<Internal.IBlockCipher> engineProvider)
        {
            CryptoStatus.IsReady();

            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("Attempt to create provider for unapproved algorithm in approved only mode");
            }

            this.name = name;
            this.engineProvider = engineProvider;
        }

        internal EngineUsage getUsage(bool forEncryption)
        {
            return (forEncryption) ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
        }

        public IKeyWrapper<TWrapParam> CreateKeyWrapper(TWrapParam parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("Attempt to create unapproved key wrapper in approved only mode");
            }

            IWrapper wrapper = ProviderUtils.CreateWrapper(name, parameters.Algorithm.Mode, parameters.IsUsingInverseFunction, true, engineProvider);

            return new KeyWrapperImpl<TWrapParam>(parameters, wrapper);
        }

        public IKeyUnwrapper<TWrapParam> CreateKeyUnwrapper(TWrapParam parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("Attempt to create unapproved key unwrapper in approved only mode");
            }

            IWrapper wrapper = ProviderUtils.CreateWrapper(name, parameters.Algorithm.Mode, parameters.IsUsingInverseFunction, false, engineProvider);

            return new KeyUnwrapperImpl<TWrapParam>(parameters, wrapper);
        }

        public IMacFactory<TAuthParam> CreateMacFactory(TAuthParam parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("Attempt to create unapproved MAC factory in approved only mode");
            }

            IEngineProvider<IMac> macProvider = ProviderUtils.CreateMacProvider(name, parameters, engineProvider);

            return new MacFactory<TAuthParam>(parameters, macProvider, (parameters.MacSizeInBits + 7) / 8);
        }

        public IBlockCipherBuilder<TParam> CreateBlockDecryptorBuilder(TParam parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("Attempt to create unapproved BlockCipherBuilder in approved only mode");
            }

            IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher(name, parameters.Algorithm.Mode, parameters, engineProvider.CreateEngine(EngineUsage.DECRYPTION));

            cipher.Init(false, null);

            return new BlockCipherBuilderImpl<TParam>(false, parameters, cipher);
        }

        public IBlockCipherBuilder<TParam> CreateBlockEncryptorBuilder(TParam parameters)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("Attempt to create unapproved BlockCipherBuilder in approved only mode");
            }

            IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher(name, parameters.Algorithm.Mode, parameters, engineProvider.CreateEngine(EngineUsage.ENCRYPTION));

            cipher.Init(true, null);

            return new BlockCipherBuilderImpl<TParam>(true, parameters, cipher);
        }
    }
}
