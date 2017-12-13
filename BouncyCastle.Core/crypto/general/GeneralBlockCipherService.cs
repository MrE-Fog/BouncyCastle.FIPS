using System;

namespace Org.BouncyCastle.Crypto.General
{
    internal class GeneralBlockCipherService<TProv,TProvWithIV>
        : IAeadBlockCipherService
    {
        private readonly TProv prov;
        private readonly TProvWithIV provWithIV;

        internal GeneralBlockCipherService(TProv prov, TProvWithIV provWithIV)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("attempt to create non-approved service in approved only mode");
            }

            this.prov = prov;
            this.provWithIV = provWithIV;
        }

        public IBlockCipherBuilder<A> CreateBlockDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            if (algorithmDetails is IParametersWithIV<IParameters<GeneralAlgorithm>, GeneralAlgorithm>)
            {
                return ((IBlockDecryptorBuilderProvider<A>)provWithIV).CreateBlockDecryptorBuilder(algorithmDetails);
            }
            return ((IBlockDecryptorBuilderProvider<A>)prov).CreateBlockDecryptorBuilder(algorithmDetails);
        }

        public IBlockCipherBuilder<A> CreateBlockEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            if (algorithmDetails is IParametersWithIV<IParameters<GeneralAlgorithm>, GeneralAlgorithm>)
            {
                return ((IBlockEncryptorBuilderProvider<A>)provWithIV).CreateBlockEncryptorBuilder(algorithmDetails);
            }
            return ((IBlockEncryptorBuilderProvider<A>)prov).CreateBlockEncryptorBuilder(algorithmDetails);
        }

        public ICipherBuilder<A> CreateDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            if (algorithmDetails is IParametersWithIV<IParameters<GeneralAlgorithm>, GeneralAlgorithm>)
            {
                return ((IDecryptorBuilderProvider<A>)provWithIV).CreateDecryptorBuilder(algorithmDetails);
            }
            return ((IDecryptorBuilderProvider<A>)prov).CreateDecryptorBuilder(algorithmDetails);
        }

        public ICipherBuilder<A> CreateEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            if (algorithmDetails is IParametersWithIV<IParameters<GeneralAlgorithm>, GeneralAlgorithm>)
            {
                return ((IEncryptorBuilderProvider<A>)provWithIV).CreateEncryptorBuilder(algorithmDetails);
            }
            return ((IEncryptorBuilderProvider<A>)prov).CreateEncryptorBuilder(algorithmDetails);
        }

        public IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails) where A : ISymmetricWrapParameters<A, Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            return ((IKeyUnwrapperProvider<A>)prov).CreateKeyUnwrapper(algorithmDetails);
        }

        public IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails) where A : ISymmetricWrapParameters<A, Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            return ((IKeyWrapperProvider<A>)prov).CreateKeyWrapper(algorithmDetails);
        }

        public IMacFactory<A> CreateMacFactory<A>(A algorithmDetails) where A : IAuthenticationParameters<A, Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            if (algorithmDetails is IAuthenticationParametersWithIV<A, Algorithm>)
            {
                return ((IMacFactoryProvider<A>)provWithIV).CreateMacFactory(algorithmDetails);
            }

            return ((IMacFactoryProvider<A>)prov).CreateMacFactory(algorithmDetails);
        }

        public IAeadCipherBuilder<A> CreateAeadDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            return ((IAeadDecryptorBuilderProvider<A>)provWithIV).CreateAeadDecryptorBuilder(algorithmDetails);
        }

        public IAeadCipherBuilder<A> CreateAeadEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
        {
            CryptoServicesRegistrar.ApprovedModeCheck(false, "Service");

            return ((IAeadEncryptorBuilderProvider<A>)provWithIV).CreateAeadEncryptorBuilder(algorithmDetails);
        }
    }
}
