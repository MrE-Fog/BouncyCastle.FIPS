using System;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Modes;
using Org.BouncyCastle.Crypto.Internal.Wrappers;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto
{
	internal class ProviderUtils
	{
		public ProviderUtils ()
		{
		}

        private static EngineUsage GetUsage(bool forEncryption, AlgorithmMode algorithmMode)
        {
            switch (algorithmMode)
            {
                case AlgorithmMode.OFB64:
                case AlgorithmMode.OFB128:
                case AlgorithmMode.CFB8:
                case AlgorithmMode.CFB64:
                case AlgorithmMode.CFB128:
                case AlgorithmMode.OpenPGPCFB:
                case AlgorithmMode.CTR:
                case AlgorithmMode.GCM:
                case AlgorithmMode.CCM:
                    return EngineUsage.ENCRYPTION;
            }

            return forEncryption ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
        }

        internal static IAeadBlockCipher CreateAeadCipher(string name, AlgorithmMode algorithmMode, IParametersWithIV<IParameters<Algorithm>, Algorithm> parameters, bool forEncryption, IEngineProvider<Internal.IBlockCipher> cipherProvider)
        {
            Internal.IBlockCipher baseCipher = cipherProvider.CreateEngine(GetUsage(forEncryption, algorithmMode));

            switch (algorithmMode)
            {
                case AlgorithmMode.CCM:
                    return new CcmBlockCipher(baseCipher);
                case AlgorithmMode.GCM:
                    return new GcmBlockCipher(baseCipher);
                default:
                    throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
            }
        }

        internal static IBufferedCipher CreateBufferedCipher(string name, AlgorithmMode algorithmMode, IParametersWithIV<IParameters<Algorithm>, Algorithm> parameters, bool forEncryption, IEngineProvider<Internal.IBlockCipher> cipherProvider)
		{
            Internal.IBlockCipher baseCipher = cipherProvider.CreateEngine(GetUsage(forEncryption, algorithmMode));
			Internal.IBlockCipher cipher;

			switch (algorithmMode)
			{
			case AlgorithmMode.CBC:
				cipher = new CbcBlockCipher(baseCipher);
				break;
            case AlgorithmMode.CS1:
                return new NistCtsBlockCipher(NistCtsBlockCipher.CS1, baseCipher);
            case AlgorithmMode.CS2:
                return new NistCtsBlockCipher(NistCtsBlockCipher.CS2, baseCipher);
            case AlgorithmMode.CS3:
                return new NistCtsBlockCipher(NistCtsBlockCipher.CS3, baseCipher);
            case AlgorithmMode.CFB8:
				cipher = new CfbBlockCipher (baseCipher, 8);
				break;
			case AlgorithmMode.CFB64:
				cipher = new CfbBlockCipher (baseCipher, 64);
				break;
            case AlgorithmMode.CFB128:
                cipher = new CfbBlockCipher(baseCipher, 128);
                break;
            case AlgorithmMode.OpenPGPCFB:
                cipher = new OpenPgpCfbBlockCipher(baseCipher);
                break;
            case AlgorithmMode.OFB64:
			    cipher = new OfbBlockCipher (baseCipher, 64);
			    break;
			case AlgorithmMode.OFB128:
				cipher = new OfbBlockCipher (baseCipher, 128);
				break;
            case AlgorithmMode.CTR:
                cipher = new SicBlockCipher(baseCipher);
                break;
            default:
				throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
			}

			return new BufferedBlockCipher(cipher);
		}

		internal static IBufferedCipher CreateBufferedCipher(string name, AlgorithmMode algorithmMode, IParameters<Algorithm> parameters, Org.BouncyCastle.Crypto.Internal.IBlockCipher baseCipher)
		{
            Org.BouncyCastle.Crypto.Internal.IBlockCipher cipher;

			switch (algorithmMode)
			{
			case AlgorithmMode.ECB:
				cipher = baseCipher;
				break;
            default:
				throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
			}

			return new BufferedBlockCipher(cipher);
		}

        private static EngineUsage GetWrapUsage(bool useInverse, bool forWrapping)
        {
            if (useInverse)
            {
                return forWrapping ? EngineUsage.DECRYPTION : EngineUsage.ENCRYPTION;
            }
            else
            {
                return forWrapping ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
            }
        }

		internal static IWrapper CreateWrapper(string name, AlgorithmMode algorithmMode, bool useInverse, bool forWrapping, IEngineProvider<Internal.IBlockCipher> baseCipherProvider)
		{
            Internal.IBlockCipher baseCipher = baseCipherProvider.CreateEngine(GetWrapUsage(useInverse, forWrapping));
			IWrapper cipher;

			switch (algorithmMode)
			{
			case AlgorithmMode.WRAP:
				cipher = new SP80038FWrapEngine(baseCipher, useInverse);
				break;
			case AlgorithmMode.WRAPPAD:
				cipher = new SP80038FWrapWithPaddingEngine(baseCipher, useInverse);
				break;
			default:
				throw new ArgumentException("Unknown wrapper algorithm passed to " + name + ".Provider: " + algorithmMode);
			}

            cipher.Init(forWrapping, null);

			return cipher;
		}

        internal static IEngineProvider<IMac> CreateMacProvider(string name, IAuthenticationParameters<IParameters<Algorithm>, Algorithm> parameters, IEngineProvider<Org.BouncyCastle.Crypto.Internal.IBlockCipher> baseCipher)
        {
            switch (parameters.Algorithm.Mode)
            {
                case AlgorithmMode.CMAC:
                    return new CMacProvider(baseCipher, parameters);
                default:
                    throw new ArgumentException("Unknown MAC algorithm passed to " + name + ".Provider: " + parameters.Algorithm.Mode);
            }
        }

        internal static IEngineProvider<IMac> CreateMacProvider(string name, IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters, IEngineProvider<Org.BouncyCastle.Crypto.Internal.IBlockCipher> baseCipher)
        {
            switch (parameters.Algorithm.Mode)
            {
                case AlgorithmMode.CCM:
                    return new CcmMacProvider(baseCipher, parameters);
                case AlgorithmMode.GMAC:
                    return new GMacProvider(baseCipher, parameters);
                default:
                    throw new ArgumentException("Unknown MAC algorithm passed to " + name + ".Provider: " + parameters.Algorithm.Mode);
            }
        }

        private class CMacProvider : IEngineProvider<IMac>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> baseProvider;
            private readonly int macSizeInBits;

            internal CMacProvider(IEngineProvider<Internal.IBlockCipher> baseProvider, IAuthenticationParameters<IParameters<Algorithm>, Algorithm> parameters)
            {
                this.baseProvider = baseProvider;
                this.macSizeInBits = parameters.MacSizeInBits;
            }

            public IMac CreateEngine(EngineUsage usage)
            {
                IMac mac = new CMac(baseProvider.CreateEngine(EngineUsage.ENCRYPTION), macSizeInBits);

                mac.Init(null);

                return mac;
            }
        }

        private class GMacProvider : IEngineProvider<IMac>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> baseProvider;
            private readonly IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters;

            internal GMacProvider(IEngineProvider<Internal.IBlockCipher> baseProvider, IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters)
            {
                this.baseProvider = baseProvider;
                this.parameters = parameters; 
            }

            public IMac CreateEngine(EngineUsage usage)
            {
                IMac mac = new GMac(new GcmBlockCipher(baseProvider.CreateEngine(EngineUsage.ENCRYPTION)), parameters.MacSizeInBits);
                mac.Init(new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()));
                return mac;
            }
        }

        private class CcmMacProvider : IEngineProvider<IMac>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> baseProvider;
            private readonly IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters;

            internal CcmMacProvider(IEngineProvider<Internal.IBlockCipher> baseProvider, IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters)
            {
                this.baseProvider = baseProvider;
                this.parameters = parameters;
            }

            public IMac CreateEngine(EngineUsage usage)
            {
                IMac mac = new AeadCipherMac(new CcmBlockCipher(baseProvider.CreateEngine(EngineUsage.ENCRYPTION)), parameters.MacSizeInBits);
                mac.Init(new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()));
                return mac;
            }
        }
    }
}

