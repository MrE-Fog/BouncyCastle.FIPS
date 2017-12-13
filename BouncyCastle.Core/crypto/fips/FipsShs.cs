using System;
using System.Collections;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Digests;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for implementations of FIPS approved secure hash algorithms.
    /// </summary>
	public class FipsShs
	{
		internal static class Algorithm 
		{
			internal static readonly FipsDigestAlgorithm SHA1 = new FipsDigestAlgorithm("SHA-1");
			internal static readonly FipsDigestAlgorithm SHA1_HMAC = new FipsDigestAlgorithm("SHA-1", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA224 = new FipsDigestAlgorithm("SHA-224");
			internal static readonly FipsDigestAlgorithm SHA224_HMAC = new FipsDigestAlgorithm("SHA-224", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA256 = new FipsDigestAlgorithm("SHA-256");
			internal static readonly FipsDigestAlgorithm SHA256_HMAC = new FipsDigestAlgorithm("SHA-256", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA384 = new FipsDigestAlgorithm("SHA-384");
			internal static readonly FipsDigestAlgorithm SHA384_HMAC = new FipsDigestAlgorithm("SHA-384", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA512 = new FipsDigestAlgorithm("SHA-512");
			internal static readonly FipsDigestAlgorithm SHA512_HMAC = new FipsDigestAlgorithm("SHA-512", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA512_224 = new FipsDigestAlgorithm("SHA-512(224)");
			internal static readonly FipsDigestAlgorithm SHA512_224_HMAC = new FipsDigestAlgorithm("SHA-512(224)", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA512_256 = new FipsDigestAlgorithm("SHA-512(256)");
			internal static readonly FipsDigestAlgorithm SHA512_256_HMAC = new FipsDigestAlgorithm("SHA-512(256)", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA3_224 = new FipsDigestAlgorithm("SHA3-224");
			internal static readonly FipsDigestAlgorithm SHA3_256 = new FipsDigestAlgorithm("SHA3-256");
			internal static readonly FipsDigestAlgorithm SHA3_384 = new FipsDigestAlgorithm("SHA3-384");
			internal static readonly FipsDigestAlgorithm SHA3_512 = new FipsDigestAlgorithm("SHA3-512");

			internal static readonly FipsAlgorithm SHAKE128 = new FipsAlgorithm("SHAKE128");
			internal static readonly FipsAlgorithm SHAKE256 = new FipsAlgorithm("SHAKE256");
		}

        /// <summary>
        /// The SHA-1 Digest marker.
        /// </summary>
		public static readonly Parameters Sha1 = new Parameters(Algorithm.SHA1);

        /// <summary>
        /// The SHA-224 Digest marker.
        /// </summary>
        public static readonly Parameters Sha224 = new Parameters(Algorithm.SHA224);

        /// <summary>
        /// The SHA-256 Digest marker.
        /// </summary>
        public static readonly Parameters Sha256 = new Parameters(Algorithm.SHA256);

        /// <summary>
        /// The SHA-384 Digest marker.
        /// </summary>
        public static readonly Parameters Sha384 = new Parameters(Algorithm.SHA384);

        /// <summary>
        /// The SHA-512 Digest marker.
        /// </summary>
        public static readonly Parameters Sha512 = new Parameters(Algorithm.SHA512);

        /// <summary>
        /// The SHA512(224) Digest marker.
        /// </summary>
        public static readonly Parameters Sha512_224 = new Parameters(Algorithm.SHA512_224);

        /// <summary>
        /// The SHA512(256) Digest marker.
        /// </summary>
        public static readonly Parameters Sha512_256 = new Parameters(Algorithm.SHA512_256);

        /// <summary>
        /// The SHA3-224 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_224 = new Parameters(Algorithm.SHA3_224);

        /// <summary>
        /// The SHA3-256 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_256 = new Parameters(Algorithm.SHA3_256);

        /// <summary>
        /// The SHA3-384 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_384 = new Parameters(Algorithm.SHA3_384);

        /// <summary>
        /// The SHA3-512 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_512 = new Parameters(Algorithm.SHA3_512);

        /// <summary>
        /// The SHA-1 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha1HMac = new AuthenticationParameters(Algorithm.SHA1_HMAC, 160);

        /// <summary>
        /// The SHA-224 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha224HMac = new AuthenticationParameters(Algorithm.SHA224_HMAC, 224);

        /// <summary>
        /// The SHA-256 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha256HMac = new AuthenticationParameters(Algorithm.SHA256_HMAC, 256);

        /// <summary>
        /// The SHA-384 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha384HMac = new AuthenticationParameters(Algorithm.SHA384_HMAC, 384);
       
        /// <summary>
        /// The SHA-512 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha512HMac = new AuthenticationParameters(Algorithm.SHA512_HMAC, 512);

        /// <summary>
        /// The SHA-512(224) HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha512_224HMac = new AuthenticationParameters(Algorithm.SHA512_224_HMAC, 224);

        /// <summary>
        /// The SHA-512(256) HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha512_256HMac = new AuthenticationParameters(Algorithm.SHA512_256_HMAC, 256);

        /// <summary>
        /// The SHAKE128 parameters source.
        /// </summary>
		public static readonly XofParameters Shake128 = new XofParameters(Algorithm.SHAKE128);

        /// <summary>
        /// The SHAKE256 parameters source.
        /// </summary>
		public static readonly XofParameters Shake256 = new XofParameters(Algorithm.SHAKE256);

        private static readonly IDictionary digestProviders = Platform.CreateHashtable();
        private static readonly IDictionary xofProviders = Platform.CreateHashtable();
        private static readonly IDictionary hmacProviders = Platform.CreateHashtable();

        static FipsShs()
        {
            digestProviders[Sha1] = digestProviders[Sha1.Algorithm] = new Sha1DigestProvider();
            digestProviders[Sha224] = digestProviders[Sha224.Algorithm] = new Sha224DigestProvider();
            digestProviders[Sha256] = digestProviders[Sha256.Algorithm] = new Sha256DigestProvider();
            digestProviders[Sha384] = digestProviders[Sha384.Algorithm] = new Sha384DigestProvider();
            digestProviders[Sha512] = digestProviders[Sha512.Algorithm] = new Sha512DigestProvider();
            digestProviders[Sha512_224] = digestProviders[Sha512_224.Algorithm] = new Sha512_224DigestProvider();
            digestProviders[Sha512_256] = digestProviders[Sha512_256.Algorithm] = new Sha512_256DigestProvider();
            digestProviders[Sha3_224] = digestProviders[Sha3_224.Algorithm] = new Sha3_224DigestProvider();
            digestProviders[Sha3_256] = digestProviders[Sha3_256.Algorithm] = new Sha3_256DigestProvider();
            digestProviders[Sha3_384] = digestProviders[Sha3_384.Algorithm] = new Sha3_384DigestProvider();
            digestProviders[Sha3_512] = digestProviders[Sha3_512.Algorithm] = new Sha3_512DigestProvider();

            xofProviders[Shake128.Algorithm] = new Shake128Provider();
            xofProviders[Shake256.Algorithm] = new Shake256Provider();

            hmacProviders[Sha1.Algorithm] = new Sha1HmacProvider();
            hmacProviders[Sha224.Algorithm] = new Sha224HmacProvider();
            hmacProviders[Sha256.Algorithm] = new Sha256HmacProvider();
            hmacProviders[Sha384.Algorithm] = new Sha384HmacProvider();
            hmacProviders[Sha512.Algorithm] = new Sha512HmacProvider();
            hmacProviders[Sha512_224.Algorithm] = new Sha512_224HmacProvider();
            hmacProviders[Sha512_256.Algorithm] = new Sha512_256HmacProvider();
            hmacProviders[Sha1HMac.Algorithm] = new Sha1HmacProvider();
            hmacProviders[Sha224HMac.Algorithm] = new Sha224HmacProvider();
            hmacProviders[Sha256HMac.Algorithm] = new Sha256HmacProvider();
            hmacProviders[Sha384HMac.Algorithm] = new Sha384HmacProvider();
            hmacProviders[Sha512HMac.Algorithm] = new Sha512HmacProvider();
            hmacProviders[Sha512_224HMac.Algorithm] = new Sha512_224HmacProvider();
            hmacProviders[Sha512_256HMac.Algorithm] = new Sha512_256HmacProvider();

            // FSM_STATE:3.SHS.0,"SECURE HASH GENERATE VERIFY KAT", "The module is performing Secure Hash generate and verify KAT self-tests"
            // FSM_TRANS:3.SHS.0, "POWER ON SELF-TEST",	"SECURE HASH GENERATE VERIFY KAT",	"Invoke Secure Hash Generate/Verify KAT self-test"
            for (IEnumerator en = digestProviders.Keys.GetEnumerator(); en.MoveNext();)
            {
                ((DigestEngineProvider)digestProviders[en.Current]).CreateEngine(EngineUsage.GENERAL);
            }
            // FSM_TRANS:3.SHS.1, "SECURE HASH GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"Secure Hash Generate/Verify KAT self-test successful completion"

            // FSM_STATE:3.SHS.1,"HMAC GENERATE VERIFY KAT", "The module is performing HMAC generate and verify KAT self-tests"
            // FSM_TRANS:3.SHS.2,"POWER ON SELF-TEST", "HMAC GENERATE VERIFY KAT", "Invoke HMAC Generate/Verify KAT self-test"
            for (IEnumerator en = hmacProviders.Keys.GetEnumerator(); en.MoveNext();)
            {
                ((HmacEngineProvider)hmacProviders[en.Current]).CreateEngine(EngineUsage.GENERAL);
            }
            // FSM_TRANS:3.SHS.3, "HMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"HMAC Generate/Verify KAT self-test successful completion"

            // FSM_STATE:3.SHS.2,"XOF GENERATE VERIFY KAT", "The module is performing Extendable Output Function generate and verify KAT self-tests"
            // FSM_TRANS:3.SHS.3,"POWER ON SELF-TEST", "XOF GENERATE VERIFY KAT", "Invoke XOF Generate/Verify KAT self-test"
            for (IEnumerator en = xofProviders.Keys.GetEnumerator(); en.MoveNext();)
            {
                ((XofEngineProvider)xofProviders[en.Current]).CreateEngine(EngineUsage.GENERAL);
            }
            // FSM_TRANS:3.SHS.4, "XOF GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"XOF Generate/Verify KAT self-test successful completion"
        }

        private FipsShs()
        {
        }

        /// <summary>
        /// Generic digest parameters.
        /// </summary>
        public class Parameters: FipsDigestAlgorithm, IParameters<FipsDigestAlgorithm>, IFactoryServiceType<IDigestFactory<Parameters>>, IFactoryService<IDigestFactory<Parameters>>
        {
			internal Parameters(FipsDigestAlgorithm algorithm): base(algorithm.Name, algorithm.Mode)
			{
			}

			public FipsDigestAlgorithm Algorithm {
				get { return this; }
			}

            Func<IParameters<Crypto.Algorithm>, IDigestFactory<Parameters>> IFactoryService<IDigestFactory<Parameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateDigestFactory(parameters as Parameters);
            }
        }

        /// <summary>
        /// Generic eXpandable output function (XOF) parameters.
        /// </summary>
		public class XofParameters: FipsAlgorithm, IParameters<FipsAlgorithm>, IFactoryServiceType<IXofFactory<XofParameters>>, IFactoryService<IXofFactory<XofParameters>>
        {
			internal XofParameters(FipsAlgorithm algorithm): base(algorithm.Name)
			{
			}

			public FipsAlgorithm Algorithm {
				get { return this; }
			}

            Func<IParameters<Crypto.Algorithm>, IXofFactory<XofParameters>> IFactoryService<IXofFactory<XofParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateXofFactory(parameters as XofParameters);
            }
        }

        /// <summary>
        /// Parameters for HMAC modes.
        /// </summary>
		public class AuthenticationParameters: FipsDigestAlgorithm, IAuthenticationParameters<AuthenticationParameters, FipsDigestAlgorithm>
		{
			private readonly FipsDigestAlgorithm algorithm;
			private readonly int macSizeInBits;

			internal AuthenticationParameters (FipsDigestAlgorithm algorithm, int macSizeInBits):base(algorithm.Name, algorithm.Mode)
			{
				this.algorithm = algorithm;
				this.macSizeInBits = macSizeInBits;
			}

			public FipsDigestAlgorithm Algorithm {
				get { return this.algorithm; }
			}

			/// <summary>
			/// Return the size of the MAC these parameters are for.
			/// </summary>
			/// <value>The MAC size in bits.</value>
			public int MacSizeInBits { get { return macSizeInBits; } }

			/// <summary>
			/// Create a new parameter set with the specified MAC size associated with it.
			/// </summary>
			/// <returns>The new parameter set.</returns>
			/// <param name="macSizeInBits">Mac size in bits.</param>
			public AuthenticationParameters WithMacSize(int macSizeInBits)
			{
				return new AuthenticationParameters (this.algorithm, macSizeInBits);
			}
		}

		private class Provider: IDigestFactoryProvider<Parameters>, IXofFactoryProvider<XofParameters>  
		{
			public IDigestFactory<Parameters> CreateDigestFactory (Parameters algorithmDetails)
			{
				DigestEngineProvider digestProvider = (DigestEngineProvider)digestProviders[algorithmDetails.Algorithm];

				return new DigestFactory<Parameters>(algorithmDetails, digestProvider, digestProvider.DigestSize);
			}

			public IXofFactory<XofParameters> CreateXofFactory (XofParameters algorithmDetails)
			{
				XofEngineProvider xofProvider = (XofEngineProvider)xofProviders[algorithmDetails.Algorithm];

				return new XofFactory<XofParameters>(algorithmDetails, xofProvider);
			}
		}

        /// <summary>
        /// HMAC key class.
        /// </summary>
        public class Key : SymmetricSecretKey, ICryptoServiceType<IMacFactoryService>, IServiceProvider<IMacFactoryService>
        {
            public Key(AuthenticationParameters parameterSet, byte[] bytes) : base(parameterSet, bytes)
            {
            }

            Func<IKey, IMacFactoryService> IServiceProvider<IMacFactoryService>.GetFunc(SecurityContext context)
            {
                return (key) => new HmacProvider(key as ISymmetricKey);
            }
        }

        private class HmacProvider: IMacFactoryService
		{
			private readonly ISymmetricKey key;

			internal HmacProvider(ISymmetricKey key)
			{
				this.key = key;
			}

            IMacFactory<A> IMacFactoryService.CreateMacFactory<A>(A algorithmDetails)
            {
                HmacEngineProvider macProvider = (HmacEngineProvider)hmacProviders[algorithmDetails.Algorithm];
                int defaultMacSize = macProvider.MacSize;

                if (key != null)
                {
                    macProvider = new KeyedHmacEngineProvider(key, macProvider);
                }

                if (algorithmDetails.MacSizeInBits != defaultMacSize * 8)
                {
                    macProvider = new TruncatedHmacEngineProvider(macProvider, algorithmDetails.MacSizeInBits);
                }

                return (IMacFactory < A > )new MacFactory<AuthenticationParameters>(algorithmDetails as AuthenticationParameters, macProvider, algorithmDetails.MacSizeInBits / 8);
            }
        }

		internal static IDigest CreateDigest(DigestAlgorithm digestAlgorithm)
		{
			return ((DigestEngineProvider)digestProviders [digestAlgorithm]).CreateEngine(EngineUsage.GENERAL);
		}

		internal static IMac CreateHmac(DigestAlgorithm hmacAlgorithm)
		{
            if (hmacAlgorithm is AuthenticationParameters)
            {
                return ((HmacEngineProvider)hmacProviders[(hmacAlgorithm as AuthenticationParameters).Algorithm]).CreateEngine(EngineUsage.GENERAL);
            }
            if (hmacAlgorithm is Parameters)
            {
                return ((HmacEngineProvider)hmacProviders[(hmacAlgorithm as Parameters).Algorithm]).CreateEngine(EngineUsage.GENERAL);
            }
            return ((HmacEngineProvider)hmacProviders[(hmacAlgorithm as DigestAlgorithm)]).CreateEngine(EngineUsage.GENERAL);
        }

        private class ShaKatTest: IBasicKatTest<IDigest>
        {
            private static byte[] stdShaVector = Strings.ToByteArray("abc");
            private readonly byte[] kat;

            internal ShaKatTest(byte[] kat)
            {
                this.kat = kat;
            }

            public bool HasTestPassed(IDigest digest)
            {
                byte[] result = Digests.DoFinal(digest, stdShaVector, 0, stdShaVector.Length);
                return Arrays.AreEqual(result, kat);
            }
        }

        private class HMacKatTest : IBasicKatTest<IMac>
        {
            private static readonly byte[] stdHMacVector = Strings.ToByteArray("what do ya want for nothing?");
            private static readonly byte[] key = Hex.Decode("4a656665");

            private readonly byte[] kat;

            internal HMacKatTest(byte[] kat)
            {
                this.kat = kat;
            }

            public bool HasTestPassed(IMac hMac)
            {
                byte[] result = Macs.DoFinal(hMac, new KeyParameter(key), stdHMacVector, 0, stdHMacVector.Length);

                return Arrays.AreEqual(result, kat);
            }
        }

        private class XofKatTest : IBasicKatTest<IXof>
        {
            private static byte[] stdShaVector = Strings.ToByteArray("abc");
            private readonly byte[] kat;

            internal XofKatTest(byte[] kat)
            {
                this.kat = kat;
            }

            public bool HasTestPassed(IXof digest)
            {
                byte[] result = Digests.DoFinal(digest, stdShaVector, 0, stdShaVector.Length);
                return Arrays.AreEqual(result, kat);
            }
        }

        private abstract class DigestEngineProvider : IEngineProvider<IDigest>
        {
			private readonly int digestSize;

			internal DigestEngineProvider(int digestSizeInBits)
			{
				this.digestSize = digestSizeInBits / 8;
			}

			public int DigestSize
			{
				get { return digestSize; }
			}

			abstract public IDigest CreateEngine (EngineUsage usage);
		}

		private abstract class XofEngineProvider: IEngineProvider<IXof>
		{
			internal XofEngineProvider()
			{
			}
				
			abstract public IXof CreateEngine (EngineUsage usage);
		}

		private abstract class HmacEngineProvider: IEngineProvider<IMac>
		{
			private readonly int macSizeInBits;

			internal HmacEngineProvider(int macSizeInBits)
			{
				this.macSizeInBits = macSizeInBits / 8;
			}

			public int MacSize
			{
				get { return macSizeInBits; }
			}

			abstract public IMac CreateEngine (EngineUsage usage);
		}

		private class KeyedHmacEngineProvider: HmacEngineProvider
		{
			private readonly ISymmetricKey key;
			private readonly HmacEngineProvider provider;

			internal KeyedHmacEngineProvider(ISymmetricKey key, HmacEngineProvider provider): base(provider.MacSize * 8)
			{
				this.key = key;
				this.provider = provider;
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				IMac mac = provider.CreateEngine (usage);

				if (key != null)
				{
					mac.Init(new KeyParameter(key.GetKeyBytes()));
				}

				return mac;
			}
		}

		private class TruncatedHmacEngineProvider: HmacEngineProvider
		{
			private readonly HmacEngineProvider provider;
			private readonly int macSizeInBits;

			internal TruncatedHmacEngineProvider(HmacEngineProvider provider, int macSizeInBits): base(macSizeInBits)
			{
				this.provider = provider;
				this.macSizeInBits = macSizeInBits;
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				IMac mac = provider.CreateEngine (usage);

				return new TruncatingMac(mac, macSizeInBits);
			}
		}

		private class Sha1DigestProvider: DigestEngineProvider
		{
			internal Sha1DigestProvider() : base(160)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA1, new Sha1Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha1]));
			}
		}

		private class Sha224DigestProvider: DigestEngineProvider
		{
			internal Sha224DigestProvider() : base(224)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
                return SelfTestExecutor.Validate(Algorithm.SHA224, new Sha224Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha224]));
            }
		}

		private class Sha256DigestProvider: DigestEngineProvider
		{
			internal Sha256DigestProvider() : base(256)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA256, new Sha256Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha256]));
			}
		}

		private class Sha384DigestProvider: DigestEngineProvider
		{
			internal Sha384DigestProvider() : base(384)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA384, new Sha384Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha384]));
			}
		}

		private class Sha512DigestProvider: DigestEngineProvider
		{
			internal Sha512DigestProvider() : base(512)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512, new Sha512Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha512]));
			}
		}

		private class Sha512_224DigestProvider: DigestEngineProvider
		{
			internal Sha512_224DigestProvider() : base(224)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512_224, new Sha512tDigest(224), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha512_224]));
			}
		}

		private class Sha512_256DigestProvider: DigestEngineProvider
		{
			internal Sha512_256DigestProvider() : base(256)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512_256, new Sha512tDigest(256), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha512_256]));
			}
		}

		private class Sha3_224DigestProvider: DigestEngineProvider
		{
			internal Sha3_224DigestProvider() : base(224)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_224, new Sha3Digest(224), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_224]));
			}
		}

		private class Sha3_256DigestProvider: DigestEngineProvider
		{
			internal Sha3_256DigestProvider() : base(256)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_256, new Sha3Digest(256), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_256]));
			}
		}

        private class Sha3_384DigestProvider : DigestEngineProvider
        {
            internal Sha3_384DigestProvider() : base(384)
            {
            }

            public override IDigest CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA3_384, new Sha3Digest(384), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_384]));
            }
        }

        private class Sha3_512DigestProvider : DigestEngineProvider
        {
            internal Sha3_512DigestProvider() : base(512)
            {
            }

            public override IDigest CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA3_512, new Sha3Digest(512), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_512]));
            }
        }

        private class Shake128Provider: XofEngineProvider
		{
			internal Shake128Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHAKE128, new ShakeDigest(128), new XofKatTest(FipsKats.Values[FipsKats.Vec.Shake128]));
            }
		}

		private class Shake256Provider: XofEngineProvider
		{
			internal Shake256Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHAKE256, new ShakeDigest(256), new XofKatTest(FipsKats.Values[FipsKats.Vec.Shake256]));
            }
		}

		private class Sha1HmacProvider: HmacEngineProvider
		{
			internal Sha1HmacProvider(): base(160)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA1_HMAC, new HMac(new Sha1Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha1HMac]));
            }
		}

		private class Sha224HmacProvider: HmacEngineProvider
		{
			internal Sha224HmacProvider(): base(224)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA224_HMAC, new HMac(new Sha224Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha224HMac]));
            }
		}

		private class Sha256HmacProvider: HmacEngineProvider
		{
			internal Sha256HmacProvider(): base(256)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA256_HMAC, new HMac(new Sha256Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha256HMac]));
            }
		}

		private class Sha384HmacProvider: HmacEngineProvider
		{
			internal Sha384HmacProvider(): base(384)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA384_HMAC, new HMac(new Sha384Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha384HMac]));
            }
		}

		private class Sha512HmacProvider: HmacEngineProvider
		{
			internal Sha512HmacProvider(): base(512)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512_HMAC, new HMac(new Sha512Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha512HMac]));
            }
		}

        private class Sha512_224HmacProvider : HmacEngineProvider
        {
            internal Sha512_224HmacProvider() : base(224)
            {
            }

            public override IMac CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA512_224_HMAC, new HMac(new Sha512tDigest(224)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha512_224HMac]));
            }
        }

        private class Sha512_256HmacProvider : HmacEngineProvider
        {
            internal Sha512_256HmacProvider() : base(256)
            {
            }

            public override IMac CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA512_256_HMAC, new HMac(new Sha512tDigest(256)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha512_256HMac]));
            }
        }
    }
}

