using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Digests;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved Key Derivation Function (KDF) implementations.
    /// </summary>
    public class FipsKdf
	{
        /// <summary>
        /// Parameters configuration for ASN X9.63-2001
        /// </summary>
        public static readonly AgreementKdfBuilderService X963 = new AgreementKdfBuilderService(new FipsAlgorithm("X9.63"));

        /// <summary>
        /// Algorithm marker for concatenating KDF in FIPS SP 800-56A/B
        /// </summary>
        public static readonly AgreementKdfBuilderService Concatenation = new AgreementKdfBuilderService(new FipsAlgorithm("Concatenation"));

        /// <summary>
        /// Algorithm marker for Transport Layer Security Version 1.0 (TLSv1.0)
        /// </summary>
        public static readonly TlsKdfBuilderService Tls1_0 = new TlsKdfBuilderService(new FipsAlgorithm("TLS1.0"));

        /// <summary>
        /// Algorithm marker for Transport Layer Security Version 1.1 (TLSv1.1)
        /// </summary>
        public static readonly TlsKdfBuilderService Tls1_1 = new TlsKdfBuilderService(new FipsAlgorithm("TLS1.1"));

        /// <summary>
        /// Algorithm marker for Transport Layer Security Version 1.2 (TLSv1.2)
        /// </summary>
        public static readonly TlsKdfWithPrfBuilderService Tls1_2 = new TlsKdfWithPrfBuilderService(new FipsAlgorithm("TLS1.2"));

        private readonly static MD5Provider md5Provider = new MD5Provider();

        static FipsKdf()
        {
            // FSM_STATE:3.KDF.0, TLS 1.0 KAT, "The module is performing the KAT test for the MD5 digest in TLS 1.0"
            // FSM_TRANS:3.KDF.0, "POWER ON SELF-TEST",	"TLS 1.0 KDF GENERATE VERIFY KAT",	"Invoke MD5 digest in TLS 1.0 KDF Generate/Verify KAT self-test"
            md5Provider.CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.KDF.1, "TLS 1.0 KDF GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"MD5 digest in TLS 1.0 KDF KAT self-test successful completion"
        }

        public class AgreementKdfBuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<AgreementKdfBuilder>, IBuilderService<AgreementKdfBuilder>
        {
            internal AgreementKdfBuilderService(FipsAlgorithm algorithm) : base(algorithm)
            {

            }

            Func<IParameters<Algorithm>, AgreementKdfBuilder> IBuilderService<AgreementKdfBuilder>.GetFunc(SecurityContext context)
            {
                return (parameters) => new AgreementKdfBuilder((FipsAlgorithm)parameters.Algorithm, FipsPrfAlgorithm.Sha1, null);
            }
        }

        public class AgreementKdfBuilder
        {
            private readonly FipsAlgorithm algorithm;
            private readonly FipsPrfAlgorithm prf;
            private readonly byte[] iv;

            internal AgreementKdfBuilder(FipsAlgorithm algorithm, FipsPrfAlgorithm prf, byte[] iv)
            {
                this.algorithm = algorithm;
                this.prf = prf;
                this.iv = iv;
            }

            public AgreementKdfBuilder WithPrf(FipsPrfAlgorithm prf)
            {
                return new AgreementKdfBuilder(algorithm, prf, iv);
            }

            public AgreementKdfBuilder WithIV(byte[] iv)
            {
                return new AgreementKdfBuilder(algorithm, prf, Arrays.Clone(iv));
            }

            public IKdfCalculator<AgreementKdfParameters> From(byte[] shared)
            {
                AgreementKdfParameters parameters = new AgreementKdfParameters(new FipsKdfAlgorithm(algorithm, prf), shared, iv);

                if (parameters.Algorithm.Kdf == X963.Algorithm)
                {
                    IDerivationFunction df = new Kdf2BytesGenerator(FipsShs.CreateDigest((FipsDigestAlgorithm)parameters.Prf.BaseAlgorithm));

                    df.Init(new KdfParameters(parameters.GetShared(), parameters.GetIV()));

                    return new AgreementKdfCalculator(parameters, df);
                }
                else
                {
                    IDerivationFunction df = new ConcatenationKdfGenerator(FipsShs.CreateDigest((FipsDigestAlgorithm)parameters.Prf.BaseAlgorithm));

                    df.Init(new KdfParameters(parameters.GetShared(), parameters.GetIV()));

                    return new AgreementKdfCalculator(parameters, df);
                }
            }
        }

        public class TlsKdfBuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<TlsKdfBuilder>, IBuilderService<TlsKdfBuilder>
        {
            internal TlsKdfBuilderService(FipsAlgorithm algorithm) : base(algorithm)
            {

            }

            Func<IParameters<Algorithm>, TlsKdfBuilder> IBuilderService<TlsKdfBuilder>.GetFunc(SecurityContext context)
            {
                return (parameters) => new TlsKdfBuilder((FipsAlgorithm)parameters.Algorithm);
            }
        }

        /// <summary>
        /// Builder for the TLS 1.0 key derivation function.
        /// </summary>
        public class TlsKdfBuilder
        {
            private readonly FipsAlgorithm algorithm;

            internal TlsKdfBuilder(FipsAlgorithm algorithm)
            {
                this.algorithm = algorithm;
            }

            public IKdfCalculator<TlsKdfParameters> From(byte[] secret, string label, params byte[][] seedMaterial)
            {
                TlsKdfParameters parameters = new TlsKdfParameters(algorithm, Arrays.Clone(secret), label, concatenate(seedMaterial));

                return new Tls10and11KdfFactory(parameters);
            }
        }

        public class TlsKdfWithPrfBuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<TlsKdfWithPrfBuilder>, IBuilderService<TlsKdfWithPrfBuilder>
        {
            internal TlsKdfWithPrfBuilderService(FipsAlgorithm algorithm) : base(algorithm)
            {

            }

            Func<IParameters<Algorithm>, TlsKdfWithPrfBuilder> IBuilderService<TlsKdfWithPrfBuilder>.GetFunc(SecurityContext context)
            {
                return (parameters) => new TlsKdfWithPrfBuilder((FipsAlgorithm)parameters.Algorithm, FipsShs.Sha256HMac);
            }
        }

        /// <summary>
        /// Builder for the TLS 1.1/1.2 key derivation function.
        /// </summary>
        public class TlsKdfWithPrfBuilder
        {
            private readonly FipsAlgorithm algorithm;
            private readonly FipsDigestAlgorithm prf;

            internal TlsKdfWithPrfBuilder(FipsAlgorithm algorithm, FipsDigestAlgorithm prf)
            {
                this.algorithm = algorithm;
                this.prf = prf;
            }

            public TlsKdfWithPrfBuilder WithPrf(FipsDigestAlgorithm prf)
            {
                return new TlsKdfWithPrfBuilder(algorithm, prf);
            }

            public FipsDigestAlgorithm Prf { get { return prf; } }

            public IKdfCalculator<TlsKdfWithPrfParameters> From(byte[] secret, string label, params byte[][] seedMaterial)
            {
                TlsKdfWithPrfParameters parameters = new TlsKdfWithPrfParameters(algorithm, prf, Arrays.Clone(secret), label, concatenate(seedMaterial));

                return new Tls12KdfFactory(parameters);
            }
        }

        /// <summary>
        /// Parameters for the X9.63 and CONCATENATION key derivation function.
        /// </summary>
        public class AgreementKdfParameters: Parameters<FipsKdfAlgorithm>
		{
            private readonly FipsKdfAlgorithm algorithm;
			private readonly byte[] shared;
			private readonly byte[] iv;

            internal AgreementKdfParameters(FipsKdfAlgorithm algorithm, byte[] shared, byte[] iv): base(algorithm)
			{
                this.algorithm = algorithm;
				this.shared = shared;
				this.iv = iv;
			}

			internal AgreementKdfParameters(FipsKdfAlgorithm algorithm, byte[] shared): this(algorithm, shared, null)
			{
			}

			public byte[] GetShared() 
			{ 
				return Arrays.Clone(shared); 
			}

			public byte[] GetIV() 
			{ 
				return Arrays.Clone(iv);
			}

			public FipsPrfAlgorithm Prf { get { return (FipsPrfAlgorithm)Algorithm.Prf; } }
        }

        /// <summary>
        /// TLS protocol stages for KDF usage.
        /// </summary>
		public class TlsStage
		{
			private TlsStage()
			{

			}

			public static readonly String MASTER_SECRET = "master secret";
			public static readonly String KEY_EXPANSION = "key expansion";
		}



		private static byte[] concatenate(params byte[][] seedMaterial)
		{
			int total = seedMaterial [0].Length;
			for (int i = 1; i < seedMaterial.Length; i++) {
				total += seedMaterial [i].Length;
			}

			byte[] rv = new byte[total];

			total = 0;
			for (int i = 0; i < seedMaterial.Length; i++) {
				Array.Copy (seedMaterial [i], 0, rv, total, seedMaterial [i].Length);
				total += seedMaterial [i].Length;
			}

			return rv;
		}

        /// <summary>
        /// Parameters for the TLS 1.0 key derivation function.
        /// </summary>
        public class TlsKdfParameters: Parameters<FipsAlgorithm>
		{
			protected readonly byte[] mSecret;
			protected readonly string mLabel;
			protected readonly byte[] mSeedMaterial;

			internal TlsKdfParameters(FipsAlgorithm algorithm, byte[] secret, string label, byte[] seedMaterial): base(algorithm)
			{
				this.mSecret = secret;
				this.mLabel = label;
				this.mSeedMaterial = seedMaterial;
			}

			public byte[] Secret { get { return Arrays.Clone(mSecret); } }

			public string Label { get { return mLabel; } }

			public byte[] SeedMaterial { get { return Arrays.Clone(mSeedMaterial); } }
		}

        /// <summary>
        /// Parameters for the TLS 1.1/1.2 key derivation function.
        /// </summary>
        public class TlsKdfWithPrfParameters: TlsKdfParameters
		{
			private readonly FipsDigestAlgorithm prf;
		
			internal TlsKdfWithPrfParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm prf, byte[] secret, string label, byte[] seedMaterial): base(algorithm, secret, label, seedMaterial)
			{
				this.prf = prf;
			}
				
			public FipsDigestAlgorithm Prf { get { return prf; } }
		}
			
		private class AgreementKdfCalculator: IKdfCalculator<AgreementKdfParameters>
		{
			private readonly AgreementKdfParameters parameters;
			private readonly IDerivationFunction derivationFunction;

			internal AgreementKdfCalculator(AgreementKdfParameters parameters, IDerivationFunction derivationFunction)
			{
				this.parameters = parameters;
				this.derivationFunction = derivationFunction;
			}

			public AgreementKdfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				byte[] rv = new byte[outputLength];

				derivationFunction.GenerateBytes (rv, 0, rv.Length);

				return new SimpleBlockResult(rv);
			}
		}

		private class Tls10and11KdfFactory: IKdfCalculator<TlsKdfParameters>
		{
			private readonly TlsKdfParameters parameters;

			internal Tls10and11KdfFactory(TlsKdfParameters parameters)
			{
				this.parameters = parameters;
			}
				
			public TlsKdfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				IMac md5Hmac = new HMac(md5Provider.CreateEngine(EngineUsage.GENERAL));
				IMac sha1HMac = FipsShs.CreateHmac(FipsShs.Sha1HMac);

				return new SimpleBlockResult(PRF_legacy(parameters, outputLength, md5Hmac, sha1HMac));
			}
		}

		private class Tls12KdfFactory: IKdfCalculator<TlsKdfWithPrfParameters>
		{
			private readonly TlsKdfWithPrfParameters parameters;

			internal Tls12KdfFactory(TlsKdfWithPrfParameters parameters)
			{
				this.parameters = parameters;
			}

			public TlsKdfWithPrfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				return new SimpleBlockResult(PRF(parameters, outputLength));
			}
		}

		private static byte[] PRF(TlsKdfWithPrfParameters parameters, int size)
		{
			byte[] label = Strings.ToByteArray(parameters.Label);
			byte[] labelSeed = Arrays.Concatenate(label, parameters.SeedMaterial);

			IMac prfMac = FipsShs.CreateHmac(parameters.Prf);
			byte[] buf = new byte[size];
			hmac_hash(prfMac, parameters.Secret, labelSeed, buf);
			return buf;
		}

		private static byte[] PRF_legacy(TlsKdfParameters parameters, int size, IMac md5Hmac, IMac sha1HMac)
		{
			byte[] label = Strings.ToByteArray(parameters.Label);
			byte[] labelSeed = Arrays.Concatenate(label, parameters.SeedMaterial);

			byte[] secret = parameters.Secret;

			int s_half = (secret.Length + 1) / 2;
			byte[] s1 = new byte[s_half];
			byte[] s2 = new byte[s_half];
			Array.Copy(secret, 0, s1, 0, s_half);
			Array.Copy(secret, secret.Length - s_half, s2, 0, s_half);

			byte[] b1 = new byte[size];
			byte[] b2 = new byte[size];
			hmac_hash(md5Hmac, s1, labelSeed, b1);
			hmac_hash(sha1HMac, s2, labelSeed, b2);
			for (int i = 0; i < size; i++)
			{
				b1[i] ^= b2[i];
			}
			return b1;
		}

		private static void hmac_hash(IMac mac, byte[] secret, byte[] seed, byte[] output)
		{
			mac.Init(new KeyParameter(secret));
			byte[] a = seed;
			int size = mac.GetMacSize();
			int iterations = (output.Length + size - 1) / size;
			byte[] buf = new byte[mac.GetMacSize()];
			byte[] buf2 = new byte[mac.GetMacSize()];
			for (int i = 0; i < iterations; i++)
			{
				mac.BlockUpdate(a, 0, a.Length);
				mac.DoFinal(buf, 0);
				a = buf;
				mac.BlockUpdate(a, 0, a.Length);
				mac.BlockUpdate(seed, 0, seed.Length);
				mac.DoFinal(buf2, 0);
				Array.Copy(buf2, 0, output, (size * i), System.Math.Min(size, output.Length - (size * i)));
			}
		}

        private class MD5Provider: IEngineProvider<IDigest>
		{
			public IDigest CreateEngine(EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Tls1_0.Algorithm, new MD5Digest (), new Md5KatTest());
			}
		}

        private class Md5KatTest: IBasicKatTest<IDigest>
        {
            private static readonly byte[] stdShaVector = Strings.ToByteArray("abc");
            private static readonly byte[] kat = Hex.Decode("900150983cd24fb0d6963f7d28e17f72");

            public bool HasTestPassed(IDigest digest)
            {
                digest.BlockUpdate(stdShaVector, 0, stdShaVector.Length);

                byte[] result = new byte[digest.GetDigestSize()];

                digest.DoFinal(result, 0);

                return Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.MD5], result);
            }
        }
}
}

