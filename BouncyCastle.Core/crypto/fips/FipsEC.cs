using System;
using System.Collections.Generic;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Agreement;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Crypto.Internal.Digests;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved implementations of Elliptic Curve (EC) algorithms.
    /// </summary>
	public class FipsEC
	{
        /// <summary>
        /// Basic Elliptic Curve algorithm marker, can be used for creating general purpose Elliptic Curve keys.
        /// </summary>
        public static readonly FipsAlgorithm Alg = new FipsAlgorithm ("EC");

        /// <summary>
        /// Elliptic Curve DSA algorithm parameter source - default is SHA-384.
        /// </summary>
		public static readonly SignatureParameters Dsa = new SignatureParameters(new FipsAlgorithm (Alg, AlgorithmMode.DSA), FipsShs.Sha384);

        /// <summary>
        /// Elliptic Curve cofactor Diffie-Hellman algorithm parameter source.
        /// </summary>
        public static readonly AgreementParameters Cdh = new AgreementParameters(new FipsAlgorithm (Alg, AlgorithmMode.CDH));

        private static readonly int MIN_FIPS_FIELD_SIZE = 224;       // 112 bits of security

		private static readonly BigInteger TEST_D_OFFSET = new BigInteger("deadbeef", 16);  // offset for generating test key pairs.

        private static readonly DsaProvider DSA_PROVIDER;
        private static readonly DhcProvider CDH_PROVIDER;

        static FipsEC()
        {
            DSA_PROVIDER = new DsaProvider();
            CDH_PROVIDER = new DhcProvider();

            // FSM_STATE:3.EC.0,"ECDSA SIGN VERIFY KAT", "The module is performing ECDSA sign and verify KAT self-test"
            // FSM_TRANS:3.EC.0,"POWER ON SELF-TEST", "ECDSA SIGN VERIFY KAT", "Invoke ECDSA Sign/Verify  KAT self-test"
            DSA_PROVIDER.CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.EC.1,"ECDSA SIGN VERIFY KAT", "POWER ON SELF-TEST", "ECDSA Sign/Verify  KAT self-test successful completion"

            // FSM_STATE:3.EC.1,"EC CVL Primitive 'Z' computation KAT", "The module is performing EC CVL Primitive 'Z' computation KAT verify KAT self-test"
            // FSM_TRANS:3.EC.2,"POWER ON SELF-TEST", "EC CVL Primitive 'Z' computation KAT", "Invoke EC CVL Primitive 'Z' computation KAT self-test"
            ecPrimitiveZTest();
            // FSM_TRANS:3.EC.3,"EC CVL Primitive 'Z' computation KAT", "POWER ON SELF-TEST", "EC CVL Primitive 'Z' computation KAT self-test successful completion"
        }

        /// <summary>
        /// ECDomainParametersID for the NIST defined EC domain parameters.
        /// </summary>
        public class DomainParams
		{
			public static readonly IECDomainParametersID B571 = new DomainParametersID ("B-571");
			public static readonly IECDomainParametersID B409 = new DomainParametersID ("B-409");
			public static readonly IECDomainParametersID B283 = new DomainParametersID ("B-283");
			public static readonly IECDomainParametersID B233 = new DomainParametersID ("B-233");
			public static readonly IECDomainParametersID B163 = new DomainParametersID ("B-163");
			public static readonly IECDomainParametersID K571 = new DomainParametersID ("K-571");
			public static readonly IECDomainParametersID K409 = new DomainParametersID ("K-409");
			public static readonly IECDomainParametersID K283 = new DomainParametersID ("K-283");
			public static readonly IECDomainParametersID K233 = new DomainParametersID ("K-233");
			public static readonly IECDomainParametersID K163 = new DomainParametersID ("K-163");
			public static readonly IECDomainParametersID P521 = new DomainParametersID ("P-521");
			public static readonly IECDomainParametersID P384 = new DomainParametersID ("P-384");
			public static readonly IECDomainParametersID P256 = new DomainParametersID ("P-256");
			public static readonly IECDomainParametersID P224 = new DomainParametersID ("P-224");
			public static readonly IECDomainParametersID P192 = new DomainParametersID ("P-192");

			internal class DomainParametersID: IECDomainParametersID
			{
				private readonly string curveName;

				internal DomainParametersID(String curveName)
				{
					this.curveName = curveName;
				}

				public string CurveName
				{
					get {
						return curveName;
					}
				}
			}

            /// <summary>
            /// Return a list of the common NIST curves.
            /// </summary>
            /// <returns>A list of the common NIST curves.</returns>
			public static List<IECDomainParametersID> Values()
			{
				List<IECDomainParametersID> v = new List<IECDomainParametersID>();

				v.Add (B571);
				v.Add (B409);
				v.Add (B283);
				v.Add (B233);
				v.Add (B163);
				v.Add (K571);
				v.Add (K409);
				v.Add (K283);
				v.Add (K233);
				v.Add (K163);
				v.Add (P521);
				v.Add (P384);
				v.Add (P256);
				v.Add (P224);
				v.Add (P192);

				return v;
			}
		}
			
		/// <summary>
		/// Parameters for EC key agreement.
		/// </summary>
		public class AgreementParameters: AgreementParameters<FipsAlgorithm, FipsDigestAlgorithm, FipsPrfAlgorithm, FipsKdfAlgorithm>
		{
			/// <summary>
			/// Default constructor which specifies returning the raw secret on agreement calculation.
			/// </summary>
			/// <param name="agreementAlgorithm">The agreement algorithm (DH or CDH).</param>
			internal AgreementParameters(FipsAlgorithm agreementAlgorithm): this(agreementAlgorithm, new CopyKMGenerator())
			{	
			}

			private AgreementParameters(FipsAlgorithm agreementAlgorithm, IKMGenerator kmGenerator): base(agreementAlgorithm, kmGenerator)
			{
			}

            /// <summary>
            /// Add a key material generator for doing final processing on the agreed value.
            /// </summary>
            /// <returns>A new parameter set, including key material generator.</returns>
            /// <param name="kmGenerator">The key material generator to use.</param>
            public AgreementParameters WithKeyMaterialGenerator(IKMGenerator kmGenerator)
			{
                if (kmGenerator == null)
                {
                    throw new ArgumentException("kmGenerator cannot be null");
                }
				return new AgreementParameters(Algorithm, kmGenerator);
			}	
		}

        private class CopyKMGenerator : IKMGenerator
        {
            public byte[] Generate(byte[] agreed)
            {
                return Arrays.Clone(agreed);
            }
        }

        /// <summary>
        /// Configuration parameters for EC DSA signatures.
        /// </summary>
        public class SignatureParameters: SignatureParameters<SignatureParameters, FipsAlgorithm, FipsDigestAlgorithm>
		{
			internal SignatureParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm): base(algorithm, digestAlgorithm)
			{
			}

			internal override SignatureParameters CreateParameter(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm)
			{
				return new SignatureParameters (algorithm, digestAlgorithm);
			}
		}

		/// <summary>
		/// Parameters for EC key pair generation.
		/// </summary>
		public class KeyGenerationParameters: FipsParameters, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
        {
			private readonly ECDomainParameters domainParameters;

			/// <summary>
			/// Constructor for the default algorithm ID.
			/// </summary>
			/// <param name="domainParameters">EC domain parameters representing the curve any generated keys will be for.</param>
			public KeyGenerationParameters(ECDomainParameters domainParameters): this(Alg, domainParameters)
			{
			}

            public KeyGenerationParameters For(SignatureParameters dsaUsage)
            {
                return new KeyGenerationParameters(dsaUsage.Algorithm, this.domainParameters);
            }

            public KeyGenerationParameters For(AgreementParameters agreementUsage)
            {
                return new KeyGenerationParameters(agreementUsage.Algorithm, this.domainParameters);
            }

			KeyGenerationParameters(FipsAlgorithm algorithm, ECDomainParameters domainParameters):base(algorithm)
			{
				this.domainParameters = domainParameters;
			}

			/// <summary>
			/// Return the EC domain parameters for this object.
			/// </summary>
			/// <value>The EC domain parameter set.</value>
			public ECDomainParameters DomainParameters
			{
				get {
					return domainParameters;
				}
			}

            Func<IParameters<Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyPairGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Key pair generator for EC. Create one these via CryptoServicesRegistrar.CreateGenerator() using the KeyGenerationParameters
        /// object as the key.
        /// </summary>
		public class KeyPairGenerator: AsymmetricKeyPairGenerator<FipsParameters, AsymmetricECPublicKey, AsymmetricECPrivateKey>
        {
			private readonly ECDomainParameters domainParameters;
			private readonly ECKeyGenerationParameters param;
			private readonly ECKeyPairGenerator engine = new ECKeyPairGenerator();

			/// <summary>
			/// Construct a key pair generator for EC keys,
			/// </summary>
			/// <param name="keyGenParameters">Domain parameters and algorithm for the generated key.</param>
			/// <param name="random">A source of randomness for calculating the private value.</param>
			internal KeyPairGenerator(KeyGenerationParameters keyGenParameters, SecureRandom random): base(keyGenParameters)
			{
				if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
				{
					validateCurveSize(keyGenParameters.Algorithm, keyGenParameters.DomainParameters);

					Utils.ValidateKeyPairGenRandom(random, Utils.GetECCurveSecurityStrength(keyGenParameters.DomainParameters.Curve), Alg);
				}

				this.param = new Org.BouncyCastle.Crypto.Internal.Parameters.ECKeyGenerationParameters(getDomainParams(keyGenParameters.DomainParameters), random);
				this.domainParameters = keyGenParameters.DomainParameters;
				this.engine.Init(param);
			}
				
			/// <summary>
			/// Generate a new EC key pair.
			/// </summary>
			/// <returns>A new AsymmetricKeyPair containing an EC key pair.</returns>
			public override AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey> GenerateKeyPair()
			{
				AsymmetricCipherKeyPair kp = engine.GenerateKeyPair();

				Internal.Parameters.ECPublicKeyParameters pubKey = (Internal.Parameters.ECPublicKeyParameters)kp.Public;
				Internal.Parameters.ECPrivateKeyParameters prvKey = (Internal.Parameters.ECPrivateKeyParameters)kp.Private;

				FipsAlgorithm algorithm = this.Parameters.Algorithm;

				// FSM_STATE:5.4, "EC PAIRWISE CONSISTENCY TEST", "The module is performing EC Pairwise Consistency self-test"
				// FSM_TRANS:5.EC.0,"CONDITIONAL TEST", "EC PAIRWISE CONSISTENCY TEST", "Invoke EC Pairwise Consistency test"
				validateKeyPair(algorithm, kp);
				// FSM_TRANS:5.EC.1,"EC PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "EC Pairwise Consistency test successful"

				return new AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey>(new AsymmetricECPublicKey(algorithm, domainParameters, pubKey.Q), new AsymmetricECPrivateKey(algorithm, domainParameters, prvKey.D, pubKey.Q));
			}
        }

		internal class AgreementCalculator: IAgreementCalculator<AgreementParameters>
		{
			private readonly IBasicAgreement agreement;
			private readonly AgreementParameters parameters;

			internal AgreementCalculator(AgreementParameters parameters, IKey ecPrivateKey)
			{
				this.agreement = CDH_PROVIDER.CreateEngine(EngineUsage.GENERAL);

                agreement.Init(GetPrivateKeyParameters((AsymmetricECPrivateKey)ecPrivateKey));

                this.parameters = parameters;
			}
				
			public AgreementParameters AlgorithmDetails 
			{ 
				get { return parameters; } 
			}

			public byte[] Calculate(IAsymmetricPublicKey publicKey)
			{
                ECDomainParameters domainParams = ((AsymmetricECPublicKey)publicKey).DomainParameters;

                byte[] zBytes = BigIntegers.AsUnsignedByteArray((domainParams.Curve.FieldSize + 7) / 8,
                    agreement.CalculateAgreement(GetPublicKeyParameters((AsymmetricECPublicKey)publicKey)));

                byte[] keyMaterial = parameters.KeyMaterialGenerator.Generate(zBytes);

                // ZEROIZE
                Arrays.Fill(zBytes, (byte)0);

                return keyMaterial;
			}
		}

        private static ICipherParameters GetPublicParameters(IKey key)
        {
            AsymmetricECPublicKey pubK = key as AsymmetricECPublicKey;
            if (pubK == null)
            {
                throw new ArgumentException("SecureRandom not required: " + Alg.Name);
            }

            ECPublicKeyParameters publicKeyParameters = GetPublicKeyParameters(pubK);

            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                validateCurveSize(Alg, pubK.DomainParameters);
            }

            return publicKeyParameters;
        }

        private static ICipherParameters GetPrivateParameters(IKey key)
        {
            AsymmetricECPrivateKey pK;
            SecureRandom random;

            if (key is KeyWithRandom)
            {
                KeyWithRandom k = (KeyWithRandom)key;

                pK = (AsymmetricECPrivateKey)k.Key;
                random = k.Random;
            }
            else
            {
                pK = (AsymmetricECPrivateKey)key;
                random = CryptoServicesRegistrar.GetSecureRandom();
            }

            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                validateCurveSize(Alg, pK.DomainParameters);
            }

            return new ParametersWithRandom(GetPrivateKeyParameters(pK), random);
        }

        internal class SignerProvider: IEngineProvider<ISigner>
		{
			private readonly SignatureParameters parameters;
			private readonly ICipherParameters sigParams;

            internal SignerProvider(SignatureParameters parameters, IKey key)
            {
                this.parameters = parameters;
                if (key is AsymmetricECPublicKey)
                {
                    this.sigParams = GetPublicParameters(key);
                }
                else
                {
                    this.sigParams = GetPrivateParameters(key);
                }
            }

            public ISigner CreateEngine (EngineUsage usage)
			{
				ISigner sig = new DsaDigestSigner(DSA_PROVIDER.CreateEngine(usage), CreateDigest(parameters.DigestAlgorithm));
	
				sig.Init ((usage == EngineUsage.SIGNING), sigParams);

				return sig;
			}
		}

        private static IDigest CreateDigest(DigestAlgorithm digestAlg)
        {
            return digestAlg == null ? new NullDigest() : FipsShs.CreateDigest(digestAlg);
        }

		private static void validateKeyPair(FipsAlgorithm algorithm, AsymmetricCipherKeyPair kp)
		{
			switch (algorithm.Mode)
			{
			case AlgorithmMode.NONE:
			case AlgorithmMode.DSA:
				SelfTestExecutor.Validate(algorithm, kp, new DsaConsistencyTest());
				break;
			case AlgorithmMode.CDH:
				SelfTestExecutor.Validate(algorithm, kp, new CdhConsistencyTest());
				break;
			default:
				throw new InvalidOperationException("Unhandled EC algorithm: " + algorithm.Name);
			}
		}

		private class DsaConsistencyTest: IConsistencyTest<AsymmetricCipherKeyPair>
		{
			public bool HasTestPassed(AsymmetricCipherKeyPair kp)
			{
				ECDsaSigner signer = new ECDsaSigner();

				signer.Init(true, new ParametersWithRandom(kp.Private, Utils.testRandom));

				byte[] message = Hex.Decode("0102030405060708090a1112131415161718191a"); // size of a SHA-1 hash
		
				BigInteger[] rs = signer.GenerateSignature(message);

				signer.Init(false, kp.Public);

				return signer.VerifySignature(FipsKats.Values[FipsKats.Vec.ECKeyPairConsistencyVec], rs[0], rs[1]);
			}
		}

		private class CdhConsistencyTest: IConsistencyTest<AsymmetricCipherKeyPair> 
		{
			public bool HasTestPassed(AsymmetricCipherKeyPair kp)
			{
				ECDHCBasicAgreement agreement = new ECDHCBasicAgreement();

				agreement.Init(kp.Private);
  
				BigInteger agree1 = agreement.CalculateAgreement(kp.Public);

				AsymmetricCipherKeyPair testKP = getTestKeyPair(kp);

				agreement.Init(testKP.Private);

				BigInteger agree2 = agreement.CalculateAgreement(testKP.Public);

				agreement.Init(kp.Private);

				BigInteger agree3 = agreement.CalculateAgreement(testKP.Public);

				agreement.Init(testKP.Private);

				BigInteger agree4 = agreement.CalculateAgreement(kp.Public).Multiply(BigInteger.ValueOf(FipsKats.Values[FipsKats.Vec.ECDHKeyPairConsistencyVec][0]));

				return !agree1.Equals(agree2) && !agree1.Equals(agree3) && agree3.Equals(agree4);
			}
		}

		private static AsymmetricCipherKeyPair getKATKeyPair()
		{
			X9ECParameters p = NistNamedCurves.GetByName("P-256");
			EcDomainParameters parameters = new EcDomainParameters(p.Curve, p.G, p.N, p.H);
			ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
				new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), // d
				parameters);

			// Verify the signature
			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
				parameters.Curve.DecodePoint(Hex.Decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), // Q
				parameters);

			return new AsymmetricCipherKeyPair(pubKey, priKey);
		}

		private class DsaProvider: IEngineProvider<ECDsaSigner>
		{
			public ECDsaSigner CreateEngine(EngineUsage usage)
			{
				// We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
				return SelfTestExecutor.Validate(Alg, new ECDsaSigner(), new DsaKatTest());
			}
		}

		private class DsaKatTest: VariantKatTest<ECDsaSigner>
		{
			internal override void Evaluate(ECDsaSigner dsa)
			{
				AsymmetricCipherKeyPair kp = getKATKeyPair();

				SecureRandom k = new TestRandomBigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335");

				byte[] M = Hex.Decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

				dsa.Init(true, new ParametersWithRandom(kp.Private, k));

				BigInteger[] sig = dsa.GenerateSignature(M);

				dsa.Init(false, kp.Public);
				if (!dsa.VerifySignature(FipsKats.Values[FipsKats.Vec.ECStartupVec], sig[0], sig[1]))
				{
					Fail("signature fails");
				}
			}
		}

		private class DhcProvider: IEngineProvider<ECDHCBasicAgreement>
		{
			public ECDHCBasicAgreement CreateEngine(EngineUsage usage)
			{
				return SelfTestExecutor.Validate (Alg, new ECDHCBasicAgreement (), new DhcKatTest ());
			}
		}

		private class DhcKatTest: VariantKatTest<ECDHCBasicAgreement>
		{
			internal override void Evaluate(ECDHCBasicAgreement agreement)
			{
				AsymmetricCipherKeyPair kp = getKATKeyPair();

				AsymmetricCipherKeyPair testOther = getTestKeyPair(kp);

				agreement.Init(kp.Private);

				BigInteger expected = new BigInteger(1, FipsKats.Values[FipsKats.Vec.ECDHHealthVec]);

				if (!expected.Equals(agreement.CalculateAgreement(testOther.Public)))
				{
					Fail("KAT ECDH agreement not verified");
				}
			}
		}

		private static void ecPrimitiveZTest()
		{
			SelfTestExecutor.Validate(Alg, new PrimitiveZTest());
		}

		private class PrimitiveZTest : VariantInternalKatTest
		{
			internal PrimitiveZTest() : base(Alg)
			{
			}

			internal override void Evaluate()
			{
				X9ECParameters p = NistNamedCurves.GetByName("P-256");
				Org.BouncyCastle.Crypto.Internal.Parameters.EcDomainParameters parameters = new Org.BouncyCastle.Crypto.Internal.Parameters.EcDomainParameters(p.Curve, p.G, p.N, p.H);
				BigInteger dValue = new BigInteger(1, FipsKats.Values[FipsKats.Vec.ECPrimitiveStartupVec]);
               
				ECPoint Q = parameters.Curve.DecodePoint(Hex.Decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D"));

                if (!Q.Equals(parameters.G.Multiply(dValue)))
				{
					Fail("EC primitive 'Z' computation failed");
				}
			}
		}

		private static AsymmetricCipherKeyPair getTestKeyPair(AsymmetricCipherKeyPair kp)
		{
			ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)kp.Private;
			EcDomainParameters ecDomainParameters = privKey.Parameters;

			BigInteger testD = privKey.D.Add(TEST_D_OFFSET).Mod(ecDomainParameters.N);

			if (testD.CompareTo(BigInteger.Two) < 0)
			{
				testD = testD.Add(TEST_D_OFFSET);
			}

			ECPrivateKeyParameters testPriv = new ECPrivateKeyParameters(testD, ecDomainParameters);
			ECPublicKeyParameters testPub = new ECPublicKeyParameters(ecDomainParameters.G.Multiply(testD), ecDomainParameters);

			return new AsymmetricCipherKeyPair(testPub, testPriv);
		}

		private static void validateCurveSize(Algorithm algorithm, ECDomainParameters domainParameters)
		{
			// curve size needs to offer 112 bits of security.
			if (domainParameters.Curve.FieldSize < MIN_FIPS_FIELD_SIZE)
			{
				throw new CryptoUnapprovedOperationError("Attempt to use curve with field size less than " + MIN_FIPS_FIELD_SIZE + " bits", algorithm);
			}
		}

		private static Org.BouncyCastle.Crypto.Internal.Parameters.EcDomainParameters getDomainParams(Org.BouncyCastle.Crypto.Asymmetric.ECDomainParameters curveParams)
		{
			if (curveParams is NamedECDomainParameters)
			{
				return new Org.BouncyCastle.Crypto.Internal.Parameters.ECNamedDomainParameters(((NamedECDomainParameters)curveParams).ID, curveParams.Curve, curveParams.G, curveParams.N, curveParams.H, curveParams.GetSeed());
			}
			return new Org.BouncyCastle.Crypto.Internal.Parameters.EcDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H, curveParams.GetSeed());
		}

		private static Org.BouncyCastle.Crypto.Internal.Parameters.ECPublicKeyParameters GetPublicKeyParameters(AsymmetricECPublicKey k)
		{
			return new Org.BouncyCastle.Crypto.Internal.Parameters.ECPublicKeyParameters(k.W, getDomainParams(k.DomainParameters));
		}

		private static Org.BouncyCastle.Crypto.Internal.Parameters.ECPrivateKeyParameters GetPrivateKeyParameters(AsymmetricECPrivateKey k)
		{
			return new Org.BouncyCastle.Crypto.Internal.Parameters.ECPrivateKeyParameters(k.S, getDomainParams(k.DomainParameters));
		}
	}
}

