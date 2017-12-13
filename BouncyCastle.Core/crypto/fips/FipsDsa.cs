using System;

using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved implementations of DSA based algorithms.
    /// </summary>
    public class FipsDsa
    {
        /// <summary>
        /// DSA key marker, can be used for creating general purpose DSA keys.
        /// </summary>
        public static readonly FipsAlgorithm Alg = new FipsAlgorithm("DSA");

        /// <summary>
        /// DSA algorithm parameter source - default is SHA-384
        /// </summary>
        public static readonly SignatureParameters Dsa = new SignatureParameters(new FipsAlgorithm(Alg, AlgorithmMode.DSA), FipsShs.Sha384);

        private static readonly IEngineProvider<DsaSigner> ENGINE_PROVIDER;

        static FipsDsa()
        {
            IEngineProvider<DsaSigner> provider = new DsaProvider();

            // FSM_STATE:3.DSA.0,"POWER ON SELF-TEST", "DSA SIGN VERIFY KAT", "The module is performing ECDSA sign and verify KAT self-test"
            // FSM_TRANS:3.DSA.0,"POWER ON SELF-TEST", "DSA SIGN VERIFY KAT", "Invoke DSA Sign/Verify KAT self-test"
            provider.CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.DSA.1,"DSA SIGN VERIFY KAT", "POWER ON SELF-TEST", "DSA Sign/Verify KAT self-test successful completion"

            ENGINE_PROVIDER = provider;
        }

        /// <summary>
        /// Configuration parameters for DSA signatures.
        /// </summary>
        public class SignatureParameters : SignatureParameters<SignatureParameters, FipsAlgorithm, FipsDigestAlgorithm>
        {
            internal SignatureParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm) : base(algorithm, digestAlgorithm)
            {
            }

            internal override SignatureParameters CreateParameter(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm)
            {
                return new SignatureParameters(algorithm, digestAlgorithm);
            }
        }

        /// <summary>
        /// Parameters for DSA key pair generation.
        /// </summary>
        public class KeyGenerationParameters : FipsParameters, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
        {
            private readonly DsaDomainParameters domainParameters;

            /// <summary>
            /// Base constructor for the default algorithm ID.
            /// </summary>
            /// <param name="domainParameters">DSA domain parameters representing the parameter set any generated keys will be for.</param>
            public KeyGenerationParameters(DsaDomainParameters domainParameters) : base(Alg)
            {
                this.domainParameters = domainParameters;
            }

            /// <summary>
            /// Return the DSA domain parameters for this object.
            /// </summary>
            /// <value>The DSA domain parameter set.</value>
            public DsaDomainParameters DomainParameters
            {
                get
                {
                    return domainParameters;
                }
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyPairGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Parameters for DSA domain parameter generation.
        /// </summary>
        public class DomainGenParameters : Parameters<FipsAlgorithm>, IGenerationServiceType<DomainParametersGenerator>, IGenerationService<DomainParametersGenerator>
        {
            private readonly int mL;
            private readonly int mN;
            private readonly int mCertainty;

            private readonly BigInteger mP;
            private readonly BigInteger mQ;
            private readonly byte[] seed;
            private readonly int mUsageIndex;

            private readonly FipsDigestAlgorithm mDigest;

            /// <summary>
            /// Construct just from strength (L) with a default value for N (160 for 1024, 256 for greater)
            /// and a default certainty.
            /// </summary>
            /// <param name="strength">Desired length of prime P in bits (the effective key size).</param>
            public DomainGenParameters(int strength) : this(strength, (strength > 1024) ? 256 : 160, PrimeCertaintyCalculator.GetDefaultCertainty(strength), null, null, null, -1)
            {
                // Valid N for 2048/3072 , N for 1024
            }

            /// <summary>
            /// Construct without a usage index, this will do a random construction of G.
            /// </summary>
            /// <param name="L">Desired length of prime P in bits (the effective key size).</param>
            /// <param name="N">Desired length of prime Q in bits.</param>
            public DomainGenParameters(int L, int N) : this(L, N, PrimeCertaintyCalculator.GetDefaultCertainty(L), null, null, null, -1)
            {
            }

            /// <summary>
            /// Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
            /// </summary>
            /// <param name="L">Desired length of prime P in bits (the effective key size).</param>
            /// <param name="N">Desired length of prime Q in bits.</param>
            /// <param name="usageIndex">A valid usage index.</param>
            public DomainGenParameters(int L, int N, int usageIndex) : this(L, N, PrimeCertaintyCalculator.GetDefaultCertainty(L), null, null, null, usageIndex)
            {
            }

            /// <summary>
            /// Construct from initial prime values, this will do a random construction of G.
            /// </summary>
            /// <param name="p">The prime P.</param>
            /// <param name="q">The prime Q.</param>
            public DomainGenParameters(BigInteger p, BigInteger q) : this(p.BitLength, q.BitLength, 0, p, q, null, -1)
            {
            }

            /// <summary>
            /// Construct for a specific usage index and initial prime values - this has the effect of using verifiable canonical generation of G.
            /// </summary>
            /// <param name="p">The prime P.</param>
            /// <param name="q">The prime Q.</param>
            /// <param name="seed">Seed used in the generation of (p, q).</param>
            /// <param name="usageIndex">A valid usage index.</param>
            public DomainGenParameters(BigInteger p, BigInteger q, byte[] seed, int usageIndex) : this(p.BitLength, q.BitLength, 0, p, q, Arrays.Clone(seed), usageIndex)
            {
            }

            DomainGenParameters(int L, int N, int certainty, BigInteger p, BigInteger q, byte[] seed, int usageIndex) : this(FipsShs.Sha256, L, N, certainty, p, q, Arrays.Clone(seed), usageIndex)
            {
            }

            DomainGenParameters(FipsDigestAlgorithm digest, int L, int N, int certainty, BigInteger p, BigInteger q, byte[] seed, int usageIndex) : base(Alg)
            {

                    if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    if (p == null && certainty < PrimeCertaintyCalculator.GetDefaultCertainty(L))
                    {
                        throw new CryptoUnapprovedOperationError("Prime generation certainty " + certainty + " inadequate for parameters of " + L + " bits", this.Algorithm);
                    }
                }

                if (usageIndex > 255)
                {
                    throw new ArgumentException("Usage index must be in range 0 to 255 (or -1 to ignore)");
                }

                this.mDigest = digest;
                this.mL = L;
                this.mN = N;
                this.mCertainty = certainty;
                this.mP = p;
                this.mQ = q;
                this.seed = seed;
                this.mUsageIndex = usageIndex;
            }

            public int L
            {
                get
                {
                    return this.mL;
                }
            }

            public int N
            {
                get
                {
                    return this.mN;
                }
            }

            public int Certainty
            {
                get
                {
                    return this.mCertainty;
                }
            }

            public DomainGenParameters WithCertainty(int certainty)
            {
                return new DomainGenParameters(mDigest, mL, mN, certainty, mP, mQ, Arrays.Clone(seed), mUsageIndex);
            }

            public BigInteger P
            {
                get
                {
                    return this.mP;
                }
            }

            public BigInteger Q
            {
                get
                {
                    return this.mQ;
                }
            }

            public int UsageIndex
            {
                get
                {
                    return mUsageIndex;
                }
            }

            public byte[] GetSeed()
            {
                return Arrays.Clone(seed);
            }

            public FipsDigestAlgorithm Digest
            {
                get
                {
                    return mDigest;
                }
            }

            public DomainGenParameters WithDigest(FipsDigestAlgorithm digest)
            {
                return new DomainGenParameters(digest, mL, mN, mCertainty, mP, mQ, Arrays.Clone(seed), mUsageIndex);
            }

            Func<IParameters<Algorithm>, SecureRandom, DomainParametersGenerator> IGenerationService<DomainParametersGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new DomainParametersGenerator(parameters as DomainGenParameters, random);
            }
        }

        private FipsDsa()
        {

        }

        /// <summary>
        /// Domain parameter generator for DSA.
        /// </summary>
        public class DomainParametersGenerator
        {
            private readonly SecureRandom random;
            private readonly DomainGenParameters parameters;
            private readonly FipsDigestAlgorithm digestAlgorithm;

            /// <summary>
            /// Base constructor.
            /// </summary>
            /// <param name="parameters">domain generation parameters.</param>
            /// <param name="random">A source of randomness for the parameter generation.</param>
            internal DomainParametersGenerator(DomainGenParameters parameters, SecureRandom random)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    int effSizeInBits = parameters.L;

                    if (effSizeInBits != 2048 && effSizeInBits != 3072)
                    {
                        throw new CryptoUnapprovedOperationError("attempt to create parameters with unapproved key size [" + effSizeInBits + "]", Alg);
                    }

                    Utils.ValidateRandom(random, Utils.GetAsymmetricSecurityStrength(effSizeInBits), Alg, "attempt to create parameters with unapproved RNG");
                }

                this.digestAlgorithm = parameters.Digest;
                this.parameters = parameters;
                this.random = random;
            }

            /// <summary>
            /// Generate a new set of DSA domain parameters.
            /// </summary>
            /// <returns>A new set of DSADomainParameters</returns>
            public DsaDomainParameters GenerateDomainParameters()
            {
                if (parameters.P != null)
                {
                    byte[] seed = parameters.GetSeed();
                    if (seed != null && parameters.UsageIndex >= 0)
                    {
                        BigInteger g = DsaParametersGenerator.CalculateGenerator_FIPS186_3_Verifiable(FipsShs.CreateDigest(digestAlgorithm), parameters.P, parameters.Q, seed, parameters.UsageIndex);

                        return new DsaDomainParameters(parameters.P, parameters.Q, g, new Org.BouncyCastle.Crypto.Asymmetric.DsaValidationParameters(seed, -1, parameters.UsageIndex));
                    }
                    else
                    {
                        BigInteger g = DsaParametersGenerator.CalculateGenerator_FIPS186_3_Unverifiable(parameters.P, parameters.Q, random);

                        return new DsaDomainParameters(parameters.P, parameters.Q, g, null);
                    }
                }
                else
                {
                    DsaParametersGenerator pGen = new DsaParametersGenerator(FipsShs.CreateDigest(digestAlgorithm));

                    DsaParameterGenerationParameters dsaGenParameters = new DsaParameterGenerationParameters(
                        parameters.L, parameters.N, parameters.Certainty, random, parameters.UsageIndex);

                    pGen.Init(dsaGenParameters);

                    DsaParameters p = pGen.GenerateParameters();

                    Org.BouncyCastle.Crypto.Internal.Parameters.DsaValidationParameters validationParameters = p.ValidationParameters;

                    return new DsaDomainParameters(p.P, p.Q, p.G, new Org.BouncyCastle.Crypto.Asymmetric.DsaValidationParameters(validationParameters.GetSeed(), validationParameters.Counter, validationParameters.UsageIndex));
                }
            }
        }

        /// <summary>
        /// Domain parameter validator for DSA.
        /// </summary>
        public class DomainParametersValidator
        {
            public enum Version
            {
                FipsPub186_2,
                FipsPub186_4
            }

            private readonly Version version;
            private readonly FipsDigestAlgorithm digestAlgorithm;
            private readonly SecureRandom random;

            /// <summary>
            /// Base constructor - for 186-4
            /// </summary>
            /// <param name="digestAlgorithm">Digest to use in prime calculations.</param>
            /// <param name="random">Source of randomness for prime number testing.</param>
            public DomainParametersValidator(FipsDigestAlgorithm digestAlgorithm, SecureRandom random) : this(Version.FipsPub186_4, digestAlgorithm, random)
            {

            }

            /// <summary>
            /// Base constructor.
            /// </summary>
            /// <param name="version">The version of DSS the validator is for.</param>
            /// <param name="digestAlgorithm">Digest to use in prime calculations.</param>
            /// <param name="random">Source of randomness for prime number testing.</param>
            public DomainParametersValidator(Version version, FipsDigestAlgorithm digestAlgorithm, SecureRandom random)
            {
                if (Version.FipsPub186_2 == version && digestAlgorithm != FipsShs.Sha1.Algorithm)
                {
                    throw new ArgumentException("186-2 can only validate with SHA-1");
                }

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    Utils.ValidateRandom(random, "FIPS SecureRandom required for DSA parameter validation in approved mode.");
                }

                this.version = version;
                this.digestAlgorithm = digestAlgorithm;
                this.random = random;
            }

            private static int getMinimumIterations(int L)
            {
                // Values based on FIPS 186-4 C.3 Table C.1
                return L <= 1024 ? 40 : (48 + 8 * ((L - 1) / 1024));
            }

            /// <summary>
            /// Validate P and Q against the passed in seed and counter.
            /// </summary>
            /// <param name="p">The prime P.</param>
            /// <param name="q">The prime Q.</param>
            /// <param name="seed">The seed P and Q were derived from.</param>
            /// <param name="counter">The number of iterations required to derive P.</param>
            /// <returns>true if the P and Q values are the expected ones, false otherwise.</returns>
            public bool IsValidPAndQ(BigInteger p, BigInteger q, byte[] seed, int counter)
            {
                IDigest hash = FipsShs.CreateDigest(digestAlgorithm);

                if (Version.FipsPub186_2 == version)
                {
                    if (p.BitLength != 1024 || q.BitLength != 160 || counter > 4095)
                    {
                        return false;
                    }

                    if (seed.Length < 20)
                    {
                        return false;
                    }

                    BigInteger computed_q = Digest(hash, seed).Xor(Digest(hash, SeedPlus1(seed)));

                    computed_q = computed_q.SetBit(0).SetBit(159);

                    if (!q.Equals(computed_q) || !IsProbablePrime(q, getMinimumIterations(1024)))
                    {
                        return false;
                    }

                    BigInteger extra = BigInteger.One.ShiftLeft(64);

                    int i = 0;
                    byte[] offset = Arrays.Clone(seed);
                    Inc(offset);

                    bool computedPIsPrime = false;
                    BigInteger computed_p = null;
                    while (i <= counter)
                    {
                        BigInteger W = BigInteger.Zero;
                        for (int j = 0; j <= 5; j++)
                        {
                            Inc(offset);
                            W = W.Add(Digest(hash, offset).ShiftLeft(160 * j));
                        }
                        // (V[6] mod 2**63) * 2**960
                        Inc(offset);
                        W = W.Add(
                            Digest(hash, offset).Mod(extra).ShiftLeft(160 * 6));

                        BigInteger X = W.SetBit(1023);
                        BigInteger c = X.Mod(q.ShiftLeft(1));

                        computed_p = X.Subtract(c.Subtract(BigInteger.One));

                        if (computed_p.BitLength == 1024)
                        {
                            if (IsProbablePrime(computed_p, getMinimumIterations(1024)))
                            {
                                computedPIsPrime = true;
                                break;
                            }
                        }
                        i++;
                    }

                    if (i != counter || !p.Equals(computed_p) || !computedPIsPrime)
                    {
                        return false;
                    }
                }
                else
                {
                    int L = p.BitLength;
                    int N = q.BitLength;

                    if (!(L == 1024 && N == 160)
                        && !(L == 2048 && N == 224)
                        && !(L == 2048 && N == 256)
                        && !(L == 3072 && N == 256))
                    {
                        return false;
                    }

                    if (counter > (4 * L - 1))
                    {
                        return false;
                    }

                    if (seed.Length * 8 < N)
                    {
                        return false;
                    }

                    BigInteger twoPowNminus1 = BigInteger.One.ShiftLeft(N - 1);
                    BigInteger U = Digest(hash, seed).Mod(twoPowNminus1);

                    BigInteger computed_q = U.SetBit(0).SetBit(N - 1);

                    if (!q.Equals(computed_q) || !IsProbablePrime(q, getMinimumIterations(L)))
                    {
                        return false;
                    }

                    int outlen = hash.GetDigestSize() * 8;

                    int n = (L + outlen - 1) / outlen - 1;
                    int b = L - (n * outlen);
                    BigInteger extra = BigInteger.One.ShiftLeft(b);

                    int i = 0;
                    byte[] offset = Arrays.Clone(seed);

                    bool computedPIsPrime = false;
                    BigInteger computed_p = null;

                    while (i <= counter)
                    {
                        BigInteger W = BigInteger.Zero;
                        for (int j = 0; j < n; j++)
                        {
                            Inc(offset);
                            W = W.Add(Digest(hash, offset).ShiftLeft(outlen * j));
                        }

                        Inc(offset);
                        W = W.Add(Digest(hash, offset).Mod(extra).ShiftLeft(outlen * n));

                        BigInteger X = W.SetBit(L - 1);
                        BigInteger c = X.Mod(q.ShiftLeft(1));

                        computed_p = X.Subtract(c.Subtract(BigInteger.One));

                        if (computed_p.BitLength == L)
                        {
                            if (IsProbablePrime(computed_p, getMinimumIterations(L)))
                            {
                                computedPIsPrime = true;
                                break;
                            }
                        }
                        i++;
                    }

                    if (i != counter || !p.Equals(computed_p) || !computedPIsPrime)
                    {
                        return false;
                    }
                }

                return true;
            }

            /// <summary>
            /// Do a partial validation of g against p and q.
            /// </summary>
            /// <param name="p">The prime P.</param>
            /// <param name="q">The prime Q.</param>
            /// <param name="g">The generator G associated with P and Q.</param>
            /// <returns>true if the generator is partially valid, false otherwise.</returns>
            public bool IsPartiallyValidG(BigInteger p, BigInteger q, BigInteger g)
            {
                if (BigInteger.Two.CompareTo(g) > 0 || p.Subtract(BigInteger.One).CompareTo(g) < 0)
                {
                    return false;
                }

                return g.ModPow(q, p).Equals(BigInteger.One);
            }

            /// <summary>
            /// Do a full validation of g against p and q by including the seed and index
            /// associated with g's related parameters.
            /// </summary>
            /// <param name="p">The prime P.</param>
            /// <param name="q">The prime Q.</param>
            /// <param name="seed">The domain parameter seed used to generate p and q.</param>
            /// <param name="index">The 8 bit usage index for G.</param>
            /// <param name="g">The generator G associated with P and Q.</param>
            /// <returns>true if the generator is valid, false otherwise.</returns>
            public bool IsValidG(BigInteger p, BigInteger q, byte[] seed, byte index, BigInteger g)
            {
                IDigest hash = FipsShs.CreateDigest(digestAlgorithm);

                if (BigInteger.Two.CompareTo(g) > 0 || p.Subtract(BigInteger.One).CompareTo(g) < 0)
                {
                    return false;
                }

                if (!g.ModPow(q, p).Equals(BigInteger.One))
                {
                    return false;
                }

                BigInteger e = p.Subtract(BigInteger.One).Divide(q);
                int count = 0;

                byte[] counter = new byte[3];
                counter[0] = index;
                byte[] U = Arrays.ConcatenateAll(seed, Hex.Decode("6767656E"), counter);

                BigInteger computed_g = null;
                // in our case the wrap check for count terminates at it's largest value.
                while (++count < (1 << 16))
                {
                    Inc(U);

                    computed_g = Digest(hash, U).ModPow(e, p);

                    if (computed_g.CompareTo(BigInteger.One) <= 0)
                    {
                        continue;
                    }

                    break;
                }

                return g.Equals(computed_g);
            }

            private BigInteger Digest(IDigest hash, byte[] input)
            {
                byte[] res = Digests.DoFinal(hash, input, 0, input.Length);
                return new BigInteger(1, res);
            }

            private byte[] SeedPlus1(byte[] seed)
            {
                return Inc(Arrays.Clone(seed));
            }

            private byte[] Inc(byte[] value)
            {
                // increment counter by 1.
                for (int i = value.Length - 1; i >= 0 && ++value[i] == 0; i--)
                {
                    ; // do nothing - pre-increment and test for 0 in counter does the job.
                }

                return value;
            }

            private bool IsProbablePrime(BigInteger x, int iterations)
            {
                /*
                 * Primes class for FIPS 186-4 C.3 primality checking
                 */
                return !Primes.HasAnySmallFactors(x) && Primes.IsMRProbablePrime(x, random, iterations);
            }
        }

        /// <summary>
        /// Key pair generator for DSA. Create one these via CryptoServicesRegistrar.CreateGenerator() using the KeyGenerationParameters
        /// object as the key.
        /// </summary>
        public class KeyPairGenerator : AsymmetricKeyPairGenerator<KeyGenerationParameters, AsymmetricDsaPublicKey, AsymmetricDsaPrivateKey>
        {
            private readonly DsaKeyPairGenerator engine = new DsaKeyPairGenerator();
            private readonly DsaDomainParameters domainParameters;
            private readonly DsaKeyGenerationParameters param;

            /// <summary>
            /// Construct a key pair generator for DSA keys.
            /// </summary>
            /// <param name="keyGenParameters">Domain parameters and algorithm for the generated key.</param>
            /// <param name="random">A source of randomness for calculating the private value.</param>
            internal KeyPairGenerator(KeyGenerationParameters keyGenParameters, SecureRandom random) : base(keyGenParameters)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    int effSizeInBits = keyGenParameters.DomainParameters.P.BitLength;

                    if (effSizeInBits != 2048 && effSizeInBits != 3072)
                    {
                        throw new CryptoUnapprovedOperationError("attempt to create key pair with unapproved key size [" + effSizeInBits + "]", keyGenParameters.Algorithm);
                    }

                    Utils.ValidateKeyPairGenRandom(random, Utils.GetAsymmetricSecurityStrength(effSizeInBits), keyGenParameters.Algorithm);
                }
    
                this.domainParameters = keyGenParameters.DomainParameters;

                this.param = new DsaKeyGenerationParameters(random, getDomainParams(domainParameters));
                this.engine.Init(param);
            }

            /// <summary>
            /// Generate a new DSA key pair.
            /// </summary>
            /// <returns>A new AsymmetricKeyPair containing a DSA key pair.</returns>
            public override AsymmetricKeyPair<AsymmetricDsaPublicKey, AsymmetricDsaPrivateKey> GenerateKeyPair()
            {
                AsymmetricCipherKeyPair kp = engine.GenerateKeyPair();

                DsaPublicKeyParameters pubKey = (DsaPublicKeyParameters)kp.Public;
                DsaPrivateKeyParameters prvKey = (DsaPrivateKeyParameters)kp.Private;

                FipsAlgorithm algorithm = this.Parameters.Algorithm;

                // FSM_STATE:5.3, "DSA PAIRWISE CONSISTENCY TEST", "The module is performing DSA Pairwise Consistency self-test"
                // FSM_TRANS:5.DSA.0,"CONDITIONAL TEST", "DSA PAIRWISE CONSISTENCY TEST", "Invoke DSA Pairwise Consistency test"
                validateKeyPair(kp);
                // FSM_TRANS:5.DSA.1,"DSA PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "DSA Pairwise Consistency test successful"

                return new AsymmetricKeyPair<AsymmetricDsaPublicKey, AsymmetricDsaPrivateKey>(new AsymmetricDsaPublicKey(algorithm, domainParameters, pubKey.Y), new AsymmetricDsaPrivateKey(algorithm, domainParameters, prvKey.X));
            }
        }

        private static ICipherParameters GetPublicParameters(IKey key)
        {
            if (key is KeyWithRandom)
            {
                throw new ArgumentException("SecureRandom not required: " + Alg.Name);
            }

            AsymmetricDsaPublicKey dsaPublicKey = (AsymmetricDsaPublicKey)key;
            DsaPublicKeyParameters publicKeyParameters = new DsaPublicKeyParameters(dsaPublicKey.Y, getDomainParams(dsaPublicKey.DomainParameters));

            int effSizeInBits = publicKeyParameters.Parameters.P.BitLength;

            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                if (effSizeInBits != 1024 && effSizeInBits != 2048 && effSizeInBits != 3072)
                {
                    throw new CryptoUnapprovedOperationError("attempt to create verifier with unapproved keysize [" + effSizeInBits + "]", Alg);
                }
            }

            return publicKeyParameters;
        }

        private static ICipherParameters GetPrivateParameters(IKey key)
        {
            DsaPrivateKeyParameters privateKeyParameters;
            SecureRandom random;

            if (key is KeyWithRandom)
            {
                KeyWithRandom k = (KeyWithRandom)key;

                privateKeyParameters = GetPrivateKeyParameters((AsymmetricDsaPrivateKey)k.Key);
                random = k.Random;
            }
            else
            {
                privateKeyParameters = GetPrivateKeyParameters((AsymmetricDsaPrivateKey)key);
                random = CryptoServicesRegistrar.GetSecureRandom();
            }

            int effSizeInBits = privateKeyParameters.Parameters.P.BitLength;

            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                if (effSizeInBits != 2048 && effSizeInBits != 3072)
                {
                    throw new CryptoUnapprovedOperationError("attempt to create signer with unapproved keysize [" + effSizeInBits + "]", Alg);
                }
            }

            return new ParametersWithRandom(privateKeyParameters, random);
        }

        internal class SignerProvider : IEngineProvider<ISigner>
        {
            private readonly SignatureParameters parameters;
            private readonly ICipherParameters sigParams;

            internal SignerProvider(SignatureParameters parameters, IKey key)
            {
                this.parameters = parameters;
                if (key is AsymmetricDsaPublicKey)
                {
                    this.sigParams = GetPublicParameters(key);
                }
                else
                {
                    this.sigParams = GetPrivateParameters(key);
                }
            }

            internal SignerProvider(SignatureParameters parameters, ICipherParameters sigParams)
            {
                this.parameters = parameters;
                this.sigParams = sigParams;
            }

            public ISigner CreateEngine(EngineUsage usage)
            {
                ISigner sig = new DsaDigestSigner(new DsaSigner(), FipsShs.CreateDigest(parameters.DigestAlgorithm));

                sig.Init((usage == EngineUsage.SIGNING), sigParams);

                return sig;
            }
        }

        private static DsaParameters getDomainParams(DsaDomainParameters dsaParams)
        {
            return new DsaParameters(dsaParams.P, dsaParams.Q, dsaParams.G);
        }

        private static DsaPrivateKeyParameters GetPrivateKeyParameters(AsymmetricDsaPrivateKey privKey)
        {
            return new DsaPrivateKeyParameters(privKey.X, getDomainParams(privKey.DomainParameters));
        }

        private static void validateKeyPair(AsymmetricCipherKeyPair kp)
        {
            SelfTestExecutor.Validate(Alg, kp, new DsaKeyPairValidationTest());
        }

        internal class DsaKeyPairValidationTest : IConsistencyTest<AsymmetricCipherKeyPair>
        {
            public bool HasTestPassed(AsymmetricCipherKeyPair kp)
            {
                byte[] data = Hex.Decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                DsaSigner signer = ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);

                signer.Init(true, new ParametersWithRandom(kp.Private, Utils.testRandom));

                BigInteger[] rv = signer.GenerateSignature(data);

                signer.Init(false, kp.Public);

                return signer.VerifySignature(FipsKats.Values[FipsKats.Vec.DsaKeyPairConsistencyVec], rv[0], rv[1]);
            }
        }

        private class DsaProvider : IEngineProvider<DsaSigner>
        {
            public DsaSigner CreateEngine(EngineUsage usage)
            {
                // We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
                return SelfTestExecutor.Validate(Alg, new DsaSigner(), new DsaKatTest());
            }
        }

        internal class DsaKatTest : VariantKatTest<DsaSigner>
        {
            // We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
            internal override void Evaluate(DsaSigner signer)
            {
                BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);

                BigInteger p = new BigInteger(
                    "C196BA05AC29E1F9C3C72D56DFFC6154" +
                        "A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A06" +
                        "7CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE4" +
                        "28782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE6" +
                        "19ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1" +
                        "E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD9" +
                        "2D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BF" +
                        "FAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E" +
                        "5320121496DC65B3930E38047294FF877831A16D5228418D" +
                        "E8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A040" +
                        "2A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);

                BigInteger g = new BigInteger(
                    "A59A749A11242C58C894E9E5A91804E8" +
                        "FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35F" +
                        "C9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E50" +
                        "48B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B" +
                        "6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B715959" +
                        "2E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E574" +
                        "5EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDF" +
                        "D049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E69" +
                        "5515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE" +
                        "7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED20" +
                        "0AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

                DsaKeyPairGenerator kpGen = new DsaKeyPairGenerator();

                kpGen.Init(new DsaKeyGenerationParameters(
                    new TestRandomBigInteger(Hex.Decode("947813B589EDBA642411AD79205E43CE9B859327A4F84CF4B02628DB058A7B22771EA1852903711B")),
                    new DsaParameters(p, q, g)));

                AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                signer.Init(true, new ParametersWithRandom(kp.Private, new TestRandomBigInteger(Hex.Decode("735959CC4463B8B440E407EECA8A473BF6A6D1FE657546F67D401F05"))));

                byte[] msg = Hex.Decode("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7");

                BigInteger[] sig = signer.GenerateSignature(msg);

                signer.Init(false, kp.Public);

                if (!signer.VerifySignature(FipsKats.Values[FipsKats.Vec.DsaStartupVec], sig[0], sig[1]))
                {
                    Fail("KAT signature not verified");
                }
            }
        }
    }
}

