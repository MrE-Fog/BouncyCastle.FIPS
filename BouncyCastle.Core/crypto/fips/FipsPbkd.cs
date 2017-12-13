using System;

using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved implementations of Password-Based Key Derivation algorithms.
    /// </summary>
	public class FipsPbkd
    {
        /// <summary>
        /// Algorithm ID for PBKDF2 (PKCS#5 scheme 2)
        /// </summary>
        private static readonly FipsAlgorithm ALGORITHM_PBKDF2 = new FipsAlgorithm("PBKDF2");

        /// <summary>
        /// PBKDF2 deriver source - default PRF is HMAC(SHA-1)
        /// </summary>
        public static readonly BuilderService PbkdF2 = new BuilderService();

        private FipsPbkd()
        {

        }

        public class BuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<IPasswordBasedDeriverBuilderService<Parameters>>, IBuilderService<IPasswordBasedDeriverBuilderService<Parameters>>
        {
            ServiceImpl service = new ServiceImpl();

            internal BuilderService() : base(ALGORITHM_PBKDF2)
            {

            }

            Func<IParameters<Algorithm>, IPasswordBasedDeriverBuilderService<Parameters>> IBuilderService<IPasswordBasedDeriverBuilderService<Parameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => service;
            }
        }

        /// <summary>
        /// PBKD parameters.
        /// </summary>
        public class Parameters : Parameters<FipsAlgorithm>
        {
            private readonly FipsDigestAlgorithm digestAlgorithm;
            private readonly PasswordConverter converter;
            private readonly byte[] password;

            private readonly byte[] salt;
            private readonly int iterationCount;

            internal Parameters(FipsDigestAlgorithm digestAlgorithm, PasswordConverter converter, byte[] password, int iterationCount, byte[] salt) : base(ALGORITHM_PBKDF2)
            {
                this.digestAlgorithm = digestAlgorithm;
                this.converter = converter;
                this.password = password;
                this.iterationCount = iterationCount;
                this.salt = salt;
            }

            internal Parameters(FipsDigestAlgorithm algorithm, PasswordConverter converter, char[] password) : this(algorithm, converter, converter.Convert(password), 1024, new byte[20])
            {
            }

            ~Parameters()
            {
                // explicitly zeroize password on deallocation
                if (password != null)
                {
                    Array.Clear(password, 0, password.Length);
                }
            }

            internal byte[] Password
            {
                get
                {
                    return Arrays.Clone(password);
                }
            }

            public FipsDigestAlgorithm Prf
            {
                get
                {
                    return digestAlgorithm;
                }
            }

            public byte[] Salt
            {
                get
                {
                    return Arrays.Clone(salt);
                }
            }

            public int IterationCount
            {
                get
                {
                    return iterationCount;
                }
            }

            public PasswordConverter Converter
            {
                get
                {
                    return converter;
                }
            }
        }

        internal class ServiceImpl : IPasswordBasedDeriverBuilderService<Parameters>
        {
            public IPasswordBasedDeriverBuilder<Parameters> From(byte[] password)
            {
                return new DeriverBuilder(Arrays.Clone(password), null, FipsShs.Sha1HMac, new byte[20], 1024);
            }

            public IPasswordBasedDeriverBuilder<Parameters> From(PasswordConverter converter, char[] password)
            {
                return new DeriverBuilder(converter.Convert(password), converter, FipsShs.Sha1HMac, new byte[20], 1024);
            }
        }

        internal class DeriverBuilder : IPasswordBasedDeriverBuilder<Parameters>
        {
            private readonly byte[] password;
            private PasswordConverter converter;

            private FipsDigestAlgorithm digestAlgorithm;
            private byte[] salt;
            private int iterationCount;

            internal DeriverBuilder(byte[] password, PasswordConverter converter, FipsDigestAlgorithm digestAlgorithm, byte[] salt, int iterationCount)
            {
                this.digestAlgorithm = digestAlgorithm;
                this.converter = converter;
                this.password = password;
                this.iterationCount = iterationCount;
                this.salt = salt;

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    if (salt.Length < 16)
                    {
                        throw new CryptoUnapprovedOperationError("salt must be at least 128 bits");
                    }
                    if (password.Length < 14)
                    {
                        throw new CryptoUnapprovedOperationError("password must be at least 112 bits");
                    }
                }
            }

            public IPasswordBasedDeriver<Parameters> Build()
            {
                Parameters parameters = new Parameters(digestAlgorithm, converter, password, iterationCount, salt);

                Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator(FipsShs.CreateHmac(parameters.Prf));

                gen.Init(parameters.Password, parameters.Salt, parameters.IterationCount);

                return new PasswordBasedDeriver<Parameters>(parameters, gen);
            }

            public IPasswordBasedDeriverBuilder<Parameters> WithIterationCount(int iterationCount)
            {
                return new DeriverBuilder(password, converter, digestAlgorithm, salt, iterationCount);
            }

            public IPasswordBasedDeriverBuilder<Parameters> WithPrf(DigestAlgorithm digestAlgorithm)
            {
                return new DeriverBuilder(password, converter, (FipsDigestAlgorithm)digestAlgorithm, salt, iterationCount);
            }

            public IPasswordBasedDeriverBuilder<Parameters> WithSalt(byte[] salt)
            {
                return new DeriverBuilder(password, converter, digestAlgorithm, Arrays.Clone(salt), iterationCount);
            }
        }
    }
}

