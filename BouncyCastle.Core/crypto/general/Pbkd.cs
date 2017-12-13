using System;

using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    ///  Source class for implementations of Password-Based Key Derivation Algorithms
    /// </summary>
	public class Pbkd
    {
        /// <summary>
        /// Algorithm ID for PKCS#12
        /// </summary>
        internal static readonly GeneralAlgorithm ALGORITHM_PKCS12 = new GeneralAlgorithm("PKCS12");

        /// <summary>
        /// Algorithm ID for OpenSSL
        /// </summary>
        internal static readonly GeneralAlgorithm ALGORITHM_OPENSSL = new GeneralAlgorithm("OpenSSL");

        /// <summary>
        /// PKCS#12 PBE algorithm parameter source - default PRF is SHA-1
        /// </summary>
        public static readonly Pkcs12BuilderService Pkcs12 = new Pkcs12BuilderService();

        /// <summary>
        /// OpenSSL PBE algorithm parameter source - PRF is MD5
        /// </summary>
        public static readonly OpenSslBuilderService OpenSsl = new OpenSslBuilderService();

        private Pbkd()
        {
        }

        /// <summary>
        /// PKCS12 password based key deriver builder service.
        /// </summary>
        public class Pkcs12BuilderService : Parameters<GeneralAlgorithm>, IBuilderServiceType<IPasswordBasedDeriverBuilderService<PbkdParameters>>, IBuilderService<IPasswordBasedDeriverBuilderService<PbkdParameters>>
        {
            Pkcs12ServiceImpl service = new Pkcs12ServiceImpl();

            internal Pkcs12BuilderService() : base(ALGORITHM_PKCS12)
            {
            }

            Func<IParameters<Algorithm>, IPasswordBasedDeriverBuilderService<PbkdParameters>> IBuilderService<IPasswordBasedDeriverBuilderService<PbkdParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => service;
            }
        }

        /// <summary>
        /// OpenSSL password based key deriver builder service.
        /// </summary>
        public class OpenSslBuilderService : Parameters<GeneralAlgorithm>, IBuilderServiceType<IPasswordBasedDeriverBuilderService<OpenSslParameters>>, IBuilderService<IPasswordBasedDeriverBuilderService<OpenSslParameters>>
        {
            OpenSslServiceImpl service = new OpenSslServiceImpl();

            internal OpenSslBuilderService() : base(ALGORITHM_PKCS12)
            {
            }

            Func<IParameters<Algorithm>, IPasswordBasedDeriverBuilderService<OpenSslParameters>> IBuilderService<IPasswordBasedDeriverBuilderService<OpenSslParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => service;
            }
        }

        /// <summary>
        /// General PBKD parameters.
        /// </summary>
        public class PbkdParameters : Parameters<GeneralAlgorithm>
        {
            private readonly DigestAlgorithm digestAlgorithm;
            private readonly PasswordConverter converter;
            private readonly byte[] password;

            private readonly byte[] salt;
            private readonly int iterationCount;

            internal PbkdParameters(DigestAlgorithm digestAlgorithm, PasswordConverter converter, byte[] password, int iterationCount, byte[] salt) : base(ALGORITHM_PKCS12)
            {
                this.digestAlgorithm = digestAlgorithm;
                this.converter = converter;
                this.password = password;
                this.iterationCount = iterationCount;
                this.salt = salt;
            }

            internal PbkdParameters(DigestAlgorithm algorithm, PasswordConverter converter, char[] password) : this(algorithm, converter, converter.Convert(password), 1024, new byte[20])
            {
            }

            ~PbkdParameters()
            {
                if (password != null)
                {
                    Array.Clear(password, 0, password.Length);
                }
            }

            internal byte[] Password
            {
                get { return Arrays.Clone(password); }
            }

            public DigestAlgorithm Prf
            {
                get { return digestAlgorithm; }
            }

            public byte[] Salt
            {
                get { return Arrays.Clone(salt); }
            }

            public int IterationCount
            {
                get { return iterationCount; }
            }

            public PasswordConverter Converter
            {
                get { return converter; }
            }
        }

        /// <summary>
        /// OpenSSL PBKD parameters.
        /// </summary>
        public class OpenSslParameters : Parameters<GeneralAlgorithm>
        {
            private readonly PasswordConverter converter;
            private readonly byte[] password;
            private readonly byte[] salt;

            internal OpenSslParameters(PasswordConverter converter, byte[] password, byte[] salt) : base(ALGORITHM_OPENSSL)
            {
                this.converter = converter;
                this.password = password;
                this.salt = salt;
            }

            internal OpenSslParameters(PasswordConverter converter, char[] password) : this(converter, converter.Convert(password), new byte[20])
            {
            }

            ~OpenSslParameters()
            {
                if (password != null)
                {
                    Array.Clear(password, 0, password.Length);
                }
            }

            internal byte[] Password
            {
                get { return Arrays.Clone(password); }
            }

            public byte[] Salt
            {
                get { return Arrays.Clone(salt); }
            }

            public PasswordConverter Converter
            {
                get { return converter; }
            }
        }

        internal class Pkcs12ServiceImpl : IPasswordBasedDeriverBuilderService<PbkdParameters>
        {
            public IPasswordBasedDeriverBuilder<PbkdParameters> From(byte[] password)
            {
                return new Pkcs12DeriverBuilder(Arrays.Clone(password), null, FipsShs.Sha1, new byte[20], 1024);
            }

            public IPasswordBasedDeriverBuilder<PbkdParameters> From(PasswordConverter converter, char[] password)
            {
                return new Pkcs12DeriverBuilder(converter.Convert(password), converter, FipsShs.Sha1, new byte[20], 1024);
            }
        }

        internal class Pkcs12DeriverBuilder : IPasswordBasedDeriverBuilder<PbkdParameters>
        {
            private readonly byte[] password;
            private PasswordConverter converter;

            private DigestAlgorithm digestAlgorithm;
            private byte[] salt;
            private int iterationCount;

            internal Pkcs12DeriverBuilder(byte[] password, PasswordConverter converter, DigestAlgorithm digestAlgorithm, byte[] salt, int iterationCount)
            {
                this.digestAlgorithm = digestAlgorithm;
                this.converter = converter;
                this.password = password;
                this.iterationCount = iterationCount;
                this.salt = salt;
            }

            public IPasswordBasedDeriver<PbkdParameters> Build()
            {
                Utils.ApprovedModeCheck("PKCS12 PBE", ALGORITHM_OPENSSL);

                PbkdParameters parameters = new PbkdParameters(digestAlgorithm, converter, password, iterationCount, salt);

                Pkcs12ParametersGenerator gen = new Pkcs12ParametersGenerator(FipsShs.CreateDigest(parameters.Prf));

                gen.Init(parameters.Password, parameters.Salt, parameters.IterationCount);

                return new PasswordBasedDeriver<PbkdParameters>(parameters, gen);
            }

            public IPasswordBasedDeriverBuilder<PbkdParameters> WithIterationCount(int iterationCount)
            {
                return new Pkcs12DeriverBuilder(password, converter, digestAlgorithm, salt, iterationCount);
            }

            public IPasswordBasedDeriverBuilder<PbkdParameters> WithPrf(DigestAlgorithm digestAlgorithm)
            {
                return new Pkcs12DeriverBuilder(password, converter, digestAlgorithm, salt, iterationCount);
            }

            public IPasswordBasedDeriverBuilder<PbkdParameters> WithSalt(byte[] salt)
            {
                return new Pkcs12DeriverBuilder(password, converter, digestAlgorithm, Arrays.Clone(salt), iterationCount);
            }
        }

        internal class OpenSslServiceImpl : IPasswordBasedDeriverBuilderService<OpenSslParameters>
        {
            public IPasswordBasedDeriverBuilder<OpenSslParameters> From(byte[] password)
            {
                return new OpenSslDeriverBuilder(Arrays.Clone(password), null, new byte[20]);
            }

            public IPasswordBasedDeriverBuilder<OpenSslParameters> From(PasswordConverter converter, char[] password)
            {
                return new OpenSslDeriverBuilder(converter.Convert(password), converter, new byte[20]);
            }
        }

        internal class OpenSslDeriverBuilder : IPasswordBasedDeriverBuilder<OpenSslParameters>
        {
            private readonly byte[] password;
            private PasswordConverter converter;
            private byte[] salt;

            internal OpenSslDeriverBuilder(byte[] password, PasswordConverter converter, byte[] salt)
            {
                this.converter = converter;
                this.password = password;
                this.salt = salt;
            }

            public IPasswordBasedDeriver<OpenSslParameters> Build()
            {
                Utils.ApprovedModeCheck("OpenSSL PBE", ALGORITHM_OPENSSL);

                OpenSslParameters parameters = new OpenSslParameters(converter, password, salt);

                OpenSslPbeParametersGenerator gen = new OpenSslPbeParametersGenerator();

                gen.Init(parameters.Password, parameters.Salt, 1);

                return new PasswordBasedDeriver<OpenSslParameters>(parameters, gen);
            }

            public IPasswordBasedDeriverBuilder<OpenSslParameters> WithSalt(byte[] salt)
            {
                return new OpenSslDeriverBuilder(password, converter, Arrays.Clone(salt));
            }

            public IPasswordBasedDeriverBuilder<OpenSslParameters> WithPrf(DigestAlgorithm digestAlgorithm)
            {
                throw new NotSupportedException("OpenSsl PBKD has a fixed PRF");
            }

            public IPasswordBasedDeriverBuilder<OpenSslParameters> WithIterationCount(int iterationCount)
            {
                throw new NotSupportedException("OpenSsl PBKD has a fixed iteration count");
            }
        }
    }
}

