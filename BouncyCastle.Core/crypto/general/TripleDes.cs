using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for non-approved mode Triple-DES based modes and algorithms.
    /// </summary>
    public class TripleDes
    {
        /// <summary>
        /// Triple-DES in OpenPGP CFB Mode.
        /// </summary>
        public static readonly ParametersWithIV OpenPgpCfb = new ParametersWithIV(new GeneralAlgorithm(FipsTripleDes.Alg, AlgorithmMode.OpenPGPCFB));

        /// <summary>
        /// Base class for general Triple-DES parameters requiring an initialization vector.
        /// </summary>
        public class ParametersWithIV
            : ParametersWithIV<ParametersWithIV, GeneralAlgorithm>
        {
            internal ParametersWithIV(GeneralAlgorithm algorithm)
                : this(algorithm, null)
            {
            }

            private ParametersWithIV(GeneralAlgorithm algorithm, byte[] iv)
                : base(algorithm, 16, iv)
            {
            }

            internal override ParametersWithIV CreateParameter(GeneralAlgorithm algorithm, byte[] iv)
            {
                return new ParametersWithIV(algorithm, iv);
            }
        }

        /// <summary>
        /// Base authentication parameters class for use with MACs and AEAD ciphers requiring a nonce or IV.
        /// </summary>
        internal class AuthenticationParametersWithIV  // not used other than for generic (at the moment)
            : AuthenticationParametersWithIV<AuthenticationParametersWithIV, GeneralAlgorithm>
        {
            internal AuthenticationParametersWithIV(GeneralAlgorithm algorithm, int macSize)
                : this(algorithm, macSize, null)
            {
            }

            private AuthenticationParametersWithIV(GeneralAlgorithm algorithm, int macSize, byte[] iv)
                : base(algorithm, macSize, 16, iv)
            {
            }

            internal override AuthenticationParametersWithIV CreateParameter(GeneralAlgorithm algorithm, int macSize, byte[] iv)
            {
                return new AuthenticationParametersWithIV(algorithm, macSize, iv);
            }
        }

        internal class ProviderForIV : GeneralIVBlockCipherProvider<ParametersWithIV, AuthenticationParametersWithIV>
        {
            public ProviderForIV(String name, IEngineProvider<Internal.IBlockCipher> engineProvider)
                : base(name, engineProvider)
            {
            }
        }
    }
}
