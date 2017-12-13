using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Fips
{
    internal class DesEdeKeyGenerator: CipherKeyGenerator
    {
        private readonly FipsAlgorithm algorithm;

    public DesEdeKeyGenerator(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Initialise the key generator - if strength is set to zero
        /// the key generated will be 192 bits in size, otherwise
        /// strength can be 128 or 192 (or 112 or 168 if you don't count
        /// parity bits), depending on whether you wish to do 2-key or 3-key
        /// triple DES.
        /// </summary>
        /// <param name="param">the parameters to be used for key generation</param>
        public new void Init(
            KeyGenerationParameters param)
        {
            this.random = param.Random;
            this.strength = (param.Strength + 7) / 8;

            if (strength == 0 || strength == (168 / 8))
            {
                strength = DesEdeParameters.DesEdeKeyLength;
            }
            else if (strength == (112 / 8))
            {
                strength = 2 * DesParameters.DesKeyLength;
            }
            else if (strength != DesEdeParameters.DesEdeKeyLength
                    && strength != (2 * DesParameters.DesKeyLength))
            {
                throw new ArgumentException("Key must be "
                    + (DesEdeParameters.DesEdeKeyLength * 8) + " or "
                    + (2 * 8 * DesParameters.DesKeyLength)
                    + " bits long: " + algorithm.Name);
            }
        }

        public byte[] generateKey()
        {
            byte[] newKey = new byte[strength];
            int count = 0;

            do
            {
                random.NextBytes(newKey);

                DesParameters.SetOddParity(newKey);
            }
            while (DesEdeParameters.IsWeakKey(newKey, 0, newKey.Length) && !DesEdeParameters.IsRealEdeKey(newKey) && count++ < 10);

            if (DesEdeParameters.IsWeakKey(newKey, 0, newKey.Length) || !DesEdeParameters.IsRealEdeKey(newKey))
            {
                // if this happens there's got to be something terribly wrong.
                throw new CryptoOperationError("Failed to generate a valid TripleDES key: " + algorithm.Name);
            }

            return newKey;
        }
    }
}
