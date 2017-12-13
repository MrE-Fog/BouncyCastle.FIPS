using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    /**
     * parameters for Key derivation functions for IEEE P1363a
     */
    internal class KdfParameters : IDerivationParameters
    {
        byte[]  iv;
        byte[]  shared;

        public KdfParameters(
            byte[]  shared,
            byte[]  iv)
        {
            this.shared = shared;
            this.iv = iv;
        }

        public byte[] GetSharedSecret()
        {
            return shared;
        }

        public byte[] GetIV()
        {
            return iv;
        }
    }

}
