using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Wrappers
{

    /**
     * an implementation of the AES Key Wrapper from the NIST Key Wrap
     * Specification as described in RFC 3394/SP800-38F.
     * <p/>
     * For further details see: <a href="http://www.ietf.org/rfc/rfc3394.txt">http://www.ietf.org/rfc/rfc3394.txt</a>
     * and  <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
     */
    internal class SP80038FWrapEngine : SP80038FWrapper
    {
        /**
         * Create a RFC 3394 WrapEngine specifying the direction for wrapping and unwrapping..
         *
         * @param engine the block cipher to be used for wrapping.
         * @param useReverseDirection true if engine should be used in decryption mode for wrapping, false otherwise.
         */
        public SP80038FWrapEngine(IBlockCipher engine, bool useReverseDirection) : base(engine, ivKW, useReverseDirection)
        {
        }

        public override string AlgorithmName
        {
            get
            {
                return engine.AlgorithmName + "/KW";
            }
        }

        public override byte[] Wrap(
            byte[] input,
            int inOff,
            int inLen)
        {
            if (!forWrapping)
            {
                throw new InvalidOperationException("not set for wrapping");
            }

            int n = inLen / delta;

            if ((n * delta) != inLen)
            {
                throw new DataLengthException("wrap data must be a multiple of " + delta + " bytes");
            }

            byte[] block = new byte[inLen + iv.Length];

            Array.Copy(iv, 0, block, 0, iv.Length);
            Array.Copy(input, inOff, block, iv.Length, inLen);

            return W(n, block);
        }

        public override byte[] Unwrap(
            byte[] input,
            int inOff,
            int inLen)
        {
            if (forWrapping)
            {
                throw new InvalidOperationException("not set for unwrapping");
            }

            int n = inLen / delta;

            if ((n * delta) != inLen)
            {
                throw new InvalidCipherTextException("unwrap data must be a multiple of " + delta + " bytes");
            }

            byte[] block = new byte[inLen - iv.Length];
            byte[] a = new byte[iv.Length];

            Array.Copy(input, inOff, a, 0, iv.Length);
            Array.Copy(input, inOff + iv.Length, block, 0, inLen - iv.Length);

            invW(n, block, a);

            if (!Arrays.ConstantTimeAreEqual(a, iv))
            {
                throw new InvalidCipherTextException("checksum failed");
            }

            return block;
        }
    }
}
