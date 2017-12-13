using System;

using Org.BouncyCastle.Crypto.Utilities;
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
    internal class SP80038FWrapWithPaddingEngine : SP80038FWrapper
    {
        /**
         * Create a RFC 3394 WrapEngine specifying the direction for wrapping and unwrapping..
         *
         * @param engine the block cipher to be used for wrapping.
         * @param useReverseDirection true if engine should be used in decryption mode for wrapping, false otherwise.
         */
        public SP80038FWrapWithPaddingEngine(IBlockCipher engine, bool useReverseDirection) : base(engine, ivKWP, useReverseDirection)
        {

        }

        public override string AlgorithmName
        {
            get
            {
                return engine.AlgorithmName + "/KWP";
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

            int n = (inLen + 7) / 8;
            int padLen = n * 8 - inLen;
            byte[] block = new byte[inLen + iv.Length + 4 + padLen];
            byte[] pLen = Pack.UInt32_To_BE((uint)inLen);

            Array.Copy(iv, 0, block, 0, iv.Length);
            Array.Copy(pLen, 0, block, iv.Length, pLen.Length);
            Array.Copy(input, inOff, block, iv.Length + 4, inLen);

            if (n == 1)
            {
                engine.Init(wrapCipherMode, param);

                // if the padded plaintext contains exactly 8 octets,
                // then prepend iv and encrypt using AES in ECB mode.

                engine.ProcessBlock(block, 0, block, 0);

                return block;
            }
            else
            {
                return W(n, block);
            }
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

            int n = inLen / 8;

            if ((n * 8) != inLen)
            {
                throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
            }

            byte[] a = new byte[iv.Length + 4];
            byte[] b = new byte[inLen - a.Length];

            if (n == 2)
            {
                byte[] buf = new byte[engine.GetBlockSize()];

                engine.Init(!wrapCipherMode, param);

                engine.ProcessBlock(input, inOff, buf, 0);

                Array.Copy(buf, 0, a, 0, a.Length);
                Array.Copy(buf, a.Length, b, 0, b.Length);
            }
            else
            {
                Array.Copy(input, inOff, a, 0, a.Length);
                Array.Copy(input, inOff + a.Length, b, 0, inLen - a.Length);

                invW(n, b, a);
            }

            byte[] recIv = new byte[iv.Length];

            Array.Copy(a, 0, recIv, 0, recIv.Length);

            int pLen = (int)Pack.BE_To_UInt32(a, 4);
            int padLen = 8 * (n - 1) - pLen;

            if (!Arrays.ConstantTimeAreEqual(recIv, iv))
            {
                throw new InvalidCipherTextException("checksum failed");
            }

            if (padLen < 0 || padLen > 7)
            {
                throw new InvalidCipherTextException("unwrap data has incorrect padding length");
            }

            byte[] block = new byte[pLen];

            Array.Copy(b, 0, block, 0, pLen);

            bool failed = false;
            for (int i = 1; i <= padLen; i++)
            {
                if (b[b.Length - i] != 0)
                {
                    failed = true;
                }
            }

            if (failed)
            {
                throw new InvalidCipherTextException("unwrap data has incorrect padding");
            }

            return block;
        }
    }
}
