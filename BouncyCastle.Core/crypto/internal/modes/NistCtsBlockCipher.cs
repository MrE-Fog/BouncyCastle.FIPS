using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Internal.Parameters;

namespace Org.BouncyCastle.Crypto.Internal.Modes
{
    /**
     * A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
     * be used to produce cipher text which is the same length as the plain text.
     * <p>
     *     This class implements the NIST version as documented in "Addendum to NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Three Variants of Ciphertext Stealing for CBC Mode"
     * </p>
     */
    internal class NistCtsBlockCipher
        : BufferedBlockCipher
    {
        public static readonly int CS1 = 1;
        public static readonly int CS2 = 2;
        public static readonly int CS3 = 3;

        private readonly int type;
        private readonly int blockSize;

        /**
         * Create a buffered block cipher that uses NIST Cipher Text Stealing
         *
         * @param type type of CTS mode (CS1, CS2, or CS3)
         * @param cipher the underlying block cipher used to create the CBC block cipher this cipher uses..
         */
        public NistCtsBlockCipher(
            int type,
            IBlockCipher cipher)
        {
            this.type = type;
            this.cipher = new CbcBlockCipher(cipher);

            blockSize = cipher.GetBlockSize();

            buf = new byte[blockSize * 2];
            bufOff = 0;
        }

        /**
         * return the size of the output buffer required for an update
         * an input of len bytes.
         *
         * @param len the length of the input.
         * @return the space required to accommodate a call to update
         * with len bytes of input.
         */
        public override int GetUpdateOutputSize(
            int len)
        {
            int total = len + bufOff;
            int leftOver = total % buf.Length;

            if (leftOver == 0)
            {
                return total - buf.Length;
            }

            return total - leftOver;
        }

        /**
         * return the size of the output buffer required for an update plus a
         * doFinal with an input of len bytes.
         *
         * @param len the length of the input.
         * @return the space required to accommodate a call to update and doFinal
         * with len bytes of input.
         */
        public override int GetOutputSize(
            int len)
        {
            return len + bufOff;
        }

        /**
         * process a single byte, producing an output block if necessary.
         *
         * @param in the input byte.
         * @param out the space for any output that might be produced.
         * @param outOff the offset from which the output will be copied.
         * @return the number of output bytes copied to out.
         * @exception DataLengthException if there isn't enough space in out.
         * @exception IllegalStateException if the cipher isn't initialised.
         */
        public override int ProcessByte(
            byte input,
            byte[] output,
            int outOff)
        {
            int resultLen = 0;

            if (bufOff == buf.Length)
            {
                resultLen = cipher.ProcessBlock(buf, 0, output, outOff);
                Array.Copy(buf, blockSize, buf, 0, blockSize);

                bufOff = blockSize;
            }

            buf[bufOff++] = input;

            return resultLen;
        }

        /**
         * process an array of bytes, producing output if necessary.
         *
         * @param in the input byte array.
         * @param inOff the offset at which the input data starts.
         * @param len the number of bytes to be copied out of the input array.
         * @param out the space for any output that might be produced.
         * @param outOff the offset from which the output will be copied.
         * @return the number of output bytes copied to out.
         * @exception DataLengthException if there isn't enough space in out.
         * @exception IllegalStateException if the cipher isn't initialised.
         */
        public override int ProcessBytes(
            byte[] input,
            int inOff,
            int len,
            byte[] output,
            int outOff)
        {
            if (len < 0)
            {
                throw new ArgumentException("Can't have a negative input length!");
            }

            int blockSize = GetBlockSize();
            int length = GetUpdateOutputSize(len);

            if (length > 0)
            {
                if ((outOff + length) > output.Length)
                {
                    throw new DataLengthException("output buffer too short");
                }
            }

            int resultLen = 0;
            int gapLen = buf.Length - bufOff;

            if (len > gapLen)
            {
                Array.Copy(input, inOff, buf, bufOff, gapLen);

                resultLen += cipher.ProcessBlock(buf, 0, output, outOff);
                Array.Copy(buf, blockSize, buf, 0, blockSize);

                bufOff = blockSize;

                len -= gapLen;
                inOff += gapLen;

                while (len > blockSize)
                {
                    Array.Copy(input, inOff, buf, bufOff, blockSize);
                    resultLen += cipher.ProcessBlock(buf, 0, output, outOff + resultLen);
                    Array.Copy(buf, blockSize, buf, 0, blockSize);

                    len -= blockSize;
                    inOff += blockSize;
                }
            }

            Array.Copy(input, inOff, buf, bufOff, len);

            bufOff += len;

            return resultLen;
        }

        /**
         * Process the last block in the buffer.
         *
         * @param out the array the block currently being held is copied into.
         * @param outOff the offset at which the copying starts.
         * @return the number of output bytes copied to out.
         * @exception DataLengthException if there is insufficient space in out for
         * the output.
         * @exception IllegalStateException if the underlying cipher is not
         * initialised.
         * @exception org.bouncycastle.crypto.InvalidCipherTextException if cipher text decrypts wrongly (in
         * case the exception will never get thrown).
         */
        public override int DoFinal(
            byte[] output,
            int outOff)
        {
            if (bufOff + outOff > output.Length)
            {
                throw new DataLengthException("output buffer to small in doFinal");
            }

            int blockSize = cipher.GetBlockSize();
            int len = bufOff - blockSize;
            byte[] block = new byte[blockSize];

            if (forEncryption)
            {
                if (bufOff < blockSize)
                {
                    throw new DataLengthException("need at least one block of input for NISTCTS");
                }

                if (bufOff > blockSize)
                {
                    byte[] lastBlock = new byte[blockSize];

                    if (this.type == CS2 || this.type == CS3)
                    {
                        cipher.ProcessBlock(buf, 0, block, 0);

                        Array.Copy(buf, blockSize, lastBlock, 0, len);

                        cipher.ProcessBlock(lastBlock, 0, lastBlock, 0);

                        if (this.type == CS2 && len == blockSize)
                        {
                            Array.Copy(block, 0, output, outOff, blockSize);

                            Array.Copy(lastBlock, 0, output, outOff + blockSize, len);
                        }
                        else
                        {
                            Array.Copy(lastBlock, 0, output, outOff, blockSize);

                            Array.Copy(block, 0, output, outOff + blockSize, len);
                        }
                    }
                    else
                    {
                        Array.Copy(buf, 0, block, 0, blockSize);
                        cipher.ProcessBlock(block, 0, block, 0);
                        Array.Copy(block, 0, output, outOff, len);

                        Array.Copy(buf, bufOff - len, lastBlock, 0, len);
                        cipher.ProcessBlock(lastBlock, 0, lastBlock, 0);
                        Array.Copy(lastBlock, 0, output, outOff + len, blockSize);
                    }
                }
                else
                {
                    cipher.ProcessBlock(buf, 0, block, 0);

                    Array.Copy(block, 0, output, outOff, blockSize);
                }
            }
            else
            {
                if (bufOff < blockSize)
                {
                    throw new DataLengthException("need at least one block of input for CTS");
                }

                byte[] lastBlock = new byte[blockSize];

                if (bufOff > blockSize)
                {
                    if (this.type == CS3 || (this.type == CS2 && ((buf.Length - bufOff) % blockSize) != 0))
                    {
                        if (cipher is CbcBlockCipher)
                        {
                            IBlockCipher c = ((CbcBlockCipher)cipher).GetUnderlyingCipher();

                            c.ProcessBlock(buf, 0, block, 0);
                        }
                        else
                        {
                            cipher.ProcessBlock(buf, 0, block, 0);
                        }

                        for (int i = blockSize; i != bufOff; i++)
                        {
                            lastBlock[i - blockSize] = (byte)(block[i - blockSize] ^ buf[i]);
                        }

                        Array.Copy(buf, blockSize, block, 0, len);

                        cipher.ProcessBlock(block, 0, output, outOff);
                        Array.Copy(lastBlock, 0, output, outOff + blockSize, len);
                    }
                    else
                    {
                        IBlockCipher c = ((CbcBlockCipher)cipher).GetUnderlyingCipher();

                        c.ProcessBlock(buf, bufOff - blockSize, lastBlock, 0);

                        Array.Copy(buf, 0, block, 0, blockSize);

                        if (len != blockSize)
                        {
                            Array.Copy(lastBlock, len, block, len, blockSize - len);
                        }

                        cipher.ProcessBlock(block, 0, block, 0);

                        Array.Copy(block, 0, output, outOff, blockSize);

                        for (int i = 0; i != len; i++)
                        {
                            lastBlock[i] ^= buf[i];
                        }

                        Array.Copy(lastBlock, 0, output, outOff + blockSize, len);
                    }
                }
                else
                {
                    cipher.ProcessBlock(buf, 0, block, 0);

                    Array.Copy(block, 0, output, outOff, blockSize);
                }
            }

            int offset = bufOff;

            Reset();

            return offset;
        }
    }
}
