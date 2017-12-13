using System;

using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Math;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Modes
{
    /**
    * Implements the Segmented Integer Counter (SIC) mode on top of a simple
    * block cipher.
    */
    internal class SicBlockCipher
        : IBlockCipher
    {
        private readonly IBlockCipher cipher;
        private readonly int blockSize;
        private readonly byte[] counter;
        private readonly byte[] counterOut;
        private byte[] IV;

        /**
        * Basic constructor.
        *
        * @param c the block cipher to be used.
        */
        public SicBlockCipher(IBlockCipher cipher)
        {
            this.cipher = cipher;
            this.blockSize = cipher.GetBlockSize();
            this.counter = new byte[blockSize];
            this.counterOut = new byte[blockSize];
            this.IV = new byte[blockSize];
        }

        /**
        * return the underlying block cipher that we are wrapping.
        *
        * @return the underlying block cipher that we are wrapping.
        */
        public virtual IBlockCipher GetUnderlyingCipher()
        {
            return cipher;
        }

        public virtual void Init(
            bool				forEncryption, //ignored by this CTR mode
            ICipherParameters	parameters)
        {
            ParametersWithIV ivParam = parameters as ParametersWithIV;
            if (ivParam == null)
                throw new ArgumentException("CTR/SIC mode requires ParametersWithIV", "parameters");

            this.IV = Arrays.Clone(ivParam.GetIV());

            if (blockSize < IV.Length)
                throw new ArgumentException("CTR/SIC mode requires IV no greater than: " + blockSize + " bytes.");
            if (blockSize - IV.Length > 8)
                throw new ArgumentException("CTR/SIC mode requires IV of at least: " + (blockSize - 8) + " bytes.");

            Reset();

            // if null it's an IV changed only.
            if (ivParam.Parameters != null)
            {
                cipher.Init(true, ivParam.Parameters);
            }
        }

        public virtual string AlgorithmName
        {
            get { return cipher.AlgorithmName + "/SIC"; }
        }

        public virtual bool IsPartialBlockOkay
        {
            get { return true; }
        }

        public virtual int GetBlockSize()
        {
            return cipher.GetBlockSize();
        }

        public virtual int ProcessBlock(
            byte[]	input,
            int		inOff,
            byte[]	output,
            int		outOff)
        {
            cipher.ProcessBlock(counter, 0, counterOut, 0);

            //
            // XOR the counterOut with the plaintext producing the cipher text
            //
            for (int i = 0; i < counterOut.Length; i++)
            {
                output[outOff + i] = (byte)(counterOut[i] ^ input[inOff + i]);
            }

            // Increment the counter
            int j = counter.Length;
            while (--j >= 0 && ++counter[j] == 0)
            {
            }
            checkCounter();
            
            return counter.Length;
        }

        private void checkCounter()
        {
            // if the IV is the same as the blocksize we assume the user know's what they are doing
            if (IV.Length != blockSize)
            {
                for (int i = 0; i != IV.Length; i++)
                {
                    if (counter[i] != IV[i])
                    {
                        throw new InvalidOperationException("counter in CTR mode out of range");
                    }
                }
            }
        }

        public virtual void Reset()
        {
            Arrays.Fill(counter, (byte)0);
            Array.Copy(IV, 0, counter, 0, IV.Length);
            cipher.Reset();
        }
    }
}
