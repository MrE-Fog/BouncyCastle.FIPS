
using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    ///  A padder that adds ISO10126-2 padding to a block.
    /// </summary>
    public class ISO10126d2Padding: IBlockCipherPadding
    {
        private SecureRandom random;

        /// <summary>
        /// Base constructor providing a source of randomness.
        /// </summary>
        /// <param name="random">A SecureRandom</param>
        public ISO10126d2Padding(SecureRandom random)
        {
            if (random == null)
            {
                throw new ArgumentException("random must be non-null");
            }

            this.random = random;
        }

        public string PaddingName
        {
            get { return "ISO10126-2"; }
        }

        public int AddPadding(
            byte[]	input,
            int		inOff)
        {
            byte code = (byte)(input.Length - inOff);

            while (inOff < (input.Length - 1))
            {
                input[inOff] = (byte)random.NextInt();
                inOff++;
            }

            input[inOff] = code;

            return code;
        }

        public int PadCount(byte[] input)
        {
            int count = input[input.Length - 1] & 0xff;

            if (count > input.Length)
            {
                throw new InvalidCipherTextException("pad block corrupted");
            }

            return count;
        }
    }

}
