using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    /// A padder that adds X9.23 padding to a block - if a SecureRandom is
    /// passed in random padding is assumed, otherwise padding with zeros is used.
    /// </summary>
    public class X923Padding : IBlockCipherPadding
    {
        private SecureRandom random;

        /// <summary>
        /// Base constructor providing a source of randomness or null if zero padding required.
        /// </summary>
        /// <param name="random">A SecureRandom (may be null)</param>
        public X923Padding(SecureRandom random)
        {
            this.random = random;
        }

        public string PaddingName
        {
            get
            {
                return "X923";
            }
        }

        public int AddPadding(
            byte[] input,
            int inOff)
        {
            byte code = (byte)(input.Length - inOff);

            while (inOff < input.Length - 1)
            {
                if (random == null)
                {
                    input[inOff] = 0;
                }
                else
                {
                    input[inOff] = (byte)random.NextInt();
                }
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
