using System;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    /// A padder that adds Pkcs7/Pkcs5 padding to a block.
    /// </summary>
    public class Pkcs7Padding
        : IBlockCipherPadding
    {
        public string PaddingName
        {
            get { return "PKCS7"; }
        }

        public int AddPadding(
            byte[] input,
            int inOff)
        {
            byte code = (byte)(input.Length - inOff);

            while (inOff < input.Length)
            {
                input[inOff] = code;
                inOff++;
            }

            return code;
        }

        public int PadCount(
            byte[] input)
        {
            byte countAsByte = input[input.Length - 1];
            int count = countAsByte;
     
            if (count < 1 || count > input.Length)
                throw new InvalidCipherTextException("pad block corrupted");
      
            for (int i = 2; i <= count; i++)
            {
                if (input[input.Length - i] != countAsByte)
                    throw new InvalidCipherTextException("pad block corrupted");
            }

            return count;
        }
    }
}
