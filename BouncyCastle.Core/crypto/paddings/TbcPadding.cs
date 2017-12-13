namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    ///  A padder that adds Trailing Bit Complement (TBC) padding to a block.
    /// </summary>
    public class TbcPadding : IBlockCipherPadding
    {
        public string PaddingName
        {
            get
            {
                return "TBC";
            }
        }

        public int AddPadding(byte[] input, int inOff)
        {
            int count = input.Length - inOff;
            byte code;

            if (inOff > 0)
            {
                code = (byte)((input[inOff - 1] & 0x01) == 0 ? 0xff : 0x00);
            }
            else
            {
                code = (byte)((input[input.Length - 1] & 0x01) == 0 ? 0xff : 0x00);
            }

            while (inOff < input.Length)
            {
                input[inOff] = code;
                inOff++;
            }

            return count;
        }

        public int PadCount(byte[] input)
        {
            byte code = input[input.Length - 1];

            int index = input.Length - 1;
            while (index > 0 && input[index - 1] == code)
            {
                index--;
            }

            return input.Length - index;
        }
    }
}
