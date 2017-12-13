namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    /// A padder that adds the padding according to the scheme referenced in
    /// ISO 7814-4 - scheme 2 from ISO 9797-1. The first byte is 0x80, rest is 0x00
    /// </summary>
    public class ISO7816d4Padding
		: IBlockCipherPadding
	{
		public string PaddingName
		{
			get { return "ISO7816-4"; }
		}

		public int AddPadding(
			byte[]	input,
			int		inOff)
		{
			int added = (input.Length - inOff);

			input[inOff]= (byte) 0x80;
			inOff ++;

			while (inOff < input.Length)
			{
				input[inOff] = (byte) 0;
				inOff++;
			}

			return added;
		}

		public int PadCount(
			byte[] input)
		{
			int count = input.Length - 1;

			while (count > 0 && input[count] == 0)
			{
				count--;
			}

			if (input[count] != (byte)0x80)
			{
				throw new InvalidCipherTextException("pad block corrupted");
			}

			return input.Length - count;
		}
	}
}
