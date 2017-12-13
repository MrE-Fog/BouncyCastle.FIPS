using System;

namespace Org.BouncyCastle.Crypto
{
    using Internal.Modes;

    internal class AeadResult : IBlockResult
	{
        private readonly int macLength;
		private readonly IAeadBlockCipher cipher;

		internal AeadResult(int macLength, IAeadBlockCipher cipher)
		{
            this.macLength = macLength;
			this.cipher = cipher;
		}

		public int Length {
			get {
				return macLength;
			}
		}

		public byte[] Collect()
		{
            return cipher.GetMac();
		}

		public int Collect(byte[] destination, int offset)
		{
            byte[] tmp = Collect();

            Array.Copy(tmp, 0, destination, offset, tmp.Length);

			return tmp.Length;
		}
	}
}

