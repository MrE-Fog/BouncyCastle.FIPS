using System;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
	internal class MacResult
        : IBlockResult
	{
		private readonly IMac mac;

		internal MacResult(IMac mac)
		{
			this.mac = mac;
		}

		public int Length
        {
			get { return mac.GetMacSize(); }
		}

		public byte[] Collect()
		{
            return Macs.DoFinal(mac);
		}

		public int Collect(byte[] destination, int offset)
		{
			mac.DoFinal(destination, offset);
			return mac.GetMacSize();
		}
	}
}
