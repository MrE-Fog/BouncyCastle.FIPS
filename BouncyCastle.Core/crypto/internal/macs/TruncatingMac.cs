using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Macs
{
	internal class TruncatingMac: IMac
	{
		private readonly IMac mac;
		private readonly int macSizeInBits;

		public TruncatingMac(IMac mac, int macSizeInBits)
		{
			this.mac = mac;
			this.macSizeInBits = macSizeInBits;
		}

		public void Init(ICipherParameters parameters)
		{
			mac.Init(parameters);
		}

		public virtual string AlgorithmName
		{
			get { return mac.AlgorithmName; }
		}

		public int GetMacSize()
		{
			return macSizeInBits / 8;
		}

		public void Update(byte b)
		{
			mac.Update(b);
		}

		public void BlockUpdate(byte[] inBytes, int inOff, int len)
		{
			mac.BlockUpdate(inBytes, inOff, len);
		}

		public int DoFinal(byte[] destination, int outOff)
		{
            byte[] res = BouncyCastle.Utilities.Macs.DoFinal(mac);

            Array.Copy(res, 0, destination, outOff, macSizeInBits / 8);

			return macSizeInBits / 8;
		}

		public void Reset()
		{
		}
	}
}

