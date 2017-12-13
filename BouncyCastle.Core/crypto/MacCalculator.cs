using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class MacCalculator : IStreamCalculator<IBlockResult>
	{
		private readonly IMac mac;
		private readonly Stream stream;

		internal MacCalculator(IMac mac)
		{
			this.mac = mac;
			this.stream = new MacBucket(mac);
		}

		public Stream Stream
		{
			get { return stream; }
		}

		public IBlockResult GetResult()
		{
			return new MacResult(mac);
		}
	}
}

