
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class DigestCalculator : IStreamCalculator<IBlockResult>
	{
        private readonly bool approvedOnlyMode;
		private readonly IDigest digest;
		private readonly Stream stream;

		internal DigestCalculator(IDigest digest)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.digest = digest;
			this.stream = new DigestBucket(digest);
		}

		public Stream Stream
		{
			get { return stream; }
		}

		public IBlockResult GetResult()
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DigestStream");

            return new DigestResult(digest);
		}
	}
}

