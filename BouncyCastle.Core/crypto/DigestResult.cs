
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
	internal class DigestResult : IBlockResult
	{
        private readonly bool approvedOnlyMode;
        private readonly IDigest digest;

		internal DigestResult(IDigest digest)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.digest = digest;
		}

		public int Length
        {
			get { return digest.GetDigestSize(); }
		}

		public byte[] Collect()
		{
            return Digests.DoFinal(digest);
		}

		public int Collect(byte[] destination, int offset)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DigestResult");

            digest.DoFinal(destination, offset);
			return digest.GetDigestSize();
		}
	}
}

