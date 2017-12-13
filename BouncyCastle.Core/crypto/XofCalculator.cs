using System.IO;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class XofCalculator : IVariableStreamCalculator<IBlockResult>
	{
        private readonly bool approvedOnlyMode;
        private readonly IXof xof;
		private readonly Stream stream;

		internal XofCalculator(IXof xof)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.xof = xof;
			this.stream = new DigestBucket(xof);
		}

		public Stream Stream
		{
			get { return stream; }
		}

		/// <summary>
		/// Gets the result.
		/// </summary>
		/// <returns>The result.</returns>
		public IBlockResult GetResult()
		{
			return GetResult(xof.GetDigestSize());
		}

		/// <summary>
		/// Gets the result.
		/// </summary>
		/// <returns>The result.</returns>
		/// <param name="outputLength">The length (in bytes) of the output wanted from the XOF.</param>
		public IBlockResult GetResult(int outputLength)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "XofResult");

            byte[] rv = new byte[outputLength];

			xof.DoOutput(rv, 0, outputLength);

			return new SimpleBlockResult(rv);
		}
	}
}

