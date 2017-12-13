using System;
using System.IO;

using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Crypto
{
	internal class DigestBucket
		: Stream
	{
        private readonly bool approvedOnlyMode;

		protected readonly IDigest digest;

		public DigestBucket(
			IDigest	digest)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.digest = digest;
		}

		public override int Read(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			throw new NotImplementedException ();
		}

		public override int ReadByte()
		{
			throw new NotImplementedException ();
		}

		public override void Write(
			byte[]	buffer,
			int		offset,
			int		count)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DigestStream");

			if (count > 0)
			{
				digest.BlockUpdate(buffer, offset, count);
			}
		}

		public override void WriteByte(
			byte b)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DigestStream");

            digest.Update(b);
		}

		public override bool CanRead
		{
			get { return false; }
		}

		public override bool CanWrite
		{
			get { return true; }
		}

		public override bool CanSeek
		{
			get { return false; }
		}

		public override long Length
		{
			get { return 0; }
		}

		public override long Position
		{
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public override void Close()
		{
		}

		public override  void Flush()
		{
		}

		public override long Seek(
			long		offset,
			SeekOrigin	origin)
		{
			throw new NotImplementedException ();
		}

		public override void SetLength(
			long length)
		{
			throw new NotImplementedException ();
		}
	}
}

