using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class SignatureBucket
		: Stream
	{
        private readonly bool approvedOnlyMode;
        protected readonly ISigner signer;

		public SignatureBucket(
			ISigner	signer)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.signer = signer;
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
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "SignatureStream");

            if (count > 0)
			{
				signer.BlockUpdate(buffer, offset, count);
			}
		}

		public override void WriteByte(
			byte b)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "SignatureStream");

            signer.Update(b);
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

