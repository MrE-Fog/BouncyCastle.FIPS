using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.IO
{
	internal class DigestStream
		: Stream
	{
		private readonly bool isApprovedModeOnly;
		protected readonly Stream stream;
		protected readonly IDigest inDigest;
		protected readonly IDigest outDigest;

		internal DigestStream(
			Stream	stream,
			IDigest	readDigest,
			IDigest	writeDigest)
		{
			this.isApprovedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode ();
			this.stream = stream;
			this.inDigest = readDigest;
			this.outDigest = writeDigest;
		}

		internal virtual IDigest ReadDigest()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "DigestStream");

			return inDigest;
		}

		internal virtual IDigest WriteDigest()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "DigestStream");

			return outDigest;
		}

		public override int Read(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			int n = stream.Read(buffer, offset, count);
			if (inDigest != null)
			{
				if (n > 0)
				{
					inDigest.BlockUpdate(buffer, offset, n);
				}
			}
			return n;
		}

		public override int ReadByte()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			int b = stream.ReadByte();
			if (inDigest != null)
			{
				if (b >= 0)
				{
					inDigest.Update((byte)b);
				}
			}
			return b;
		}

		public override void Write(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			if (outDigest != null)
			{
				if (count > 0)
				{
					outDigest.BlockUpdate(buffer, offset, count);
				}
			}
			stream.Write(buffer, offset, count);
		}

		public override void WriteByte(
			byte b)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			if (outDigest != null)
			{
				outDigest.Update(b);
			}
			stream.WriteByte(b);
		}

		public override bool CanRead
		{
			get { return stream.CanRead; }
		}

		public override bool CanWrite
		{
			get { return stream.CanWrite; }
		}

		public override bool CanSeek
		{
			get { return stream.CanSeek; }
		}

		public override long Length
		{
			get { return stream.Length; }
		}

		public override long Position
		{
			get { return stream.Position; }
			set { stream.Position = value; }
		}

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
			    CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

                Platform.Dispose(stream);
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
        {
            CryptoServicesRegistrar.ApprovedModeCheck(isApprovedModeOnly, "DigestStream");

            Platform.Dispose(stream);
            base.Close();
        }
#endif

        public override  void Flush()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			stream.Flush();
		}

		public override long Seek(
			long		offset,
			SeekOrigin	origin)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			return stream.Seek(offset, origin);
		}

		public override void SetLength(
			long length)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly,  "DigestStream");

			stream.SetLength(length);
		}
	}
}

