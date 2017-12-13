using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.IO
{
	internal class SignerStream
		: Stream
	{
		private readonly bool isApprovedModeOnly;
		protected readonly Stream stream;
		protected readonly ISigner inSigner;
		protected readonly ISigner outSigner;

		public SignerStream(
			Stream	stream,
			ISigner	readSigner,
			ISigner	writeSigner)
		{
			this.isApprovedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode ();
			this.stream = stream;
			this.inSigner = readSigner;
			this.outSigner = writeSigner;
		}

		internal virtual ISigner ReadSigner()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			return inSigner;
		}

		internal virtual ISigner WriteSigner()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			return outSigner;
		}

		public override int Read(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			int n = stream.Read(buffer, offset, count);
			if (inSigner != null)
			{
				if (n > 0)
				{
					inSigner.BlockUpdate(buffer, offset, n);
				}
			}
			return n;
		}

		public override int ReadByte()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			int b = stream.ReadByte();
			if (inSigner != null)
			{
				if (b >= 0)
				{
					inSigner.Update((byte)b);
				}
			}
			return b;
		}

		public override void Write(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			if (outSigner != null)
			{
				if (count > 0)
				{
					outSigner.BlockUpdate(buffer, offset, count);
				}
			}
			stream.Write(buffer, offset, count);
		}

		public override void WriteByte(
			byte b)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			if (outSigner != null)
			{
				outSigner.Update(b);
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
    			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

                Platform.Dispose(stream);
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
        {
            CryptoServicesRegistrar.ApprovedModeCheck(isApprovedModeOnly, "SignerStream");

            Platform.Dispose(stream);
            base.Close();
        }
#endif

        public override  void Flush()
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			stream.Flush();
		}

		public override long Seek(
			long		offset,
			SeekOrigin	origin)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			return stream.Seek(offset, origin);
		}

		public override void SetLength(
			long length)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, "SignerStream");

			stream.SetLength(length);
		}
	}
}

