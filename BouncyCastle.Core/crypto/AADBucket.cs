using System;
using System.IO;
using Org.BouncyCastle.Crypto.Internal.Modes;

namespace Org.BouncyCastle.Crypto
{
    internal class AADBucket
		: Stream
	{
        private readonly bool approvedOnlyMode;

		protected readonly IAeadBlockCipher aeadCipher;

		public AADBucket(
            IAeadBlockCipher aeadCipher)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.aeadCipher = aeadCipher;
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
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "AAD");

			if (count > 0)
			{
				aeadCipher.ProcessAadBytes(buffer, offset, count);
			}
		}

		public override void WriteByte(
			byte b)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "AAD");

            aeadCipher.ProcessAadByte(b);
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