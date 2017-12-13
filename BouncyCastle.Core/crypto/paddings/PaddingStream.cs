using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Paddings
{
	internal class PaddingStream: Stream
	{
		private readonly bool forEncryption;
		private readonly IBlockCipherPadding padding;
		private readonly Stream sourceStream;
		private readonly int blockSize;
		private readonly byte[] buffer;
		private readonly int bufMax;

		private int bufStart;
		private int bufEnd;
		private bool isEOF;

		internal PaddingStream(bool forEncryption, IBlockCipherPadding padding, int blockSize, Stream sourceStream)
		{
			if (sourceStream.CanWrite && sourceStream.CanRead) {
				throw new ArgumentException ("cannot use read/write stream");
			}

			this.forEncryption = forEncryption;
			this.padding = padding;
			this.blockSize = blockSize;
			this.sourceStream = sourceStream;

			this.bufMax = blockSize * 1024;

			if (sourceStream.CanRead) {
				this.buffer = new byte[bufMax + blockSize];
			} else {
				this.buffer = new byte[blockSize];
			}
     
			this.isEOF = false;
			this.bufStart = 0;
			this.bufEnd = 0;
		}

		public override bool CanRead {
			get {
				return sourceStream.CanRead;
			}
		}

		public override bool CanSeek {
			get {
				return false;
			}
		}

		public override bool CanWrite {
			get {
				return sourceStream.CanWrite;
			}
		}

		public override long Length {
			get {
				throw new NotImplementedException ();
			}
		}

		public override long Position {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		public override void Flush ()
		{
			if (sourceStream.CanWrite) {
				sourceStream.Flush ();
			}
		}

		public override void Close ()
		{
			if (sourceStream.CanWrite) {
				if (forEncryption) {
					int offset = bufEnd;

                    if (offset == blockSize)
                    {
                        sourceStream.Write(buffer, 0, blockSize);
                        offset = 0;
                    }

                    padding.AddPadding (buffer, offset);
                    
					sourceStream.Write (buffer, 0, blockSize);

				} else {
					bufEnd -= padding.PadCount (buffer);

					sourceStream.Write (buffer, 0, bufEnd);
				}
			}
		
			sourceStream.Close ();
		}

		public override int Read (byte[] destination, int offset, int count)
		{
			int available = bufEnd - bufStart;
            if (isEOF && available == 0)
            {
                return 0;
            }

            if (bufEnd - bufStart <= blockSize)
            {
                loadBuffer();
            }

            available = bufEnd - bufStart;

            int length = count < available ? count : available;

            Array.Copy(buffer, bufStart, destination, offset, length);
			bufStart += length;

			return length;
		}

		public override long Seek (long offset, SeekOrigin origin)
		{
			throw new NotImplementedException ();
		}

		public override void SetLength (long value)
		{
			throw new NotImplementedException ();
		}

		public override void Write (byte[] source, int offset, int count)
		{
			int total = count + bufEnd;

            if (total > blockSize)
            {
                int extra = total % blockSize;
                if (!forEncryption && extra == 0)
                {
                    extra = blockSize;
                }
                int writeableLength = count - extra;

                sourceStream.Write(buffer, 0, bufEnd);
                sourceStream.Write(source, offset, writeableLength);
                offset += writeableLength;

                Array.Copy(source, offset, buffer, 0, extra);
                bufEnd = extra;

                if (forEncryption)
                {   // for TBC mode which uses the last byte
                    if (bufEnd == 0 && count > 0)
                    {
                        buffer[buffer.Length - 1] = source[writeableLength - 1];
                    }
                }
            }
            else
            {
                Array.Copy(source, offset, buffer, bufEnd, count);
                bufEnd += count;
            }
		}

		private void loadBuffer()
		{
            if (isEOF)
            {
                return;
            }

			if (bufEnd > 0) {

				for (int i = bufStart; i < bufEnd; i++) {
					buffer [i - bufStart] = buffer [i];
				}

				bufEnd = bufEnd - bufStart;
				bufStart = 0;
			}

			int readCount = -1;

			while ((bufEnd - bufStart) < buffer.Length && readCount != 0)
			{
				readCount = sourceStream.Read (buffer, bufEnd, bufMax - bufEnd);

				bufEnd += readCount;
			}

			if (readCount == 0) {
				isEOF = true;

				byte[] padBlock = new byte[blockSize];

				if (forEncryption) {
                    // for TBC mode - it needs the last byte of the last block...
                    if (bufEnd != 0)
                    {
                        padBlock[padBlock.Length - 1] = buffer[bufEnd - 1];
                    }
                    else
                    {
                        padBlock[padBlock.Length - 1] = 0;
                    }
  
					padding.AddPadding (padBlock, bufEnd % blockSize);

                    int count = 0;
				    for (int i = bufEnd % blockSize; i < padBlock.Length; i++) {
						buffer [bufEnd + count++] = padBlock [i];
					}
 
                    bufEnd += padBlock.Length - (bufEnd % blockSize);
                } else {
					Array.Copy(buffer, bufEnd - padBlock.Length, padBlock, 0, padBlock.Length);
					bufEnd -= padding.PadCount (padBlock);
				}
			}
		}
	}
}

