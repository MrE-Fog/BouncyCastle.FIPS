using System;
using System.IO;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
	public class CmsTypedStream
	{
		private const int BufferSize = 32 * 1024;

		private readonly DerObjectIdentifier _oid;
		private readonly Stream	_in;

		public CmsTypedStream(
			Stream inStream)
			: this(PkcsObjectIdentifiers.Data, inStream, BufferSize)
		{
		}

		public CmsTypedStream(
			DerObjectIdentifier oid,
			Stream inStream)
			: this(oid, inStream, BufferSize)
		{
		}

		public CmsTypedStream(
            DerObjectIdentifier oid,
			Stream	inStream,
			int		bufSize)
		{
			_oid = oid;
#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE
			_in = new FullReaderStream(inStream);
#else
			_in = new FullReaderStream(new BufferedStream(inStream, bufSize));
#endif
		}

		public DerObjectIdentifier ContentType
		{
			get { return _oid; }
		}

		public Stream ContentStream
		{
			get { return _in; }
		}

		public void Drain()
		{
			Streams.Drain(_in);
            Platform.Dispose(_in);
		}

		private class FullReaderStream : FilterStream
		{
			internal FullReaderStream(Stream input)
				: base(input)
			{
			}

			public override int Read(byte[]	buf, int off, int len)
			{
				return Streams.ReadFully(base.s, buf, off, len);
			}
		}
	}
}
