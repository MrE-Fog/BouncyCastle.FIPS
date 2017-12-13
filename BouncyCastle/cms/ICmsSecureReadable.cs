using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;

namespace Org.BouncyCastle.Cms
{
	internal interface ICmsSecureReadable
	{
        Stream GetInputStream();
	}
}
