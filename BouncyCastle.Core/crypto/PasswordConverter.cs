using System;

using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Crypto
{
	abstract public class PasswordConverter: ICharToByteConverter
	{
		private readonly string type;

		public PasswordConverter (string type)
		{
			this.type = type;
		}

		public string Type {
			get { return type; }
		}

		abstract public byte[] Convert (char[] password);

		public static readonly PasswordConverter ASCII = new ASCIIConverter();
		public static readonly PasswordConverter UTF8 = new UTF8Converter();
		public static readonly PasswordConverter PKCS12 = new PKCS12Converter();

		private class ASCIIConverter : PasswordConverter
		{
			internal ASCIIConverter() : base("ASCII")
			{
			}

			public override byte[] Convert(char[] password)
			{
				return PbeParametersGenerator.Pkcs5PasswordToBytes(password);
			}
		}

		private class UTF8Converter : PasswordConverter
		{
			internal UTF8Converter() : base("UTF8")
			{
			}

			public override byte[] Convert(char[] password)
			{
				return PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password);
			}
		}

		private class PKCS12Converter : PasswordConverter
		{
			internal PKCS12Converter() : base("PKCS12")
			{
			}

			public override byte[] Convert(char[] password)
			{
				return PbeParametersGenerator.Pkcs12PasswordToBytes(password);
			}
		}
	}
}

