using System;

namespace Org.BouncyCastle.Crypto
{
	internal interface IEngineProvider<TEngine>
	{
		TEngine CreateEngine (EngineUsage usage);
	}
}

