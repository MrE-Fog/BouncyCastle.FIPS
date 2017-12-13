using System;

namespace Org.BouncyCastle.Crypto
{
	internal interface IBasicKatTest<T>
	{
		bool HasTestPassed(T engine);
	}
}

