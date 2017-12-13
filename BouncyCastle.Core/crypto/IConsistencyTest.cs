namespace Org.BouncyCastle.Crypto
{
	internal interface IConsistencyTest<TypeT>
	{
		bool HasTestPassed (TypeT parameters);
	}
}

