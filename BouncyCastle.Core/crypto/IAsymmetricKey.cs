
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for Public/Private keys.
    /// </summary>
    public interface IAsymmetricKey: IKey
	{
		/// <summary>
		/// Return an ASN.1 encoding of the key wrapped in a PrivateKeyInfo or a SubjectPublicKeyInfo structure.
		/// </summary>
		/// <returns>An encoding of a PrivateKeyInfo or a SubjectPublicKeyInfo structure.</returns>
		byte[] GetEncoded();
	}
}

