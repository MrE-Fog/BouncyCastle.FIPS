namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for a password based key deriver builder.
    /// </summary>
    /// <typeparam name="A">Type for configuration parameters used to create derivers produced by this service.</typeparam>
    public interface IPasswordBasedDeriverBuilderService<A>
    {
        /// <summary>
        /// Construct a builder from the passed in password encoding.
        /// </summary>
        /// <param name="password">a byte encoding of the password.</param>
        /// <returns></returns>
        IPasswordBasedDeriverBuilder<A> From(byte[] password);

        /// <summary>
        /// Construct a builder from the passed in password as converted by converter.
        /// </summary>
        /// <param name="converter">a converter to use to convert the password into bytes.</param>
        /// <param name="password">a password as a char array.</param>
        /// <returns></returns>
        IPasswordBasedDeriverBuilder<A> From(PasswordConverter converter, char[] password);
    }
}
