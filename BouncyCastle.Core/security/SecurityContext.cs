using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Security
{
    internal abstract class SecurityContext
    {
        internal abstract bool IsApprovedOnlyMode { get; }

        internal A CreateService<A>(ICryptoServiceType<A> type)
        {
            CryptoStatus.IsReady();

            return (type as IServiceProvider<A>).GetFunc(this).Invoke((IKey)type);
        }

        internal A CreateService<A>(ICryptoServiceType<A> type, IAsymmetricKey key)
        {
            CryptoStatus.IsReady();

            return (type as IServiceProvider<A>).GetFunc(this).Invoke(key);
        }

        internal A CreateService<A>(ICryptoServiceType<A> type, IAsymmetricKey key, SecureRandom random)
        {
            CryptoStatus.IsReady();

            return (type as IServiceProvider<A>).GetFunc(this).Invoke(new KeyWithRandom(key, random));
        }

        internal A CreateGenerator<A>(IGenerationServiceType<A> type, SecureRandom random)
        {
            CryptoStatus.IsReady();

            return (type as IGenerationService<A>).GetFunc(this).Invoke(type as IParameters<Algorithm>, random);
        }

        internal A CreateFactory<A>(IFactoryServiceType<A> type)
        {
            CryptoStatus.IsReady();

            return (type as IFactoryService<A>).GetFunc(this).Invoke(type as IParameters<Algorithm>);
        }

        internal A CreateBuilder<A>(IBuilderServiceType<A> type)
        {
            CryptoStatus.IsReady();

            return (type as IBuilderService<A>).GetFunc(this).Invoke(type as IParameters<Algorithm>);
        }
    }
}
