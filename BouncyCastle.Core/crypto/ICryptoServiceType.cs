using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto
{
    internal interface IServiceProvider<out S>
    {
        Func<IKey, S> GetFunc(SecurityContext context);
    }

    /// <summary>
    /// Marker interface for classes that can be used with CryptoServicesRegistrar.CreateService()
    /// </summary>
    /// <typeparam name="S">The service produced.</typeparam>
    public interface ICryptoServiceType<out S>
    {
       
    }

    internal interface IGenerationService<S>
    {
        Func<IParameters<Algorithm>, SecureRandom, S> GetFunc(SecurityContext context);
    }

    /// <summary>
    /// Marker interface for classes that can be used with CryptoServicesRegistrar.CreateGenerator()
    /// </summary>
    /// <typeparam name="S">The generator produced.</typeparam>
    public interface IGenerationServiceType<S>
    {

    }

    internal interface IFactoryService<S>
    {
        Func<IParameters<Algorithm>, S> GetFunc(SecurityContext context);
    }

    /// <summary>
    /// Marker interface for factory classes that can be used with CryptoServicesRegistrar.CreateService()
    /// </summary>
    /// <typeparam name="S">The factory service produced.</typeparam>
    public interface IFactoryServiceType<S>
    {

    }

    internal interface IBuilderService<S>
    {
        Func<IParameters<Algorithm>, S> GetFunc(SecurityContext context);
    }

    /// <summary>
    /// Marker interface for builder classes that can be used with CryptoServicesRegistrar.CreateService()
    /// </summary>
    /// <typeparam name="S">The builder service produced.</typeparam>
    public interface IBuilderServiceType<S>
    {

    }
}
