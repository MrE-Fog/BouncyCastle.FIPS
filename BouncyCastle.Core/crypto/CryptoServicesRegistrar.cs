using System;
using System.Threading;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Crypto
{
    internal class KeyWithRandom
        : IKey
    {
        private readonly IKey key;
        private readonly SecureRandom random;

        internal KeyWithRandom(IKey key, SecureRandom random)
        {
            this.key = key;
            this.random = random;
        }

        public Algorithm Algorithm
        {
            get { return key.Algorithm; }
        }

        public IKey Key
        {
            get { return key; }
        }

        public SecureRandom Random
        {
            get { return random; }
        }
    }

    public static class CryptoServicesRegistrar
    {
        private static readonly SecurityContext FipsContext = new FipsModeContext();
        private static readonly SecurityContext GeneralContext = new GeneralModeContext();
        private static SecureRandom defaultSecureRandom;

        private static readonly ThreadLocal<SecurityContext> threadSecurityContext = new ThreadLocal<SecurityContext>(() => GeneralContext);
        private static SecurityContext ThreadSecurityContext
        {
            get { return threadSecurityContext.Value; }
        }

        public static void SetApprovedOnlyMode(bool approvedOnlyMode)
        {
            if (approvedOnlyMode == IsInApprovedOnlyMode())
                return;

            if (!approvedOnlyMode)
                throw new CryptoUnapprovedOperationError("Attempt to move from approved mode to unapproved mode");

            // TODO[permissions]
            //CheckPermission(AbleToChangeToApprovedMode);

            threadSecurityContext.Value = FipsContext;
        }

        public static bool IsInApprovedOnlyMode()
		{
			return ThreadSecurityContext.IsApprovedOnlyMode;
		}

		public static SecureRandom GetSecureRandom()
		{
            // TODO Delegate to ThreadSecurityContext
            if (defaultSecureRandom == null)
            {
                throw new InvalidOperationException("no default SecureRandom specified and one requested - use CryptoServicesRegistrar.setSecureRandom()");
            }

            if (IsInApprovedOnlyMode())
            {
                if (!(defaultSecureRandom is FipsSecureRandom))
                {
                    throw new CryptoUnapprovedOperationError("default SecureRandom not FIPS approved");
                }
            }

            return defaultSecureRandom;
		}

        public static void SetSecureRandom(SecureRandom random)
        {
            if (IsInApprovedOnlyMode())
            {
                if (!(random is FipsSecureRandom))
                {
                    throw new CryptoUnapprovedOperationError("random not FIPS approved");
                }
            }

            defaultSecureRandom = random;
        }

        public static A CreateService<A>(IBuilderServiceType<A> type)
        {
            return ThreadSecurityContext.CreateBuilder(type);
        }

        public static A CreateService<A>(ICryptoServiceType<A> type)
        {
            if (type is IAsymmetricKey)
            {
                return ThreadSecurityContext.CreateService(type, (IAsymmetricKey)type);
            }
            return ThreadSecurityContext.CreateService(type);
        }

        public static A CreateService<A>(IFactoryServiceType<A> type)
        {
            return ThreadSecurityContext.CreateFactory(type);
        }

        public static A CreateService<A>(ICryptoServiceType<A> type, SecureRandom random)
        {
            return ThreadSecurityContext.CreateService(type, (IAsymmetricKey)type, random);
        }

        public static A CreateGenerator<A>(IGenerationServiceType<A> type)
        {
            return ThreadSecurityContext.CreateGenerator(type, CryptoServicesRegistrar.GetSecureRandom());
        }

        public static A CreateGenerator<A>(IGenerationServiceType<A> type, SecureRandom random)
        {
            return ThreadSecurityContext.CreateGenerator(type, random);
        }

        internal static void ApprovedModeCheck(bool approvedMode, string algorithmName)
		{
			if (approvedMode != IsInApprovedOnlyMode())
			{
				if (approvedMode)
				{
					throw new CryptoUnapprovedOperationError("attempt to use approved instance in unapproved thread: " + algorithmName);
				}
				else
				{
					throw new CryptoUnapprovedOperationError("attempt to use unapproved instance in approved thread: " + algorithmName);
				}
			}
			if (CryptoStatus.IsErrorStatus())
			{
				throw new CryptoOperationError(CryptoStatus.GetStatusMessage());
			}
		}

        internal static void GeneralModeCheck(bool approvedOnlyMode, Algorithm algorithm)
        {
            if (approvedOnlyMode)
            {
                throw new CryptoUnapprovedOperationError("attempt to create unapproved algorithm in approved thread: " + algorithm.Name + "[" + algorithm.Mode + "]");
            }
        }
	}
}
