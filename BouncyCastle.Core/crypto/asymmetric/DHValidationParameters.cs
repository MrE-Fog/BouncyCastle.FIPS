using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public class DHValidationParameters
    {
        private int usageIndex;
        private byte[] seed;
        private int counter;

        /**
         * Base constructor - a seed, the counter will be set to -1.
         *
         * @param seed the seed used to generate the parameters.
         */
        public DHValidationParameters(
            byte[] seed): this(seed, -1, -1)
        {
            
        }

        /**
         * Constructor with a seed and a (p, q) counter for it.
         *
         * @param seed the seed used to generate the parameters.
         * @param counter the counter value associated with using the seed to generate the parameters.
         */
        public DHValidationParameters(
            byte[] seed,
            int counter): this(seed, counter, -1)
        {
            
        }

        /**
         * Base constructor with a seed, counter, and usage index.
         *
         * @param seed the seed value.
         * @param counter  (p, q) counter - -1 if not avaliable.
         * @param usageIndex the usage index.
         */
        public DHValidationParameters(
            byte[] seed,
            int counter,
            int usageIndex)
        {
            this.seed = Arrays.Clone(seed);
            this.counter = counter;
            this.usageIndex = usageIndex;
        }

        /**
         * Return the (p, q) counter value.
         *
         * @return  the (p, q) counter value, -1 if unavailable.
         */
        public int Counter
        {
            get
            {
                return counter;
            }
        }

        /**
         * Return the seed used for the parameter generation.
         *
         * @return the seed array.
         */
        public byte[] GetSeed()
        {
            return Arrays.Clone(seed);
        }

        /**
         * Return the usage index, -1 if none given.
         *
         * @return the usage index.
         */
        public int UsageIndex
        {
            get
            {
                return usageIndex;
            }
        }

        public int GetHashCode()
        {
            int code = this.counter;

            code += 37 * Arrays.GetHashCode(seed);
            code += 37 * usageIndex;

            return code;
        }

        public bool Equals(
            object o)
        {
            if (!(o is DHValidationParameters))
            {
                return false;
            }

            DHValidationParameters other = (DHValidationParameters)o;

            if (other.counter != this.counter)
            {
                return false;
            }

            if (other.usageIndex != this.usageIndex)
            {
                return false;
            }

            return Arrays.AreEqual(this.seed, other.seed);
        }
    }
}