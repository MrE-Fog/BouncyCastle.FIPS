using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities
{
    /// <summary>
    /// Interface a selector from a store should conform to.
    /// </summary>
    /// <typeparam name="TSelect">the type stored in the store.</typeparam>
    public interface ISelector<TSelect>
    {
        /// <summary>
        /// Match the passed in object, returning true if it would be selected by this selector, false otherwise.
        /// </summary>
        /// <param name="obj">the object to be matched.</param>
        /// <returns>if the object is a match for this selector, false otherwise.</returns>
        bool Match(TSelect obj);
    }
}
