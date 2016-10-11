using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Caching.Distributed;

namespace QuickstartIdentityServer.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class CachedPropertiesDataFormat 
        : ISecureDataFormat<AuthenticationProperties>        
    {

        public const string CacheKeyPrefix = "CachedPropertiesData-";

        private readonly IDistributedCache _cache;
        private readonly IDataProtector _dataProtector;
        private readonly IDataSerializer<AuthenticationProperties> _serializer;

        public CachedPropertiesDataFormat(
            IDistributedCache cache,
            IDataProtector dataProtector) 
            : this(cache, dataProtector, new PropertiesSerializer()) {

        }

        public CachedPropertiesDataFormat(
            IDistributedCache cache,
            IDataProtector dataProtector,
            IDataSerializer<AuthenticationProperties> serializer) {

            _dataProtector = dataProtector;
            _cache = cache;
            _serializer = serializer;

        }

        public string Protect(AuthenticationProperties data) {
            return Protect(data, null);
        }

        public string Protect(AuthenticationProperties data, string purpose) {

            var key = Guid.NewGuid().ToString();
            var cacheKey = $"{CacheKeyPrefix}{key}";
            var serialized = _serializer.Serialize(data);

            _cache.Set(cacheKey, serialized);

            return _dataProtector.Protect(key);

        }

        public AuthenticationProperties Unprotect(string protectedText) {
            return Unprotect(protectedText, null);
        }

        public AuthenticationProperties Unprotect(string protectedText, string purpose) {

            var key = _dataProtector.Unprotect(protectedText);
            var cacheKey = $"{CacheKeyPrefix}{key}";
            var serialized = _cache.Get(cacheKey);

            return _serializer.Deserialize(serialized);

        }

    }
}
