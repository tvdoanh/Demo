using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace ExternalAuth
{
    public static class Config
    {
        // Identity resources
        public static IEnumerable<IdentityResource> GetIdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };

        // Scopes
        public static IEnumerable<ApiScope> GetApiScopes =>
            new ApiScope[]
            {
                new ApiScope("api"),
            };

        // Clients
        public static IEnumerable<Client> GetClients =>
            new Client[]
            {
                // test client credentials flow client
                new Client
                {
                    ClientId = "test",
                    ClientName = "Test Client",

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                    }
                }
            };
    }
}
